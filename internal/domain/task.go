// Package domain holds the owner's rules for durable background work
// (DD-09 §1): the request states and every transition decision, free of
// SQL, gRPC and Fx. The application layer executes a decision inside one
// transaction; the decision itself is a pure function of the current row,
// the request and the clock.
package domain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// TaskState mirrors TaskState of anvilkit.mcp.v1 and the state column.
type TaskState string

const (
	StatePending         TaskState = "pending"
	StateLeased          TaskState = "leased"
	StateResultSubmitted TaskState = "result_submitted"
	StateAccepted        TaskState = "accepted"
	StateRetryScheduled  TaskState = "retry_scheduled"
	StateDead            TaskState = "dead"
	StateStale           TaskState = "stale"
	StateCanceled        TaskState = "canceled"
)

// Terminal reports whether no claim, result or cancellation can change the
// request any more.
func (s TaskState) Terminal() bool {
	switch s {
	case StateAccepted, StateDead, StateStale, StateCanceled:
		return true
	}
	return false
}

// Effects classifies what a lease may have caused outside the owner's
// database: reconstructible computation can be reassigned when a lease
// expires; external effects need the original Control dispatch queried first.
type Effects string

const (
	EffectsReconstructible Effects = "reconstructible"
	EffectsExternal        Effects = "external"
)

// Attempt outcomes recorded on task_attempts.
const (
	AttemptSubmitted = "submitted"
	AttemptAccepted  = "accepted"
	AttemptStale     = "stale"
	AttemptExpired   = "expired"
	AttemptFailed    = "failed"
)

// Failure codes recorded on the request (contracts.md §4 vocabulary plus
// the owner's own reasons; never a body or a secret).
const (
	FailureLeaseExpired         = "LEASE_EXPIRED"
	FailureEffectUncertain      = "EFFECT_UNCERTAIN"
	FailureProfileMismatch      = "PROFILE_MISMATCH"
	FailureAuthorizationRevoked = "AUTHORIZATION_REVOKED"
	FailureCanceled             = "CANCELED"
	FailureSuperseded           = "SUPERSEDED"
	FailureAttemptsExhausted    = "ATTEMPTS_EXHAUSTED"
	FailureHandler              = "HANDLER_FAILED"
)

// The task kinds this owner's schema admits (migration 00002) and the
// fixture kind of the background lane. local-check is DEVELOPMENT_ONLY
// fixed computation: it qualifies claims, acceptance, relays and the
// Worker without any business handler.
const (
	KindCatalogRefresh = "mcp-catalog-refresh"
	KindLocalCheck     = "local-check"
)

// LocalCheckProfile is the result profile of the fixture: the result
// reference names the task and the result digest is the SHA-256 of the
// declared bytes, so the owner recomputes the expectation from the frozen
// input and a wrong result is a profile mismatch, not an acceptance.
const LocalCheckProfile = "local-check-v1"

// Errors of the decisions; the transport maps them to gRPC codes.
var (
	ErrNotFound         = errors.New("NOT_FOUND")
	ErrInvalid          = errors.New("INVALID_ARGUMENT")
	ErrNotClaimable     = errors.New("NOT_CLAIMABLE")
	ErrStaleExecution   = errors.New("STALE_EXECUTION")
	ErrEffectUncertain  = errors.New("EFFECT_UNCERTAIN")
	ErrProfileUnknown   = errors.New("PROFILE_UNQUALIFIED")
	ErrAlreadyClaimed   = errors.New("ALREADY_CLAIMED")
	ErrInputTooLarge    = errors.New("INPUT_TOO_LARGE")
	ErrDuplicateClaimID = errors.New("WORKER_IDENTITY_REUSED")
)

// Task is the durable request row of one generation.
type Task struct {
	TaskID           string
	Generation       uint64
	TenantID         string
	Kind             string
	InputDigest      string
	Input            []byte
	State            TaskState
	WorkerID         string
	LeaseUntil       time.Time
	AttemptCount     uint32
	MaxAttempts      uint32
	ResultProfile    string
	Effects          Effects
	DispatchID       string
	AuthorizationRef string
	RetryAt          *time.Time
	ResultRef        string
	ResultDigest     string
	FailureCode      string
	Revision         uint64
	CorrelationID    string
}

// Attempt is one lease of a generation by one worker identity.
type Attempt struct {
	Ordinal    uint32
	WorkerID   string
	LeasedAt   time.Time
	LeaseUntil time.Time
	Outcome    string
}

// Bounds are the owner's reviewed limits of the lane (DEVELOPMENT_ONLY
// values in config.yaml until ENV-05 fixes them).
type Bounds struct {
	MaxInputBytes int
	MaxLease      time.Duration
	RetryDelay    time.Duration
	MaxAttempts   uint32
}

// InputDigest is the canonical digest of the frozen input bytes.
func InputDigest(input []byte) string {
	sum := sha256.Sum256(input)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

// NewRequest validates a new generation of a request. A profile that this
// build cannot check is refused (PROFILE_UNQUALIFIED); an input over the
// bound is refused before it is stored (ClaimTaskResponse.input carries at
// most 64 KiB).
func NewRequest(taskID, tenantID, kind, profile string, input []byte, effects Effects, dispatchID, authorizationRef, correlationID string, bounds Bounds) (Task, error) {
	switch {
	case taskID == "" || tenantID == "" || correlationID == "":
		return Task{}, fmt.Errorf("%w: task, tenant and correlation identities are required", ErrInvalid)
	case kind != KindCatalogRefresh && kind != KindLocalCheck:
		return Task{}, fmt.Errorf("%w: unknown task kind %q", ErrInvalid, kind)
	case len(input) > bounds.MaxInputBytes:
		return Task{}, fmt.Errorf("%w: %d bytes over the %d-byte bound", ErrInputTooLarge, len(input), bounds.MaxInputBytes)
	case effects != EffectsReconstructible && effects != EffectsExternal:
		return Task{}, fmt.Errorf("%w: effects %q", ErrInvalid, effects)
	case effects == EffectsExternal && dispatchID == "":
		return Task{}, fmt.Errorf("%w: an external-effect request names its Control dispatch", ErrInvalid)
	case !json.Valid(input):
		return Task{}, fmt.Errorf("%w: input is not JSON", ErrInvalid)
	}
	if err := checkProfileInput(profile, input); err != nil {
		return Task{}, err
	}
	return Task{
		TaskID: taskID, Generation: 1, TenantID: tenantID, Kind: kind, InputDigest: InputDigest(input), Input: input,
		State: StatePending, MaxAttempts: bounds.MaxAttempts, ResultProfile: profile, Effects: effects, DispatchID: dispatchID,
		AuthorizationRef: authorizationRef, Revision: 1, CorrelationID: correlationID,
	}, nil
}

// LocalCheckInput is the fixture's frozen input (DEVELOPMENT_ONLY): the
// bytes whose SHA-256 is the expected result, and optional switches the
// verification scenarios use to make the handler hold, fail or answer
// wrongly. Nothing here is a business parser, memory or tool.
type LocalCheckInput struct {
	SchemaVersion int    `json:"schemaVersion"`
	Computation   string `json:"computation"`
	Bytes         string `json:"bytes"`
	HoldMs        int    `json:"holdMs,omitempty"`
	Fail          bool   `json:"fail,omitempty"`
	WrongDigest   bool   `json:"wrongDigest,omitempty"`
}

func checkProfileInput(profile string, input []byte) error {
	switch profile {
	case LocalCheckProfile:
		var in LocalCheckInput
		if err := json.Unmarshal(input, &in); err != nil {
			return fmt.Errorf("%w: local-check input: %v", ErrInvalid, err)
		}
		if in.SchemaVersion != 1 || in.Computation != LocalCheckProfile {
			return fmt.Errorf("%w: local-check input must declare schemaVersion 1 and computation %s", ErrInvalid, LocalCheckProfile)
		}
		if _, err := base64.StdEncoding.DecodeString(in.Bytes); err != nil {
			return fmt.Errorf("%w: local-check bytes are not base64", ErrInvalid)
		}
		return nil
	default:
		return fmt.Errorf("%w: result profile %q has no acceptance rule in this build", ErrProfileUnknown, profile)
	}
}

// ExpectedResult returns the result reference and digest the profile
// requires for this task, recomputed from the frozen input.
func ExpectedResult(t Task) (ref, digest string, err error) {
	switch t.ResultProfile {
	case LocalCheckProfile:
		var in LocalCheckInput
		if err := json.Unmarshal(t.Input, &in); err != nil {
			return "", "", fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		raw, err := base64.StdEncoding.DecodeString(in.Bytes)
		if err != nil {
			return "", "", fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		sum := sha256.Sum256(raw)
		return fmt.Sprintf("local-check:%s:%d", t.TaskID, t.Generation), "sha256:" + hex.EncodeToString(sum[:]), nil
	default:
		return "", "", fmt.Errorf("%w: %q", ErrProfileUnknown, t.ResultProfile)
	}
}

// Supersede fences the previous generation when a new one is created: a
// non-terminal generation becomes stale (its claimant's heartbeat and
// result are refused from now on).
func Supersede(prev Task) (Task, bool) {
	if prev.State.Terminal() {
		return prev, false
	}
	prev.State = StateStale
	prev.FailureCode = FailureSuperseded
	prev.Revision++
	return prev, true
}

// ---------------------------------------------------------------------------
// Claim / heartbeat
// ---------------------------------------------------------------------------

// ClaimDecision is the accepted claim: the new row and the attempt to record.
type ClaimDecision struct {
	Task            Task
	Attempt         Attempt
	ExpiredPrevious bool // the previous lease had expired and is recorded as such
}

// DecideClaim admits a claim of the current generation: pending or due
// retry_scheduled rows, and a leased row whose lease has expired when the
// computation is reconstructible (an external-effect lease is only released
// by the sweeper after the Control query). A worker identity that already
// held an attempt of this generation cannot claim it again (the identity
// reuse fence); the attempt bound is enforced here as well as by the sweeper.
func DecideClaim(t Task, previous []Attempt, workerID string, lease time.Duration, now time.Time, bounds Bounds) (ClaimDecision, error) {
	if lease <= 0 || lease > bounds.MaxLease {
		return ClaimDecision{}, fmt.Errorf("%w: lease %s outside (0, %s]", ErrInvalid, lease, bounds.MaxLease)
	}
	for _, a := range previous {
		if a.WorkerID == workerID {
			return ClaimDecision{}, fmt.Errorf("%w: %s already claimed generation %d as attempt %d", ErrDuplicateClaimID, workerID, t.Generation, a.Ordinal)
		}
	}
	expiredPrevious := false
	switch t.State {
	case StatePending:
	case StateRetryScheduled:
		if t.RetryAt != nil && t.RetryAt.After(now) {
			return ClaimDecision{}, fmt.Errorf("%w: retry scheduled at %s", ErrNotClaimable, t.RetryAt.UTC().Format(time.RFC3339))
		}
	case StateLeased:
		if t.LeaseUntil.After(now) {
			return ClaimDecision{}, fmt.Errorf("%w: leased by another worker until %s", ErrAlreadyClaimed, t.LeaseUntil.UTC().Format(time.RFC3339))
		}
		if t.Effects != EffectsReconstructible {
			return ClaimDecision{}, fmt.Errorf("%w: lease expired on an external-effect task; the owner queries the original dispatch before any reassignment", ErrEffectUncertain)
		}
		expiredPrevious = true
	default:
		return ClaimDecision{}, fmt.Errorf("%w: state %s", ErrNotClaimable, t.State)
	}
	if t.AttemptCount >= t.MaxAttempts {
		return ClaimDecision{}, fmt.Errorf("%w: %d of %d attempts used", ErrNotClaimable, t.AttemptCount, t.MaxAttempts)
	}
	t.State = StateLeased
	t.WorkerID = workerID
	t.LeaseUntil = now.Add(lease)
	t.AttemptCount++
	t.RetryAt = nil
	t.FailureCode = ""
	t.Revision++
	return ClaimDecision{
		Task:            t,
		Attempt:         Attempt{Ordinal: t.AttemptCount, WorkerID: workerID, LeasedAt: now, LeaseUntil: t.LeaseUntil},
		ExpiredPrevious: expiredPrevious,
	}, nil
}

// DecideHeartbeat extends a valid lease of the current claimant by the
// attempt's own lease length; anything else tells the worker to stop.
func DecideHeartbeat(t Task, current Attempt, workerID string, now time.Time) (Task, error) {
	if t.State != StateLeased || t.WorkerID != workerID || current.WorkerID != workerID {
		return Task{}, fmt.Errorf("%w: not the current claimant (state %s)", ErrStaleExecution, t.State)
	}
	if !t.LeaseUntil.After(now) {
		return Task{}, fmt.Errorf("%w: lease expired at %s", ErrStaleExecution, t.LeaseUntil.UTC().Format(time.RFC3339))
	}
	t.LeaseUntil = now.Add(current.LeaseUntil.Sub(current.LeasedAt))
	t.Revision++
	return t, nil
}

// ---------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------

// Submission is what the worker sends (SubmitTaskResultRequest).
type Submission struct {
	WorkerID     string
	InputDigest  string
	Succeeded    bool
	ResultRef    string
	ResultDigest string
	FailureCode  string
}

// AuthorizationState is the owner's current answer for the request's
// authorization reference at acceptance time.
type AuthorizationState int

const (
	AuthorizationCurrent AuthorizationState = iota
	AuthorizationRevoked
)

// SubmitDecision is the outcome of a submission.
type SubmitDecision struct {
	Task           Task
	AttemptOutcome string // outcome to record on the current attempt ("" when nothing changes)
	Accepted       bool
	Existing       bool
	Changed        bool
}

// DecideSubmit accepts or refuses a result under the owner's CAS (DD-09
// §1): the current generation, the current claimant with a valid lease,
// the frozen input digest, the result profile and the current
// authorization. A repeated identical submission returns the existing
// acceptance; a superseded or expired claimant is refused without touching
// the row; a digest mismatch is a caller error; a profile mismatch or a
// reported failure consumes the attempt (retry or dead); a revoked
// authorization cancels the request.
func DecideSubmit(t Task, current Attempt, sub Submission, auth AuthorizationState, now time.Time, bounds Bounds) (SubmitDecision, error) {
	if !digestPattern.MatchString(sub.InputDigest) {
		return SubmitDecision{}, fmt.Errorf("%w: input digest", ErrInvalid)
	}
	if t.State == StateAccepted {
		if t.WorkerID == sub.WorkerID && t.ResultDigest == sub.ResultDigest && t.ResultRef == sub.ResultRef && sub.Succeeded {
			return SubmitDecision{Task: t, Accepted: true, Existing: true}, nil
		}
		return SubmitDecision{}, fmt.Errorf("%w: generation %d already accepted a result", ErrStaleExecution, t.Generation)
	}
	if t.State != StateLeased || t.WorkerID != sub.WorkerID || current.WorkerID != sub.WorkerID {
		return SubmitDecision{}, fmt.Errorf("%w: not the current claimant (state %s)", ErrStaleExecution, t.State)
	}
	if !t.LeaseUntil.After(now) {
		return SubmitDecision{}, fmt.Errorf("%w: lease expired at %s", ErrStaleExecution, t.LeaseUntil.UTC().Format(time.RFC3339))
	}
	if sub.InputDigest != t.InputDigest {
		return SubmitDecision{}, fmt.Errorf("%w: input digest does not match the frozen input", ErrInvalid)
	}
	if auth == AuthorizationRevoked {
		t.State = StateCanceled
		t.FailureCode = FailureAuthorizationRevoked
		t.Revision++
		return SubmitDecision{Task: t, AttemptOutcome: AttemptStale, Changed: true}, nil
	}
	if !sub.Succeeded {
		code := sub.FailureCode
		if code == "" {
			code = FailureHandler
		}
		return failAttempt(t, code, now, bounds), nil
	}
	if !digestPattern.MatchString(sub.ResultDigest) {
		return SubmitDecision{}, fmt.Errorf("%w: a succeeded result carries its digest", ErrInvalid)
	}
	ref, digest, err := ExpectedResult(t)
	if err != nil {
		return SubmitDecision{}, err
	}
	if sub.ResultRef != ref || sub.ResultDigest != digest {
		return failAttempt(t, FailureProfileMismatch, now, bounds), nil
	}
	t.State = StateAccepted
	t.ResultRef = sub.ResultRef
	t.ResultDigest = sub.ResultDigest
	t.FailureCode = ""
	t.Revision++
	return SubmitDecision{Task: t, AttemptOutcome: AttemptAccepted, Accepted: true, Changed: true}, nil
}

func failAttempt(t Task, code string, now time.Time, bounds Bounds) SubmitDecision {
	t.FailureCode = code
	t.Revision++
	if t.AttemptCount >= t.MaxAttempts {
		t.State = StateDead
		return SubmitDecision{Task: t, AttemptOutcome: AttemptFailed, Changed: true}
	}
	retryAt := now.Add(bounds.RetryDelay)
	t.State = StateRetryScheduled
	t.RetryAt = &retryAt
	t.WorkerID = ""
	return SubmitDecision{Task: t, AttemptOutcome: AttemptFailed, Changed: true}
}

// ---------------------------------------------------------------------------
// Cancel / expiry
// ---------------------------------------------------------------------------

// DecideCancel cancels a non-terminal generation; a leased attempt is
// recorded stale so its claimant's later heartbeat and result are refused.
func DecideCancel(t Task) (task Task, attemptOutcome string, changed bool) {
	if t.State.Terminal() {
		return t, "", false
	}
	if t.State == StateLeased {
		attemptOutcome = AttemptStale
	}
	t.State = StateCanceled
	t.FailureCode = FailureCanceled
	t.Revision++
	return t, attemptOutcome, true
}

// DispatchOutcome is Control's answer about the original dispatch of an
// external-effect attempt (DD-02 §4): only NotSent evidence releases the
// lease for reassignment.
type DispatchOutcome int

const (
	DispatchUnknown DispatchOutcome = iota
	DispatchNotSent
	DispatchSent
)

// DecideExpire handles a lease that ran out (DD-09 §1): reconstructible
// computation is rescheduled while attempts remain and dead afterwards; an
// external-effect lease is released only with not-sent evidence, otherwise
// the request is dead with EFFECT_UNCERTAIN and nothing is resent.
func DecideExpire(t Task, outcome DispatchOutcome, now time.Time, bounds Bounds) (task Task, attemptOutcome string, changed bool) {
	if t.State != StateLeased || t.LeaseUntil.After(now) {
		return t, "", false
	}
	if t.Effects == EffectsExternal && outcome != DispatchNotSent {
		t.State = StateDead
		t.FailureCode = FailureEffectUncertain
		t.Revision++
		return t, AttemptExpired, true
	}
	t.Revision++
	t.WorkerID = ""
	if t.AttemptCount >= t.MaxAttempts {
		t.State = StateDead
		t.FailureCode = FailureAttemptsExhausted
		return t, AttemptExpired, true
	}
	retryAt := now.Add(bounds.RetryDelay)
	t.State = StateRetryScheduled
	t.RetryAt = &retryAt
	t.FailureCode = FailureLeaseExpired
	return t, AttemptExpired, true
}
