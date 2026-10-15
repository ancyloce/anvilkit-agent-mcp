package application

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres/sqlc"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// Guarded tool execution (DD-08 §3-§5, DD-02 §4). A call is persisted
// (accepted) before anything else; the trusted adapter asks Control's
// AdmitTool under the call's own identity, and only the request that
// received dispatchAllowed=true may send. Before the send, the connection
// is qualified (route, negotiated protocol, live input schema, upstream
// authorization) and the grant is re-read as still executable; the send
// marker is committed in that same transaction and exactly one tools/call
// follows. A call admitted without a committed marker was never sent
// (CANCELED, zero usage); a marker without a recorded outcome is UNKNOWN,
// which is never resent and restricts new calls to the server until its
// original identity is resolved at Control.

// OwnerIdentity is the dispatch owner and actor MCP presents to Control.
const OwnerIdentity = "anvilkit-agent-mcp"

// ToolAdmit is the AdmitTool request of a call.
type ToolAdmit struct {
	Command        ControlCommand
	CallID         string
	OperationID    string
	AttemptID      string
	InstanceID     string
	ExecutionEpoch uint64
	GrantID        string
	GrantRevision  uint64
	ServerID       string
	Method         string
	ArgumentDigest string
	SideEffecting  bool
	MaxExposure    domain.Money
	Deadline       time.Time
}

// ToolAdmission is Control's answer; State is the dispatch state
// (authorized, denied, observed, unknown, confirmed_not_sent, prepared).
type ToolAdmission struct {
	DispatchID string
	Allowed    bool
	DenialCode string
	State      string
}

// DispatchView is Control's current record of a dispatch.
type DispatchView struct {
	State   string
	Outcome string // succeeded | failed | canceled | unknown | ""
}

// Outcomes reported to Control.
const (
	OutcomeSucceeded = "succeeded"
	OutcomeFailed    = "failed"
	OutcomeCanceled  = "canceled"
	OutcomeUnknown   = "unknown"
)

// ToolDispatcher is Control's DispatchService for tool dispatches.
type ToolDispatcher interface {
	// CheckExecution asks Control's AuthorizationService whether the
	// caller may execute the resource now (P2.1); an error establishes
	// nothing and refuses the call.
	CheckExecution(ctx context.Context, scope Scope, resourceType, resourceID, action string) (ExecutionDecision, error)
	AdmitTool(ctx context.Context, req ToolAdmit) (ToolAdmission, error)
	// ObserveTool reports an outcome under (dispatch, sequence); units is
	// nil for UNKNOWN.
	ObserveTool(ctx context.Context, dispatchID string, sequence uint64, outcome string, units *uint64, at time.Time) error
	GetTool(ctx context.Context, tenantID, dispatchID string) (DispatchView, error)
}

// ExecutionDecision is Control's commercial authorization answer.
type ExecutionDecision struct {
	Allowed  bool
	Revision string
	Reason   string
}

// UpstreamTarget is what a send is qualified against: the reviewed
// revision's lock (P2.5) — the server's name and version, the method's
// input and output schema and annotations digests — recomputed from the
// live session and compared before anything is sent, and the revision's
// network scope, the only hosts the session may reach.
type UpstreamTarget struct {
	Resource           string
	ProtocolVersion    string
	Transport          string
	Method             string
	InputSchemaDigest  string
	OutputSchemaDigest string
	AnnotationsDigest  string
	ServerName         string
	ServerVersion      string
	NetworkScope       []string
	Token              string
}

// UpstreamReply is the normalized result and the private native evidence.
type UpstreamReply struct {
	Result  []byte
	Native  []byte
	IsError bool
}

// UpstreamSession sends the one tools/call of a call.
type UpstreamSession interface {
	Send(ctx context.Context, method string, args []byte) (UpstreamReply, error)
	Close()
}

// Upstream opens a qualified session on the selected route; an error is a
// NotSentError (nothing was sent to the tool).
type Upstream interface {
	Open(ctx context.Context, t UpstreamTarget) (UpstreamSession, error)
}

// Tokens obtains the upstream access token of a grant ("" when the grant
// binds no issuer).
type Tokens interface {
	Token(ctx context.Context, g domain.Grant) (string, error)
}

// NotSentError: the call was refused before its send.
type NotSentError struct {
	Code string
	Err  error
}

func (e *NotSentError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *NotSentError) Unwrap() error { return e.Err }

// AnsweredError: the server answered the send with a protocol error.
type AnsweredError struct {
	Code string
	Err  error
}

func (e *AnsweredError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *AnsweredError) Unwrap() error { return e.Err }

// UnknownError: the send may have reached the server; no outcome is known.
type UnknownError struct {
	Code string
	Err  error
}

func (e *UnknownError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *UnknownError) Unwrap() error { return e.Err }

// QualifiedRoute is one reviewed (resource, protocol, transport, route)
// combination; any other combination stays disabled.
type QualifiedRoute struct {
	Resource        string
	ProtocolVersion string
	Transport       string
	Route           string
}

// CallOptions bound the call path.
type CallOptions struct {
	SendTimeout    time.Duration
	Wait           time.Duration // how long CreateCall waits for the outcome
	ReconcileAge   time.Duration
	ReconcileBatch int32
	// ResolveInterval is the slower cadence at which an UNKNOWN call that
	// waits for its original identity to be resolved at Control is asked
	// about again (0: every pass). The rows are operator-pending: asking
	// every pass gains nothing and crowds the pass.
	ResolveInterval time.Duration
}

// ErrShuttingDown: the process stops admitting new calls; the caller
// retries against another replica (the same command answers the original).
var ErrShuttingDown = errors.New("SHUTTING_DOWN")

type Calls struct {
	store    *postgres.Store
	dispatch ToolDispatcher
	upstream map[string]Upstream
	tokens   Tokens
	routes   []QualifiedRoute
	opts     CallOptions
	clock    Clock
	metrics  *Metrics
	log      *slog.Logger
	authz    *Authorizer

	// Detached dispatches of this process (DD-09 §3 drain): tracked so a
	// stop waits for them within the send bound and records what did not
	// finish, instead of leaving marked calls to the reconciler of another
	// replica after the Pod is gone.
	closing  atomic.Bool
	inflight sync.WaitGroup
	liveMu   sync.Mutex
	live     map[string]struct{}
	// nextResolve throttles the Control queries of operator-pending UNKNOWN
	// calls per call id (pruned to the rows the last pass saw).
	resolveMu   sync.Mutex
	nextResolve map[string]time.Time
}

func NewCalls(store *postgres.Store, dispatch ToolDispatcher, upstream map[string]Upstream, tokens Tokens, routes []QualifiedRoute, opts CallOptions, clock Clock, metrics *Metrics, log *slog.Logger) *Calls {
	if opts.ReconcileBatch <= 0 {
		opts.ReconcileBatch = 50
	}
	return &Calls{store: store, dispatch: dispatch, upstream: upstream, tokens: tokens, routes: routes, opts: opts, clock: clock, metrics: metrics, log: log,
		live: map[string]struct{}{}, nextResolve: map[string]time.Time{}}
}

func (c *Calls) routeOf(g domain.Grant) (string, bool) {
	for _, r := range c.routes {
		if r.Resource == g.CanonicalResource && r.ProtocolVersion == g.ProtocolVersion && r.Transport == g.Transport {
			if _, ok := c.upstream[r.Route]; ok {
				return r.Route, true
			}
		}
	}
	return "", false
}

func callerMaySend(scope Scope, g domain.Grant) bool {
	switch g.SubjectType {
	case "tenant":
		return true
	case "project":
		return scope.ProjectID != "" && g.SubjectID == scope.ProjectID
	case "actor":
		return g.SubjectID == scope.ActorID
	case "role":
		return slices.Contains(scope.Roles, g.SubjectID)
	}
	return false
}

func (c *Calls) load(ctx context.Context, q *sqlc.Queries, callID string) (domain.Call, error) {
	r, err := q.GetToolRequest(ctx, callID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Call{}, fmt.Errorf("%w: call %s", domain.ErrNotFound, callID)
	}
	if err != nil {
		return domain.Call{}, err
	}
	return postgres.CallFromRow(r), nil
}

// Get answers a call of the caller's tenant; querying never sends.
func (c *Calls) Get(ctx context.Context, scope Scope, callID string) (domain.Call, error) {
	call, err := c.load(ctx, c.store.Queries(), callID)
	if err != nil {
		return domain.Call{}, err
	}
	if call.TenantID != scope.TenantID {
		return domain.Call{}, fmt.Errorf("%w: call %s", domain.ErrNotFound, callID)
	}
	return call, nil
}

// Create tracks a call and dispatches it. The same command answers the
// original call and never sends again. It waits for the outcome up to
// opts.Wait (and the caller's context); the dispatch continues detached.
func (c *Calls) Create(ctx context.Context, cmd Command, scope Scope, req domain.CallRequest) (domain.Call, bool, error) {
	if err := checkCommand(cmd, scope); err != nil {
		return domain.Call{}, false, err
	}
	if c.closing.Load() {
		return domain.Call{}, false, ErrShuttingDown
	}
	q := c.store.Queries()
	if prev, err := q.GetToolRequestByCommand(ctx, sqlc.GetToolRequestByCommandParams{TenantID: cmd.TenantID, CommandID: cmd.CommandID}); err == nil {
		if prev.RequestDigest != cmd.RequestDigest {
			return domain.Call{}, false, fmt.Errorf("%w: the command id was used with another request", domain.ErrCommandConflict)
		}
		return postgres.CallFromRow(prev), true, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return domain.Call{}, false, err
	}
	now := c.clock.Now()
	if err := domain.CheckCallRequest(req, now); err != nil {
		return domain.Call{}, false, err
	}
	callID := idOf("call-", cmd.TenantID, cmd.CommandID)
	// Control's commercial authorization of the execution, outside every
	// lock and before anything is recorded (P2.1): a denial or an
	// unreachable decision refuses the call.
	if gr, err := q.GetGrant(ctx, req.GrantID); err == nil && gr.TenantID == scope.TenantID {
		decision, err := c.dispatch.CheckExecution(ctx, scope, "mcp-tool", gr.ServerID+"/"+req.Method, "execute")
		if err != nil {
			return domain.Call{}, false, fmt.Errorf("commercial authorization of %s/%s: %w", gr.ServerID, req.Method, err)
		}
		if !decision.Allowed {
			return domain.Call{}, false, fmt.Errorf("%w: %s: %s (revision %s)", ErrForbidden, domain.CallAuthorizationDenied, decision.Reason, decision.Revision)
		}
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return domain.Call{}, false, err
	}
	err := c.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		gr, err := tx.Q.GetGrantForShare(ctx, req.GrantID)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && gr.TenantID != scope.TenantID) {
			return fmt.Errorf("%w: grant %s", domain.ErrNotFound, req.GrantID)
		}
		if err != nil {
			return err
		}
		g := postgres.GrantFromRow(gr)
		if !callerMaySend(scope, g) {
			return fmt.Errorf("%w: grant %s", domain.ErrNotFound, req.GrantID)
		}
		if g.Revision != req.GrantRevision {
			return fmt.Errorf("%w: grant %s is at revision %d", domain.ErrRevisionMismatch, g.GrantID, g.Revision)
		}
		if !g.Executable(now) {
			return fmt.Errorf("%w: %s: grant %s is %s", ErrForbidden, domain.CallGrantNotExecutable, g.GrantID, g.State)
		}
		if !slices.Contains(g.Methods, req.Method) {
			return fmt.Errorf("%w: %s: method %s is not granted", ErrForbidden, domain.CallGrantNotExecutable, req.Method)
		}
		dr, err := tx.Q.GetDescriptor(ctx, sqlc.GetDescriptorParams{ServerID: g.ServerID, Revision: int64(g.DescriptorRevision)})
		if err != nil {
			return err
		}
		if dr.State != string(domain.CatalogApproved) || dr.DescriptorDigest != g.DescriptorDigest {
			return fmt.Errorf("%w: %s: descriptor %s@%d is %s", ErrForbidden, domain.CallGrantNotExecutable, g.ServerID, g.DescriptorRevision, dr.State)
		}
		srv, err := tx.Q.GetServer(ctx, g.ServerID)
		if err != nil {
			return err
		}
		desc, err := postgres.DescriptorFromRow(dr, srv)
		if err != nil {
			return err
		}
		tool, ok := desc.Method(req.Method)
		if !ok {
			return fmt.Errorf("%w: %s: method %s", ErrForbidden, domain.CallSchemaDrift, req.Method)
		}
		// P2.5: the arguments against the grant revision's input schema
		// (CreateCallRequest.arguments), before anything is recorded.
		if err := domain.CheckArguments(desc.InputSchemas[req.Method], req.Arguments); err != nil {
			return err
		}
		route, ok := c.routeOf(g)
		if !ok {
			return fmt.Errorf("%w: %s: no qualified route for %s with %s over %s", ErrForbidden, domain.CallRouteUnqualified, g.CanonicalResource, g.ProtocolVersion, g.Transport)
		}
		restricted, err := tx.Q.HasUnknownToolRequest(ctx, sqlc.HasUnknownToolRequestParams{TenantID: g.TenantID, ServerID: g.ServerID})
		if err != nil {
			return err
		}
		if restricted {
			if c.metrics != nil {
				c.metrics.RestrictedRefusals.Inc()
			}
			return fmt.Errorf("%w: %s: a call to server %s has an unknown outcome", ErrForbidden, domain.CallRecoveryRestricted, g.ServerID)
		}
		return tx.Q.InsertToolRequest(ctx, sqlc.InsertToolRequestParams{
			CallID: callID, TenantID: g.TenantID, GrantID: g.GrantID, GrantRevision: int64(g.Revision), ServerID: g.ServerID,
			DescriptorRevision: int64(g.DescriptorRevision), Method: req.Method, ArgumentRef: req.ArgumentRef, ArgumentDigest: req.ArgumentDigest,
			OperationID: &req.OperationID, AttemptID: &req.AttemptID, CommandID: cmd.CommandID, RequestDigest: cmd.RequestDigest,
			Deadline: pgtype.Timestamptz{Time: req.Deadline.UTC().Truncate(time.Microsecond), Valid: true}, InstanceID: req.InstanceID,
			ExecutionEpoch: int64(req.ExecutionEpoch), Arguments: req.Arguments, DescriptorDigest: g.DescriptorDigest, ProtocolVersion: g.ProtocolVersion,
			Transport: g.Transport, Route: route, SideEffecting: tool.SideEffecting, ExposureCurrency: tool.UnitPrice.Currency, ExposureAmount: tool.UnitPrice.Amount,
		})
	})
	if errors.Is(err, postgres.ErrDuplicateKey) {
		// A concurrent identical command won the insert: answer it.
		return c.Create(ctx, cmd, scope, req)
	}
	if err != nil {
		return domain.Call{}, false, err
	}
	c.count(domain.CallAccepted)
	done := make(chan struct{})
	c.track(callID)
	go func() {
		defer close(done)
		defer c.untrack(callID)
		c.advance(context.WithoutCancel(ctx), callID)
	}()
	wait := time.NewTimer(c.opts.Wait)
	defer wait.Stop()
	select {
	case <-done:
	case <-wait.C:
	case <-ctx.Done():
	}
	call, err := c.load(context.WithoutCancel(ctx), c.store.Queries(), callID)
	return call, false, err
}

func (c *Calls) track(callID string) {
	c.inflight.Add(1)
	c.liveMu.Lock()
	c.live[callID] = struct{}{}
	c.liveMu.Unlock()
}

func (c *Calls) untrack(callID string) {
	c.liveMu.Lock()
	delete(c.live, callID)
	c.liveMu.Unlock()
	c.inflight.Done()
}

// Shutdown stops admitting calls, waits for this process's detached
// dispatches until ctx ends (the caller bounds it by the send bound), and
// records UNKNOWN synchronously for every call of this process still marked
// as sent: the Pod is about to go, and a marked call without an outcome
// must not wait for another replica's reconciler to notice it. Calls that
// were admitted but never marked are left to the reconciler (nothing was
// sent; it cancels them). It reports how many calls it recorded UNKNOWN.
func (c *Calls) Shutdown(ctx context.Context) int {
	c.closing.Store(true)
	done := make(chan struct{})
	go func() { c.inflight.Wait(); close(done) }()
	select {
	case <-done:
		return 0
	case <-ctx.Done():
	}
	c.liveMu.Lock()
	remaining := make([]string, 0, len(c.live))
	for id := range c.live {
		remaining = append(remaining, id)
	}
	c.liveMu.Unlock()
	slices.Sort(remaining)
	record := context.WithoutCancel(ctx)
	q := c.store.Queries()
	recorded := 0
	for _, id := range remaining {
		code := domain.CallOutcomeUnknown
		n, err := q.SetToolRequestOutcome(record, sqlc.SetToolRequestOutcomeParams{CallID: id, State: string(domain.CallUnknown), FailureCode: &code, Expected: []string{string(domain.CallSent)}})
		if err != nil {
			c.log.Warn("shutdown: outcome of an in-flight send not recorded; the reconciler marks it", "callId", id, "err", err)
			continue
		}
		if n != 1 {
			continue // finished or never marked meanwhile
		}
		recorded++
		c.count(domain.CallUnknown)
		c.log.Warn("shutdown: an in-flight send is recorded UNKNOWN; new calls to its server are restricted", "callId", id)
		if call, err := c.load(record, q, id); err == nil {
			observe, cancel := context.WithTimeout(record, 5*time.Second)
			c.observe(observe, call)
			cancel()
		}
	}
	return recorded
}

func (c *Calls) count(s domain.CallState) {
	if c.metrics != nil {
		c.metrics.CallTransitions.WithLabelValues(string(s)).Inc()
	}
}

// advance moves a call as far as it can go from its current state; it is
// what CreateCall runs detached and what the reconciler runs again.
func (c *Calls) advance(ctx context.Context, callID string) {
	call, err := c.load(ctx, c.store.Queries(), callID)
	if err != nil {
		c.log.Warn("tool call load failed", "callId", callID, "err", err)
		return
	}
	switch call.State {
	case domain.CallAccepted:
		c.admit(ctx, call)
	case domain.CallSucceeded, domain.CallFailed, domain.CallCanceled, domain.CallUnknown:
		if call.ObservedAt == nil && call.DispatchID != "" {
			c.observe(ctx, call)
		}
	}
}

func (c *Calls) admit(ctx context.Context, call domain.Call) {
	adm, err := c.dispatch.AdmitTool(ctx, ToolAdmit{
		Command: ControlCommand{TenantID: call.TenantID, CommandID: "admit:" + call.CallID, ActorID: OwnerIdentity, RequestDigest: call.RequestDigest},
		CallID:  call.CallID, OperationID: call.OperationID, AttemptID: call.AttemptID, InstanceID: call.InstanceID, ExecutionEpoch: call.ExecutionEpoch,
		GrantID: call.GrantID, GrantRevision: call.GrantRevision, ServerID: call.ServerID, Method: call.Method, ArgumentDigest: call.ArgumentDigest,
		SideEffecting: call.SideEffecting, MaxExposure: call.Exposure, Deadline: call.Deadline,
	})
	if err != nil {
		// Uncertain admission: the call stays accepted and the reconciler
		// asks again under the same identity (never a new permission).
		c.log.Warn("AdmitTool failed; the call stays accepted", "callId", call.CallID, "err", err)
		return
	}
	q := c.store.Queries()
	if !adm.Allowed {
		if adm.State == "denied" {
			if n, err := q.SetToolRequestAdmission(ctx, sqlc.SetToolRequestAdmissionParams{CallID: call.CallID, State: string(domain.CallDenied), ControlDispatchID: &adm.DispatchID, FailureCode: &adm.DenialCode}); err == nil && n == 1 {
				c.count(domain.CallDenied)
			}
			return
		}
		// A permission was issued to an earlier request of this call whose
		// answer was lost: nobody may send it now. Record the admission and
		// cancel (no marker was ever committed).
		if n, err := q.SetToolRequestAdmission(ctx, sqlc.SetToolRequestAdmissionParams{CallID: call.CallID, State: string(domain.CallAdmitted), ControlDispatchID: &adm.DispatchID}); err != nil || n != 1 {
			return
		}
		call.State, call.DispatchID = domain.CallAdmitted, adm.DispatchID
		c.cancel(ctx, call, domain.CallNotSent)
		return
	}
	n, err := q.SetToolRequestAdmission(ctx, sqlc.SetToolRequestAdmissionParams{CallID: call.CallID, State: string(domain.CallAdmitted), ControlDispatchID: &adm.DispatchID})
	if err != nil || n != 1 {
		c.log.Warn("admitted call changed concurrently; not sending", "callId", call.CallID, "err", err)
		return
	}
	c.count(domain.CallAdmitted)
	call.State, call.DispatchID = domain.CallAdmitted, adm.DispatchID
	c.send(ctx, call)
}

// send runs only in the request that received dispatchAllowed=true.
func (c *Calls) send(ctx context.Context, call domain.Call) {
	q := c.store.Queries()
	gr, err := q.GetGrant(ctx, call.GrantID)
	if err != nil {
		c.cancel(ctx, call, domain.CallGrantNotExecutable)
		return
	}
	g := postgres.GrantFromRow(gr)
	dr, err := q.GetDescriptor(ctx, sqlc.GetDescriptorParams{ServerID: call.ServerID, Revision: int64(call.DescriptorRevision)})
	if err != nil {
		c.cancel(ctx, call, domain.CallGrantNotExecutable)
		return
	}
	srv, err := q.GetServer(ctx, call.ServerID)
	if err != nil {
		c.cancel(ctx, call, domain.CallGrantNotExecutable)
		return
	}
	desc, err := postgres.DescriptorFromRow(dr, srv)
	if err != nil {
		c.cancel(ctx, call, domain.CallGrantNotExecutable)
		return
	}
	tool, _ := desc.Method(call.Method)
	// The send bound runs on the context's own (real) time: the injected
	// clock decides admission and executability, never how long a real
	// qualification and send may take.
	sendCtx, cancel := context.WithTimeout(ctx, c.opts.SendTimeout)
	defer cancel()
	sendCtx, cancelDeadline := context.WithDeadline(sendCtx, call.Deadline)
	defer cancelDeadline()
	token, err := c.tokens.Token(sendCtx, g)
	if err != nil {
		c.log.Warn("upstream authorization refused; call not sent", "callId", call.CallID, "err", err)
		c.cancel(ctx, call, domain.CallAuthorization)
		return
	}
	up, ok := c.upstream[call.Route]
	if !ok {
		c.cancel(ctx, call, domain.CallRouteUnqualified)
		return
	}
	sess, err := up.Open(sendCtx, UpstreamTarget{Resource: g.CanonicalResource, ProtocolVersion: call.ProtocolVersion, Transport: call.Transport,
		Method: call.Method, InputSchemaDigest: tool.InputSchemaDigest, OutputSchemaDigest: tool.OutputSchemaDigest, AnnotationsDigest: tool.AnnotationsDigest,
		ServerName: desc.ServerName, ServerVersion: desc.ServerVersion, NetworkScope: desc.NetworkScope, Token: token})
	if err != nil {
		code := domain.CallUpstreamUnavailable
		var ns *NotSentError
		if errors.As(err, &ns) {
			code = ns.Code
		}
		c.log.Warn("connection not qualified; call not sent", "callId", call.CallID, "code", code, "err", err)
		c.cancel(ctx, call, code)
		return
	}
	defer sess.Close()
	// A send bound that elapsed during qualification: nothing is sent, the
	// permission is canceled (a marker would make a never-sent call UNKNOWN).
	if sendCtx.Err() != nil {
		c.log.Warn("send bound elapsed before the marker; call not sent", "callId", call.CallID, "err", sendCtx.Err())
		c.cancel(ctx, call, domain.CallNotSent)
		return
	}
	// The marker commits with the grant still executable under its share
	// lock: a revocation that committed first is seen here, one that commits
	// later counts this call as open until its outcome is observed.
	marked := false
	err = c.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		gr, err := tx.Q.GetGrantForShare(ctx, call.GrantID)
		if err != nil {
			return err
		}
		cur := postgres.GrantFromRow(gr)
		if cur.Revision != call.GrantRevision || !cur.Executable(c.clock.Now()) {
			return nil
		}
		n, err := tx.Q.SetToolRequestMarker(ctx, call.CallID)
		marked = n == 1
		return err
	})
	if err != nil || !marked {
		if err == nil {
			c.cancel(ctx, call, domain.CallGrantNotExecutable)
		}
		return
	}
	c.count(domain.CallSent)
	reply, err := sess.Send(sendCtx, call.Method, call.Arguments)
	state, code, units := domain.CallSucceeded, "", uint64(1)
	var answered *AnsweredError
	var unknown *UnknownError
	switch {
	case err == nil && reply.IsError:
		state, code = domain.CallFailed, domain.CallToolError
	case err == nil:
	case errors.As(err, &answered):
		state, code = domain.CallFailed, answered.Code
	case errors.As(err, &unknown):
		state, code = domain.CallUnknown, unknown.Code
	default:
		state, code = domain.CallUnknown, domain.CallOutcomeUnknown
	}
	params := sqlc.SetToolRequestOutcomeParams{CallID: call.CallID, State: string(state), Expected: []string{string(domain.CallSent)}, NativeEvidence: reply.Native}
	if code != "" {
		params.FailureCode = &code
	}
	if state != domain.CallUnknown {
		u := int64(units)
		params.UsageUnits = &u
	}
	if reply.Result != nil && state != domain.CallUnknown {
		d := domain.DigestBytes(reply.Result)
		ref := "mcp-result:" + call.CallID
		params.Result, params.ResultDigest, params.ResultRef = reply.Result, &d, &ref
	}
	if n, err := q.SetToolRequestOutcome(ctx, params); err != nil || n != 1 {
		// The reconciler records UNKNOWN for a marked call without outcome.
		c.log.Warn("tool call outcome not recorded", "callId", call.CallID, "err", err)
		return
	}
	c.count(state)
	if state == domain.CallUnknown {
		c.log.Warn("tool call outcome unknown; new calls to the server are restricted", "callId", call.CallID, "serverId", call.ServerID, "code", code)
	}
	call, err = c.load(ctx, q, call.CallID)
	if err == nil {
		c.observe(ctx, call)
	}
}

// cancel ends an admitted call that was never sent (no marker) and reports
// it to Control as CANCELED with zero usage.
func (c *Calls) cancel(ctx context.Context, call domain.Call, code string) {
	q := c.store.Queries()
	zero := int64(0)
	n, err := q.SetToolRequestOutcome(ctx, sqlc.SetToolRequestOutcomeParams{CallID: call.CallID, State: string(domain.CallCanceled), FailureCode: &code,
		UsageUnits: &zero, Expected: []string{string(domain.CallAdmitted)}})
	if err != nil || n != 1 {
		return
	}
	c.count(domain.CallCanceled)
	if call, err = c.load(ctx, q, call.CallID); err == nil {
		c.observe(ctx, call)
	}
}

// observe reports the recorded outcome to Control under the call's next
// observation sequence; a failure leaves it for the reconciler.
func (c *Calls) observe(ctx context.Context, call domain.Call) {
	var outcome string
	var units *uint64
	switch call.State {
	case domain.CallSucceeded:
		outcome, units = OutcomeSucceeded, call.UsageUnits
	case domain.CallFailed:
		outcome, units = OutcomeFailed, call.UsageUnits
	case domain.CallCanceled:
		outcome, units = OutcomeCanceled, call.UsageUnits
	case domain.CallUnknown:
		outcome = OutcomeUnknown
	default:
		return
	}
	if outcome != OutcomeUnknown && units == nil {
		zero := uint64(0)
		units = &zero
	}
	if err := c.dispatch.ObserveTool(ctx, call.DispatchID, call.ObservationSeq, outcome, units, c.clock.Now()); err != nil {
		c.log.Warn("ObserveDispatch failed; the reconciler repeats it", "callId", call.CallID, "err", err)
		return
	}
	if err := c.store.Queries().SetToolRequestObserved(ctx, sqlc.SetToolRequestObservedParams{CallID: call.CallID, ObservationSequence: int64(call.ObservationSeq)}); err != nil {
		c.log.Warn("observation not recorded", "callId", call.CallID, "err", err)
	}
}

// Reconcile advances calls untouched for opts.ReconcileAge: an accepted
// call asks AdmitTool again under its identity; an admitted call without a
// marker was never sent (its sender is gone) and is canceled; a marked call
// without an outcome is UNKNOWN; an UNKNOWN call is resolved only from
// Control's record of its original dispatch (an operator's not-sent
// confirmation or observation); unobserved outcomes are reported again.
//
// A pass walks every open row in keyset-ordered pages of ReconcileBatch
// (the cursor is the last row's (updated_at, call_id)): rows the pass
// cannot advance — UNKNOWN calls waiting for Control — are passed over and
// never hide the rows behind them. A marked call is treated as abandoned
// once its marker is older than the send bound (its sender is bounded by
// it); operator-pending UNKNOWN calls are asked about at ResolveInterval.
func (c *Calls) Reconcile(ctx context.Context) (int, error) {
	q := c.store.Queries()
	sentAge := c.opts.SendTimeout + 5*time.Second
	if c.opts.ReconcileAge < sentAge {
		sentAge = c.opts.ReconcileAge
	}
	seen := map[string]struct{}{}
	total := 0
	after := sqlc.ListOpenToolRequestsParams{Limit: c.opts.ReconcileBatch, AgeSeconds: c.opts.ReconcileAge.Seconds(), SentAgeSeconds: sentAge.Seconds(),
		AfterAt: pgtype.Timestamptz{Time: time.Time{}, Valid: true}, AfterID: ""}
	for {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		rows, err := q.ListOpenToolRequests(ctx, after)
		if err != nil {
			return total, err
		}
		if len(rows) == 0 {
			break
		}
		total += len(rows)
		last := rows[len(rows)-1]
		after.AfterAt, after.AfterID = last.UpdatedAt, last.CallID
		for _, r := range rows {
			call := postgres.CallFromRow(r)
			seen[call.CallID] = struct{}{}
			c.reconcileOne(ctx, q, call)
		}
		if int32(len(rows)) < c.opts.ReconcileBatch {
			break
		}
	}
	c.resolveMu.Lock()
	for id := range c.nextResolve {
		if _, ok := seen[id]; !ok {
			delete(c.nextResolve, id)
		}
	}
	c.resolveMu.Unlock()
	return total, nil
}

func (c *Calls) reconcileOne(ctx context.Context, q *sqlc.Queries, call domain.Call) {
	switch call.State {
	case domain.CallAccepted:
		c.admit(ctx, call)
	case domain.CallAdmitted:
		c.cancel(ctx, call, domain.CallNotSent)
	case domain.CallSent:
		code := domain.CallOutcomeUnknown
		if n, err := q.SetToolRequestOutcome(ctx, sqlc.SetToolRequestOutcomeParams{CallID: call.CallID, State: string(domain.CallUnknown), FailureCode: &code,
			Expected: []string{string(domain.CallSent)}}); err == nil && n == 1 {
			c.count(domain.CallUnknown)
			c.log.Warn("marked call without outcome beyond the send bound; recorded UNKNOWN", "callId", call.CallID, "serverId", call.ServerID)
			if call, err = c.load(ctx, q, call.CallID); err == nil {
				c.observe(ctx, call)
			}
		}
	case domain.CallUnknown:
		if call.ObservedAt == nil {
			c.observe(ctx, call)
			return
		}
		if c.dueForResolve(call.CallID) {
			c.resolve(ctx, call)
		}
	default:
		c.observe(ctx, call)
	}
}

// dueForResolve reports whether an operator-pending UNKNOWN call is asked
// about at Control in this pass, and schedules the next time.
func (c *Calls) dueForResolve(callID string) bool {
	if c.opts.ResolveInterval <= 0 {
		return true
	}
	now := c.clock.Now()
	c.resolveMu.Lock()
	defer c.resolveMu.Unlock()
	if next, ok := c.nextResolve[callID]; ok && now.Before(next) {
		return false
	}
	c.nextResolve[callID] = now.Add(c.opts.ResolveInterval)
	return true
}

// WithAuthorizer gives the call use cases MCP's role bindings (the
// operator reconciliation's call-operator role, P2.5).
func (c *Calls) WithAuthorizer(a *Authorizer) *Calls {
	c.authz = a
	return c
}

// ReconcileCallAs is the operator reconciliation through the API (P2.5):
// the operator holds the call-operator role in the call's tenant; another
// tenant's call is indistinguishable from a missing one. It never sends.
func (c *Calls) ReconcileCallAs(ctx context.Context, scope Scope, callID string) (domain.Call, error) {
	if err := c.authz.Require(scope.TenantID, scope.ActorID, ActCallReconcile); err != nil {
		return domain.Call{}, err
	}
	call, err := c.load(ctx, c.store.Queries(), callID)
	if err != nil {
		return domain.Call{}, err
	}
	if call.TenantID != scope.TenantID {
		return domain.Call{}, fmt.Errorf("%w: call %s", domain.ErrNotFound, callID)
	}
	return c.ReconcileCall(ctx, callID)
}

// ReconcileCall is the operator path (`anvilkit-agent-mcp reconcile
// <callId>`): the call is advanced now under its original identity, an
// UNKNOWN call by Control's current record of its original dispatch —
// which, once Control resolved that identity, clears the RECOVERY_RESTRICTED
// hold on the server. It never sends.
func (c *Calls) ReconcileCall(ctx context.Context, callID string) (domain.Call, error) {
	q := c.store.Queries()
	call, err := c.load(ctx, q, callID)
	if err != nil {
		return domain.Call{}, err
	}
	switch call.State {
	case domain.CallUnknown:
		if call.ObservedAt == nil {
			c.observe(ctx, call)
		}
		c.resolve(ctx, call)
	case domain.CallSent:
		c.reconcileOne(ctx, q, call)
	case domain.CallSucceeded, domain.CallFailed, domain.CallCanceled:
		if call.ObservedAt == nil && call.DispatchID != "" {
			c.observe(ctx, call)
		}
	}
	return c.load(ctx, q, callID)
}

// resolve reads Control's record of an UNKNOWN call's original dispatch.
func (c *Calls) resolve(ctx context.Context, call domain.Call) {
	v, err := c.dispatch.GetTool(ctx, call.TenantID, call.DispatchID)
	if err != nil {
		return
	}
	var state domain.CallState
	var code string
	switch {
	case v.State == "confirmed_not_sent":
		state, code = domain.CallFailed, "CONFIRMED_NOT_SENT"
	case v.State == "observed" && v.Outcome == OutcomeSucceeded:
		state = domain.CallSucceeded
	case v.State == "observed":
		state, code = domain.CallFailed, "RESOLVED_"+v.Outcome
	default:
		// Still unknown: the restriction stays until the original identity
		// is reconciled at Control (manual; no original-outcome query).
		return
	}
	p := sqlc.SetToolRequestOutcomeParams{CallID: call.CallID, State: string(state), Expected: []string{string(domain.CallUnknown)}}
	if code != "" {
		p.FailureCode = &code
	}
	if n, err := c.store.Queries().SetToolRequestOutcome(ctx, p); err == nil && n == 1 {
		c.count(state)
	}
}
