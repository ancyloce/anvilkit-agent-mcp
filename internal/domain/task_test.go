package domain

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

var bounds = Bounds{MaxInputBytes: 65536, MaxLease: time.Hour, RetryDelay: 5 * time.Second, MaxAttempts: 2}

func localCheckInput(t *testing.T, payload string) []byte {
	t.Helper()
	raw, err := json.Marshal(LocalCheckInput{SchemaVersion: 1, Computation: LocalCheckProfile, Bytes: base64.StdEncoding.EncodeToString([]byte(payload))})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newTask(t *testing.T) Task {
	t.Helper()
	task, err := NewRequest("task_1", "tenant_a", KindLocalCheck, LocalCheckProfile, localCheckInput(t, "hello"), EffectsReconstructible, "", "grant:g1", "req_1", bounds)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestNewRequestRefusals(t *testing.T) {
	big := make([]byte, 70000)
	for i := range big {
		big[i] = 'a'
	}
	cases := []struct {
		name    string
		profile string
		input   []byte
		effects Effects
		dispID  string
		want    error
	}{
		{"unknown profile", "parser-v1", localCheckInput(t, "x"), EffectsReconstructible, "", ErrProfileUnknown},
		{"input over bound", LocalCheckProfile, append([]byte(`{"schemaVersion":1,"computation":"local-check-v1","bytes":"`), append(big, '"', '}')...), EffectsReconstructible, "", ErrInputTooLarge},
		{"not json", LocalCheckProfile, []byte("nope"), EffectsReconstructible, "", ErrInvalid},
		{"wrong computation", LocalCheckProfile, []byte(`{"schemaVersion":1,"computation":"other","bytes":""}`), EffectsReconstructible, "", ErrInvalid},
		{"external without dispatch", LocalCheckProfile, localCheckInput(t, "x"), EffectsExternal, "", ErrInvalid},
	}
	for _, c := range cases {
		_, err := NewRequest("task", "tenant", KindLocalCheck, c.profile, c.input, c.effects, c.dispID, "grant:g", "req", bounds)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
}

func TestClaimFencesAndRaces(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	task := newTask(t)
	d, err := DecideClaim(task, nil, "w1", time.Minute, now, bounds)
	if err != nil {
		t.Fatal(err)
	}
	if d.Task.State != StateLeased || d.Task.AttemptCount != 1 || d.Task.Revision != 2 || d.Attempt.Ordinal != 1 {
		t.Fatalf("claim: %+v", d.Task)
	}
	// The second racer sees the leased row.
	if _, err := DecideClaim(d.Task, []Attempt{d.Attempt}, "w2", time.Minute, now.Add(time.Second), bounds); !errors.Is(err, ErrAlreadyClaimed) {
		t.Fatalf("second claim: %v", err)
	}
	// After expiry, a reconstructible task is claimable by a new identity, not by the same one.
	later := now.Add(2 * time.Minute)
	if _, err := DecideClaim(d.Task, []Attempt{d.Attempt}, "w1", time.Minute, later, bounds); !errors.Is(err, ErrDuplicateClaimID) {
		t.Fatalf("identity reuse: %v", err)
	}
	d2, err := DecideClaim(d.Task, []Attempt{d.Attempt}, "w2", time.Minute, later, bounds)
	if err != nil || !d2.ExpiredPrevious || d2.Task.AttemptCount != 2 {
		t.Fatalf("reclaim: %v %+v", err, d2)
	}
	// The old claimant is fenced: heartbeat and submit are STALE_EXECUTION.
	if _, err := DecideHeartbeat(d2.Task, d2.Attempt, "w1", later); !errors.Is(err, ErrStaleExecution) {
		t.Fatalf("stale heartbeat: %v", err)
	}
	ref, digest, _ := ExpectedResult(task)
	if _, err := DecideSubmit(d2.Task, d2.Attempt, Submission{WorkerID: "w1", InputDigest: task.InputDigest, Succeeded: true, ResultRef: ref, ResultDigest: digest}, AuthorizationCurrent, later, bounds); !errors.Is(err, ErrStaleExecution) {
		t.Fatalf("stale submit: %v", err)
	}
	// Attempts are bounded: a third claim is refused.
	if _, err := DecideClaim(d2.Task, []Attempt{d.Attempt, d2.Attempt}, "w3", time.Minute, later.Add(2*time.Minute), bounds); !errors.Is(err, ErrNotClaimable) {
		t.Fatalf("attempt bound: %v", err)
	}
	// An external-effect lease is never reassigned by a claim.
	ext, _ := NewRequest("task_2", "tenant_a", KindLocalCheck, LocalCheckProfile, localCheckInput(t, "x"), EffectsExternal, "disp_1", "grant:g1", "req_2", bounds)
	e1, _ := DecideClaim(ext, nil, "w1", time.Minute, now, bounds)
	if _, err := DecideClaim(e1.Task, []Attempt{e1.Attempt}, "w2", time.Minute, later, bounds); !errors.Is(err, ErrEffectUncertain) {
		t.Fatalf("external reclaim: %v", err)
	}
}

func TestSubmitAcceptanceRules(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	task := newTask(t)
	d, _ := DecideClaim(task, nil, "w1", time.Minute, now, bounds)
	ref, digest, err := ExpectedResult(task)
	if err != nil {
		t.Fatal(err)
	}
	good := Submission{WorkerID: "w1", InputDigest: task.InputDigest, Succeeded: true, ResultRef: ref, ResultDigest: digest}

	// Digest mismatch is a caller error and changes nothing.
	bad := good
	bad.InputDigest = "sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := DecideSubmit(d.Task, d.Attempt, bad, AuthorizationCurrent, now, bounds); !errors.Is(err, ErrInvalid) {
		t.Fatalf("digest mismatch: %v", err)
	}
	// Profile mismatch consumes the attempt (retry, then dead).
	wrong := good
	wrong.ResultDigest = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
	pm, err := DecideSubmit(d.Task, d.Attempt, wrong, AuthorizationCurrent, now, bounds)
	if err != nil || pm.Accepted || pm.Task.State != StateRetryScheduled || pm.Task.FailureCode != FailureProfileMismatch || pm.AttemptOutcome != AttemptFailed {
		t.Fatalf("profile mismatch: %v %+v", err, pm)
	}
	// Revoked authorization cancels.
	rv, err := DecideSubmit(d.Task, d.Attempt, good, AuthorizationRevoked, now, bounds)
	if err != nil || rv.Accepted || rv.Task.State != StateCanceled || rv.Task.FailureCode != FailureAuthorizationRevoked {
		t.Fatalf("revoked: %v %+v", err, rv)
	}
	// Acceptance, then the identical repeat returns the existing acceptance.
	ok, err := DecideSubmit(d.Task, d.Attempt, good, AuthorizationCurrent, now, bounds)
	if err != nil || !ok.Accepted || ok.Existing || ok.Task.State != StateAccepted || ok.Task.Revision != 3 {
		t.Fatalf("accept: %v %+v", err, ok)
	}
	again, err := DecideSubmit(ok.Task, d.Attempt, good, AuthorizationCurrent, now.Add(time.Hour), bounds)
	if err != nil || !again.Accepted || !again.Existing || again.Changed {
		t.Fatalf("repeat: %v %+v", err, again)
	}
	other := good
	other.ResultDigest = wrong.ResultDigest
	if _, err := DecideSubmit(ok.Task, d.Attempt, other, AuthorizationCurrent, now, bounds); !errors.Is(err, ErrStaleExecution) {
		t.Fatalf("different result after acceptance: %v", err)
	}
	// A reported failure on the last attempt is dead.
	d2, _ := DecideClaim(pm.Task, []Attempt{d.Attempt}, "w2", time.Minute, now.Add(time.Minute), bounds)
	failed, err := DecideSubmit(d2.Task, d2.Attempt, Submission{WorkerID: "w2", InputDigest: task.InputDigest, Succeeded: false, FailureCode: "HANDLER_FAILED"}, AuthorizationCurrent, now.Add(time.Minute), bounds)
	if err != nil || failed.Task.State != StateDead || failed.Task.FailureCode != "HANDLER_FAILED" {
		t.Fatalf("dead: %v %+v", err, failed)
	}
}

func TestExpireCancelSupersede(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	task := newTask(t)
	d, _ := DecideClaim(task, nil, "w1", time.Minute, now, bounds)
	if _, _, changed := DecideExpire(d.Task, DispatchUnknown, now.Add(30*time.Second), bounds); changed {
		t.Fatal("a valid lease does not expire")
	}
	exp, outcome, changed := DecideExpire(d.Task, DispatchUnknown, now.Add(2*time.Minute), bounds)
	if !changed || exp.State != StateRetryScheduled || outcome != AttemptExpired || exp.FailureCode != FailureLeaseExpired || exp.WorkerID != "" {
		t.Fatalf("expire: %+v", exp)
	}
	ext, _ := NewRequest("task_2", "tenant_a", KindLocalCheck, LocalCheckProfile, localCheckInput(t, "x"), EffectsExternal, "disp_1", "grant:g1", "req_2", bounds)
	e1, _ := DecideClaim(ext, nil, "w1", time.Minute, now, bounds)
	dead, _, _ := DecideExpire(e1.Task, DispatchUnknown, now.Add(2*time.Minute), bounds)
	if dead.State != StateDead || dead.FailureCode != FailureEffectUncertain {
		t.Fatalf("unknown effect: %+v", dead)
	}
	released, _, _ := DecideExpire(e1.Task, DispatchNotSent, now.Add(2*time.Minute), bounds)
	if released.State != StateRetryScheduled {
		t.Fatalf("not-sent evidence releases: %+v", released)
	}
	// Cancel while leased fences the attempt; cancel of a terminal state is a no-op.
	c, attempt, changed := DecideCancel(d.Task)
	if !changed || c.State != StateCanceled || attempt != AttemptStale {
		t.Fatalf("cancel: %+v %s", c, attempt)
	}
	if _, _, changed := DecideCancel(c); changed {
		t.Fatal("cancel of canceled")
	}
	// Supersede fences a non-terminal generation.
	s, changed := Supersede(d.Task)
	if !changed || s.State != StateStale || s.FailureCode != FailureSuperseded {
		t.Fatalf("supersede: %+v", s)
	}
	if _, changed := Supersede(c); changed {
		t.Fatal("supersede of terminal")
	}
	ev, err := CompletedEvent(c, now)
	if err != nil || ev.Subject != SubjectBackgroundCompleted || ev.AggregateRevision != "3" {
		t.Fatalf("event: %v %+v", err, ev)
	}
	if _, err := CompletedEvent(d.Task, now); err == nil {
		t.Fatal("completed event of a leased task")
	}
}
