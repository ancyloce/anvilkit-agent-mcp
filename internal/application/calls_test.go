package application_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// fakeToolDispatch is Control's DispatchService for tool dispatches with its
// single-use rule: the first AdmitTool of a call id answers the permission,
// every later one the recorded dispatch without it. Faults: "error" (no
// answer, nothing recorded), "lost" (recorded and permitted, answer lost),
// "deny".
type fakeToolDispatch struct {
	mu        sync.Mutex
	admits    map[string][]application.ToolAdmit
	dispatch  map[string]string // call -> dispatch id
	state     map[string]string // dispatch -> state
	outcome   map[string]string
	observed  map[string][]string // dispatch -> outcomes
	units     map[string]*uint64
	fault     string
	denyCode  string
	observeUp bool
	// authz answers CheckExecution: "" allows, "deny" denies, "error" fails.
	authz  string
	checks int
}

func (f *fakeToolDispatch) CheckExecution(_ context.Context, scope application.Scope, resourceType, resourceID, action string) (application.ExecutionDecision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks++
	switch f.authz {
	case "deny":
		return application.ExecutionDecision{Allowed: false, Revision: "rev-1", Reason: "NO_ENTITLEMENT"}, nil
	case "error":
		return application.ExecutionDecision{}, errors.New("AUTHORITY_UNAVAILABLE")
	}
	return application.ExecutionDecision{Allowed: true, Revision: "rev-1"}, nil
}

func newFakeToolDispatch() *fakeToolDispatch {
	return &fakeToolDispatch{admits: map[string][]application.ToolAdmit{}, dispatch: map[string]string{}, state: map[string]string{}, outcome: map[string]string{},
		observed: map[string][]string{}, units: map[string]*uint64{}, observeUp: true}
}

func (f *fakeToolDispatch) AdmitTool(_ context.Context, r application.ToolAdmit) (application.ToolAdmission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.admits[r.CallID] = append(f.admits[r.CallID], r)
	fault := f.fault
	f.fault = ""
	if fault == "error" {
		return application.ToolAdmission{}, errors.New("unavailable")
	}
	if id, ok := f.dispatch[r.CallID]; ok {
		return application.ToolAdmission{DispatchID: id, State: f.state[id]}, nil
	}
	id := fmt.Sprintf("dsp-%d", len(f.dispatch)+1)
	f.dispatch[r.CallID] = id
	if fault == "deny" {
		f.state[id] = "denied"
		return application.ToolAdmission{DispatchID: id, State: "denied", DenialCode: f.denyCode}, nil
	}
	f.state[id] = "authorized"
	if fault == "lost" {
		return application.ToolAdmission{}, errors.New("deadline exceeded after Control answered")
	}
	return application.ToolAdmission{DispatchID: id, Allowed: true, State: "authorized"}, nil
}

func (f *fakeToolDispatch) ObserveTool(_ context.Context, dispatchID string, _ uint64, outcome string, units *uint64, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.observeUp {
		return errors.New("unavailable")
	}
	f.observed[dispatchID] = append(f.observed[dispatchID], outcome)
	f.units[dispatchID] = units
	if outcome == application.OutcomeUnknown {
		f.state[dispatchID] = "unknown"
	} else {
		f.state[dispatchID], f.outcome[dispatchID] = "observed", outcome
	}
	return nil
}

func (f *fakeToolDispatch) GetTool(_ context.Context, _, dispatchID string) (application.DispatchView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return application.DispatchView{State: f.state[dispatchID], Outcome: f.outcome[dispatchID]}, nil
}

func (f *fakeToolDispatch) set(fn func(*fakeToolDispatch)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// fakeUpstream counts what reached the tool; Open and Send outcomes are
// injectable, and onOpen runs between qualification and the marker.
type fakeUpstream struct {
	mu      sync.Mutex
	sends   map[string]int
	openErr error
	sendErr error
	isError bool
	onOpen  func()
	targets []application.UpstreamTarget
	// hold, when set, keeps a send in flight until it is closed (or ctx ends).
	hold chan struct{}
}

func (u *fakeUpstream) Open(_ context.Context, t application.UpstreamTarget) (application.UpstreamSession, error) {
	u.mu.Lock()
	u.targets = append(u.targets, t)
	err, hook := u.openErr, u.onOpen
	u.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if hook != nil {
		hook()
	}
	return &fakeSession{u: u}, nil
}

type fakeSession struct{ u *fakeUpstream }

func (s *fakeSession) Close() {}

func (s *fakeSession) Send(ctx context.Context, method string, args []byte) (application.UpstreamReply, error) {
	s.u.mu.Lock()
	s.u.sends[string(args)]++
	hold := s.u.hold
	s.u.mu.Unlock()
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return application.UpstreamReply{}, &application.UnknownError{Code: domain.CallOutcomeUnknown, Err: ctx.Err()}
		}
	}
	s.u.mu.Lock()
	defer s.u.mu.Unlock()
	native := []byte(`{"content":[{"type":"text","text":"ok"}]}`)
	if s.u.sendErr != nil {
		return application.UpstreamReply{Native: native}, s.u.sendErr
	}
	return application.UpstreamReply{Result: []byte(`{"untrusted":true,"content":[{"type":"text","text":"ok"}]}`), Native: native, IsError: s.u.isError}, nil
}

func (u *fakeUpstream) count(args string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.sends[args]
}

func (u *fakeUpstream) set(fn func(*fakeUpstream)) {
	u.mu.Lock()
	defer u.mu.Unlock()
	fn(u)
}

type fakeTokens struct{ err error }

func (f *fakeTokens) Token(context.Context, domain.Grant) (string, error) { return "", f.err }

var agent = application.Scope{TenantID: "tenant_a", ProjectID: "proj_a", ActorID: "agent-1"}

func TestCalls(t *testing.T) {
	h := newCatalogHarness(t)
	ctx := context.Background()
	d := h.approved(t)
	req := grantRequest(d)
	req.Methods = []string{"search_issues", "create_issue"}
	g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, req)
	require.NoError(t, err)
	require.Equal(t, domain.GrantActive, g.State)

	disp := newFakeToolDispatch()
	up := &fakeUpstream{sends: map[string]int{}}
	tokens := &fakeTokens{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	calls := application.NewCalls(h.store, disp, map[string]application.Upstream{"go-sdk": up}, tokens,
		[]application.QualifiedRoute{{Resource: issuesURL, ProtocolVersion: protocol, Transport: "streamable-http", Route: "go-sdk"}},
		application.CallOptions{SendTimeout: 5 * time.Second, Wait: 5 * time.Second, ReconcileAge: 0, ReconcileBatch: 50}, h.clock, application.NewMetrics(prometheus.NewRegistry()), log)
	n := 0
	call := func(method, args string) (application.Command, domain.CallRequest) {
		n++
		return h.cmd(agent), domain.CallRequest{GrantID: g.GrantID, GrantRevision: g.Revision, Method: method, ArgumentRef: "inline", ArgumentDigest: domain.DigestBytes([]byte(args)),
			Arguments: []byte(args), OperationID: "op_1", AttemptID: "att_1", InstanceID: "inst_1", ExecutionEpoch: 1, Deadline: time.Now().Add(time.Hour)}
	}
	reconcile := func() {
		_, err := calls.Reconcile(ctx)
		require.NoError(t, err)
	}
	admin := func(stmt string, args ...any) { h.inst.Admin(t, fmt.Sprintf(stmt, args...)) }

	t.Run("a call is admitted once and sent once; the same command answers the original", func(t *testing.T) {
		c, r := call("search_issues", `{"query":"open"}`)
		got, existing, err := calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.False(t, existing)
		require.Equal(t, domain.CallSucceeded, got.State)
		require.Equal(t, 1, up.count(`{"query":"open"}`))
		require.NotEmpty(t, got.ResultDigest)
		require.Equal(t, domain.DigestBytes(got.Result), got.ResultDigest)
		require.NotNil(t, got.ObservedAt)
		require.Equal(t, []string{application.OutcomeSucceeded}, disp.observed[got.DispatchID])
		require.Equal(t, uint64(1), *disp.units[got.DispatchID])
		again, existing, err := calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.True(t, existing)
		require.Equal(t, got.CallID, again.CallID)
		require.Equal(t, 1, up.count(`{"query":"open"}`), "a repeated command never sends again")
		require.Len(t, disp.admits[got.CallID], 1)
		conflict := c
		conflict.RequestDigest = domain.DigestBytes([]byte("other"))
		_, _, err = calls.Create(ctx, conflict, agent, r)
		require.ErrorIs(t, err, domain.ErrCommandConflict)
		read, err := calls.Get(ctx, agent, got.CallID)
		require.NoError(t, err)
		require.Equal(t, got.ResultDigest, read.ResultDigest)
		_, err = calls.Get(ctx, application.Scope{TenantID: "tenant_b", ActorID: "x"}, got.CallID)
		require.ErrorIs(t, err, domain.ErrNotFound)
	})

	t.Run("paid reads and free writes are both admitted, bound to their arguments and effect class", func(t *testing.T) {
		c, r := call("create_issue", `{"title":"x"}`)
		got, _, err := calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.Equal(t, domain.CallSucceeded, got.State)
		a := disp.admits[got.CallID][0]
		require.True(t, a.SideEffecting)
		require.Equal(t, domain.Money{Currency: "USD", Amount: 5}, a.MaxExposure)
		require.Equal(t, domain.DigestBytes([]byte(`{"title":"x"}`)), a.ArgumentDigest)
		require.Equal(t, "admit:"+got.CallID, a.Command.CommandID)
		c, r = call("search_issues", `{"query":"free"}`)
		got, _, err = calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		a = disp.admits[got.CallID][0]
		require.False(t, a.SideEffecting)
		require.Equal(t, int64(0), a.MaxExposure.Amount, "the free read is still admitted")
	})

	t.Run("invalid or unauthorized requests are refused before anything is tracked", func(t *testing.T) {
		for name, mutate := range map[string]func(*domain.CallRequest){
			"digest mismatch": func(r *domain.CallRequest) { r.Arguments = []byte(`{"query":"other"}`) },
			"not an object": func(r *domain.CallRequest) {
				r.Arguments = []byte(`[1]`)
				r.ArgumentDigest = domain.DigestBytes(r.Arguments)
			},
			"duplicate keys": func(r *domain.CallRequest) {
				r.Arguments = []byte(`{"a":1,"a":2}`)
				r.ArgumentDigest = domain.DigestBytes(r.Arguments)
			},
			"P2.5: arguments that violate the revision's input schema": func(r *domain.CallRequest) {
				r.Arguments = []byte(`{"query":5}`)
				r.ArgumentDigest = domain.DigestBytes(r.Arguments)
			},
			"no binding":        func(r *domain.CallRequest) { r.AttemptID = "" },
			"ungranted method":  func(r *domain.CallRequest) { r.Method = "delete_issue" },
			"stale revision":    func(r *domain.CallRequest) { r.GrantRevision = 2 },
			"unknown grant":     func(r *domain.CallRequest) { r.GrantID = "grt-unknown" },
			"past the deadline": func(r *domain.CallRequest) { r.Deadline = time.Now().Add(-time.Second) },
		} {
			c, r := call("search_issues", `{"query":"refused"}`)
			mutate(&r)
			_, _, err := calls.Create(ctx, c, agent, r)
			require.Error(t, err, name)
		}
		c, r := call("search_issues", `{"query":5}`)
		_, _, err := calls.Create(ctx, c, agent, r)
		require.ErrorIs(t, err, domain.ErrInvalid)
		require.ErrorContains(t, err, domain.CallArgumentsInvalid)
		var tracked int
		require.NoError(t, h.store.Pool().QueryRow(ctx, "SELECT count(*) FROM tool_requests WHERE command_id = $1", c.CommandID).Scan(&tracked))
		require.Zero(t, tracked, "an argument refusal records nothing")
		c, r = call("search_issues", `{"query":"refused"}`)
		_, _, err = calls.Create(ctx, c, application.Scope{TenantID: "tenant_a", ProjectID: "proj_b", ActorID: "agent-1"}, r)
		require.ErrorIs(t, err, domain.ErrNotFound, "another project's caller never sees the grant")
		require.Equal(t, 0, up.count(`{"query":"refused"}`))
	})

	t.Run("P2.1: Control's commercial authorization refuses the call before anything is tracked", func(t *testing.T) {
		for _, answer := range []string{"deny", "error"} {
			disp.set(func(f *fakeToolDispatch) { f.authz = answer })
			c, r := call("search_issues", `{"query":"commercial-`+answer+`"}`)
			_, _, err := calls.Create(ctx, c, agent, r)
			require.Error(t, err, answer)
			if answer == "deny" {
				require.ErrorIs(t, err, application.ErrForbidden)
				require.ErrorContains(t, err, domain.CallAuthorizationDenied)
			}
			_, err = calls.Get(ctx, agent, "call-unknown")
			require.ErrorIs(t, err, domain.ErrNotFound)
			require.Equal(t, 0, up.count(`{"query":"commercial-`+answer+`"}`), "nothing reaches the tool")
			var tracked int
			require.NoError(t, h.store.Pool().QueryRow(ctx, "SELECT count(*) FROM tool_requests WHERE command_id = $1", c.CommandID).Scan(&tracked))
			require.Zero(t, tracked, "no call is recorded")
		}
		disp.set(func(f *fakeToolDispatch) { f.authz = "" })
	})

	t.Run("a connection that is not qualified is never sent to; the permission is canceled", func(t *testing.T) {
		for code, set := range map[string]func(){
			domain.CallSchemaDrift: func() {
				up.set(func(u *fakeUpstream) {
					u.openErr = &application.NotSentError{Code: domain.CallSchemaDrift, Err: errors.New("drift")}
				})
			},
			domain.CallEgressRefused: func() {
				up.set(func(u *fakeUpstream) {
					u.openErr = &application.NotSentError{Code: domain.CallEgressRefused, Err: errors.New("rebind")}
				})
			},
			domain.CallAuthorization: func() { tokens.err = errors.New("substituted metadata") },
			domain.CallProtocolMismatch: func() {
				up.set(func(u *fakeUpstream) {
					u.openErr = &application.NotSentError{Code: domain.CallProtocolMismatch, Err: errors.New("2025-06-18")}
				})
			},
		} {
			set()
			args := fmt.Sprintf(`{"query":%q}`, code)
			c, r := call("search_issues", args)
			got, _, err := calls.Create(ctx, c, agent, r)
			require.NoError(t, err)
			require.Equal(t, domain.CallCanceled, got.State, code)
			require.Equal(t, code, got.FailureCode)
			require.Equal(t, 0, up.count(args), code)
			require.Equal(t, []string{application.OutcomeCanceled}, disp.observed[got.DispatchID])
			require.Equal(t, uint64(0), *disp.units[got.DispatchID])
			up.set(func(u *fakeUpstream) { u.openErr = nil })
			tokens.err = nil
		}
	})

	t.Run("a refusal answered by the server fails definitively; a tool error is a failed outcome", func(t *testing.T) {
		up.set(func(u *fakeUpstream) {
			u.sendErr = &application.AnsweredError{Code: domain.CallProtocolError, Err: errors.New("-32602")}
		})
		c, r := call("search_issues", `{"query":"answered"}`)
		got, _, err := calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.Equal(t, domain.CallFailed, got.State)
		require.Equal(t, domain.CallProtocolError, got.FailureCode)
		require.Equal(t, []string{application.OutcomeFailed}, disp.observed[got.DispatchID])
		up.set(func(u *fakeUpstream) { u.sendErr, u.isError = nil, true })
		c, r = call("search_issues", `{"query":"iserror"}`)
		got, _, err = calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.Equal(t, domain.CallFailed, got.State)
		require.Equal(t, domain.CallToolError, got.FailureCode)
		up.set(func(u *fakeUpstream) { u.isError = false })
	})

	t.Run("Control's denial is final and nothing is sent", func(t *testing.T) {
		disp.set(func(f *fakeToolDispatch) { f.fault, f.denyCode = "deny", "BUDGET_EXHAUSTED" })
		c, r := call("search_issues", `{"query":"denied"}`)
		got, _, err := calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.Equal(t, domain.CallDenied, got.State)
		require.Equal(t, "BUDGET_EXHAUSTED", got.FailureCode)
		require.Equal(t, 0, up.count(`{"query":"denied"}`))
	})

	t.Run("crash boundaries: lost admission, abandoned permission, sent without outcome", func(t *testing.T) {
		// AdmitTool unanswered: the call stays accepted and asks again.
		disp.set(func(f *fakeToolDispatch) { f.fault = "error" })
		c, r := call("search_issues", `{"query":"retry-admit"}`)
		got, _, err := calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.Equal(t, domain.CallAccepted, got.State)
		reconcile()
		got, _ = calls.Get(ctx, agent, got.CallID)
		require.Equal(t, domain.CallSucceeded, got.State, "the first permission under the call's identity is used once")
		require.Equal(t, 1, up.count(`{"query":"retry-admit"}`))

		// Control permitted but the answer was lost: nobody may send it.
		disp.set(func(f *fakeToolDispatch) { f.fault = "lost" })
		c, r = call("search_issues", `{"query":"lost"}`)
		got, _, err = calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.Equal(t, domain.CallAccepted, got.State)
		reconcile()
		got, _ = calls.Get(ctx, agent, got.CallID)
		require.Equal(t, domain.CallCanceled, got.State)
		require.Equal(t, domain.CallNotSent, got.FailureCode)
		require.Equal(t, 0, up.count(`{"query":"lost"}`), "a permission whose answer was lost is never sent")
		require.Equal(t, []string{application.OutcomeCanceled}, disp.observed[got.DispatchID])

		// The sender died after admission, before its marker.
		disp.set(func(f *fakeToolDispatch) { f.fault = "error" })
		c, r = call("search_issues", `{"query":"abandoned"}`)
		got, _, err = calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		admin("UPDATE tool_requests SET state = 'admitted', control_dispatch_id = 'dsp-abandoned' WHERE call_id = '%s'", got.CallID)
		disp.set(func(f *fakeToolDispatch) { f.state["dsp-abandoned"] = "authorized" })
		reconcile()
		got, _ = calls.Get(ctx, agent, got.CallID)
		require.Equal(t, domain.CallCanceled, got.State)
		require.Equal(t, []string{application.OutcomeCanceled}, disp.observed["dsp-abandoned"])

		// The sender died after its marker, before the outcome.
		disp.set(func(f *fakeToolDispatch) { f.fault = "error" })
		c, r = call("create_issue", `{"title":"marked"}`)
		got, _, err = calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		admin("UPDATE tool_requests SET state = 'sent', send_marker_at = now(), control_dispatch_id = 'dsp-marked' WHERE call_id = '%s'", got.CallID)
		reconcile()
		got, _ = calls.Get(ctx, agent, got.CallID)
		require.Equal(t, domain.CallUnknown, got.State)
		require.Equal(t, []string{application.OutcomeUnknown}, disp.observed["dsp-marked"])
		require.Equal(t, 0, up.count(`{"title":"marked"}`), "an uncertain send is never repeated")

		// UNKNOWN restricts new calls to the server, of any id, until the
		// original identity is resolved at Control.
		c, r = call("search_issues", `{"query":"replacement"}`)
		_, _, err = calls.Create(ctx, c, agent, r)
		require.ErrorIs(t, err, application.ErrForbidden)
		require.ErrorContains(t, err, domain.CallRecoveryRestricted)
		reconcile()
		got, _ = calls.Get(ctx, agent, got.CallID)
		require.Equal(t, domain.CallUnknown, got.State, "no query answers it: recovery stays manual")
		disp.set(func(f *fakeToolDispatch) { f.state["dsp-marked"] = "confirmed_not_sent" })
		reconcile()
		got, _ = calls.Get(ctx, agent, got.CallID)
		require.Equal(t, domain.CallFailed, got.State)
		require.Equal(t, "CONFIRMED_NOT_SENT", got.FailureCode)
		c, r = call("search_issues", `{"query":"after-resolution"}`)
		got, _, err = calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.Equal(t, domain.CallSucceeded, got.State)
	})

	t.Run("an unknown send outcome is recorded, observed and never resent", func(t *testing.T) {
		up.set(func(u *fakeUpstream) {
			u.sendErr = &application.UnknownError{Code: domain.CallOutcomeUnknown, Err: errors.New("connection reset")}
		})
		c, r := call("create_issue", `{"title":"reset"}`)
		got, _, err := calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.Equal(t, domain.CallUnknown, got.State)
		require.Equal(t, []string{application.OutcomeUnknown}, disp.observed[got.DispatchID])
		up.set(func(u *fakeUpstream) { u.sendErr = nil })
		reconcile()
		require.Equal(t, 1, up.count(`{"title":"reset"}`))
		disp.set(func(f *fakeToolDispatch) {
			f.state[got.DispatchID], f.outcome[got.DispatchID] = "observed", application.OutcomeSucceeded
		})
		reconcile()
		got, _ = calls.Get(ctx, agent, got.CallID)
		require.Equal(t, domain.CallSucceeded, got.State, "resolved from Control's record of the original dispatch")
	})

	t.Run("P1.2: sixty unresolvable UNKNOWN rows do not starve the reconciler; a newly resolved row settles within two passes", func(t *testing.T) {
		// Sixty operator-pending rows older than the batch (50), all unknown at
		// Control (the fake answers "unknown" for dispatch ids it never issued);
		// they belong to another tenant so the restriction they carry does not
		// fall on tenant_a's server.
		for i := 0; i < 60; i++ {
			admin("INSERT INTO tool_requests (call_id, tenant_id, grant_id, grant_revision, server_id, descriptor_revision, method, argument_ref, argument_digest, operation_id, attempt_id, state, command_id, request_digest, deadline, instance_id, execution_epoch, arguments, descriptor_digest, protocol_version, transport, route, side_effecting, exposure_currency, exposure_amount, control_dispatch_id, failure_code, send_marker_at, observed_at, created_at, updated_at) "+
				"VALUES ('call-stuck-%d', 'tenant_stuck', '%s', %d, '%s', %d, 'search_issues', 'inline', '%s', 'op_1', 'att_1', 'unknown', 'cmd-stuck-%d', '%s', now() + interval '1 hour', 'inst_1', 1, '{}', '%s', '%s', 'streamable-http', 'go-sdk', false, 'USD', 0, 'dsp-stuck-%d', 'OUTCOME_UNKNOWN', now() - interval '10 minutes', now() - interval '10 minutes', now() - interval '10 minutes', now() - interval '10 minutes' + make_interval(secs => %d))",
				i, g.GrantID, g.Revision, g.ServerID, g.DescriptorRevision, domain.DigestBytes([]byte("{}")), i, domain.DigestBytes([]byte(fmt.Sprintf("stuck-%d", i))), g.DescriptorDigest, g.ProtocolVersion, i, i)
		}
		// The row that will be resolved is the newest open one: a LIMIT over the
		// oldest rows never reaches it.
		up.set(func(u *fakeUpstream) {
			u.sendErr = &application.UnknownError{Code: domain.CallOutcomeUnknown, Err: errors.New("connection reset")}
		})
		disp.set(func(f *fakeToolDispatch) { f.fault = "" })
		c, r := call("create_issue", `{"title":"newest-unknown"}`)
		got, _, err := calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.Equal(t, domain.CallUnknown, got.State)
		up.set(func(u *fakeUpstream) { u.sendErr = nil })
		disp.set(func(f *fakeToolDispatch) {
			f.state[got.DispatchID], f.outcome[got.DispatchID] = "observed", application.OutcomeSucceeded
		})
		n1, err := calls.Reconcile(ctx)
		require.NoError(t, err)
		require.GreaterOrEqual(t, n1, 61, "the pass walks every open row, not one batch")
		resolved, _ := calls.Get(ctx, agent, got.CallID)
		if resolved.State != domain.CallSucceeded {
			reconcile()
			resolved, _ = calls.Get(ctx, agent, got.CallID)
		}
		require.Equal(t, domain.CallSucceeded, resolved.State, "resolved within two passes behind sixty unresolvable rows")
		require.Equal(t, 1, up.count(`{"title":"newest-unknown"}`))
		admin("DELETE FROM tool_requests WHERE call_id LIKE 'call-stuck-%%'")
	})

	t.Run("P1.2: the operator path advances one call now; a resolved identity at Control clears the restriction", func(t *testing.T) {
		up.set(func(u *fakeUpstream) {
			u.sendErr = &application.UnknownError{Code: domain.CallOutcomeUnknown, Err: errors.New("connection reset")}
		})
		c, r := call("create_issue", `{"title":"operator"}`)
		got, _, err := calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.Equal(t, domain.CallUnknown, got.State)
		up.set(func(u *fakeUpstream) { u.sendErr = nil })
		c2, r2 := call("search_issues", `{"query":"restricted"}`)
		_, _, err = calls.Create(ctx, c2, agent, r2)
		require.ErrorContains(t, err, domain.CallRecoveryRestricted)
		still, err := calls.ReconcileCall(ctx, got.CallID)
		require.NoError(t, err)
		require.Equal(t, domain.CallUnknown, still.State, "Control has not resolved the identity: the call stays unknown")
		disp.set(func(f *fakeToolDispatch) { f.state[got.DispatchID] = "confirmed_not_sent" })
		done, err := calls.ReconcileCall(ctx, got.CallID)
		require.NoError(t, err)
		require.Equal(t, domain.CallFailed, done.State)
		require.Equal(t, "CONFIRMED_NOT_SENT", done.FailureCode)
		c3, r3 := call("search_issues", `{"query":"unrestricted"}`)
		ok, _, err := calls.Create(ctx, c3, agent, r3)
		require.NoError(t, err)
		require.Equal(t, domain.CallSucceeded, ok.State)
		require.Equal(t, 1, up.count(`{"title":"operator"}`), "the operator path never sends")
		_, err = calls.ReconcileCall(ctx, "call-nonexistent")
		require.ErrorIs(t, err, domain.ErrNotFound)
		// P2.5: through the API, the operator holds the call-operator role in the call's tenant.
		_, err = calls.ReconcileCallAs(ctx, agent, got.CallID)
		require.ErrorIs(t, err, application.ErrForbidden, "a caller without the role")
		ops, err := application.NewAuthorizer([]application.RoleBinding{{TenantID: "tenant_a", ActorID: "olga-operator", Role: application.RoleCallOperator},
			{TenantID: "tenant_b", ActorID: "otto-operator", Role: application.RoleCallOperator}})
		require.NoError(t, err)
		calls.WithAuthorizer(ops)
		viaAPI, err := calls.ReconcileCallAs(ctx, application.Scope{TenantID: "tenant_a", ActorID: "olga-operator"}, got.CallID)
		require.NoError(t, err)
		require.Equal(t, domain.CallFailed, viaAPI.State)
		_, err = calls.ReconcileCallAs(ctx, application.Scope{TenantID: "tenant_b", ActorID: "otto-operator"}, got.CallID)
		require.ErrorIs(t, err, domain.ErrNotFound, "another tenant's call is indistinguishable from a missing one")
		require.Equal(t, 1, up.count(`{"title":"operator"}`), "the operator path never sends")
	})

	t.Run("P1.2: a stop waits for in-flight sends within its bound and records UNKNOWN for what did not finish", func(t *testing.T) {
		// A separate Calls so its closing state does not affect the other scenarios.
		hold := make(chan struct{})
		holdUp := &fakeUpstream{sends: map[string]int{}, hold: hold}
		stopping := application.NewCalls(h.store, disp, map[string]application.Upstream{"go-sdk": holdUp}, tokens,
			[]application.QualifiedRoute{{Resource: issuesURL, ProtocolVersion: protocol, Transport: "streamable-http", Route: "go-sdk"}},
			application.CallOptions{SendTimeout: 30 * time.Second, Wait: 200 * time.Millisecond, ReconcileAge: 0, ReconcileBatch: 50}, h.clock, application.NewMetrics(prometheus.NewRegistry()), log)
		c, _, err := stopping.Create(ctx, h.cmd(agent), agent, domain.CallRequest{GrantID: g.GrantID, GrantRevision: g.Revision, Method: "search_issues", ArgumentRef: "inline",
			ArgumentDigest: domain.DigestBytes([]byte(`{"query":"in-flight"}`)), Arguments: []byte(`{"query":"in-flight"}`), OperationID: "op_1", AttemptID: "att_1", InstanceID: "inst_1", ExecutionEpoch: 1, Deadline: time.Now().Add(time.Hour)})
		require.NoError(t, err)
		require.Equal(t, domain.CallSent, c.State, "the send is in flight when the wait returns")
		// The send finishes within the stop bound: a definite outcome.
		go func() { time.Sleep(300 * time.Millisecond); close(hold) }()
		stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		recorded := stopping.Shutdown(stopCtx)
		cancel()
		require.Zero(t, recorded)
		finished, _ := stopping.Get(ctx, agent, c.CallID)
		require.Equal(t, domain.CallSucceeded, finished.State)
		_, _, err = stopping.Create(ctx, h.cmd(agent), agent, domain.CallRequest{GrantID: g.GrantID, GrantRevision: g.Revision, Method: "search_issues", ArgumentRef: "inline",
			ArgumentDigest: domain.DigestBytes([]byte(`{"query":"late"}`)), Arguments: []byte(`{"query":"late"}`), OperationID: "op_1", AttemptID: "att_1", InstanceID: "inst_1", ExecutionEpoch: 1, Deadline: time.Now().Add(time.Hour)})
		require.ErrorIs(t, err, application.ErrShuttingDown, "a stopping process admits nothing")

		// A send still running at the bound is recorded UNKNOWN before the process exits.
		hold2 := make(chan struct{})
		holdUp2 := &fakeUpstream{sends: map[string]int{}, hold: hold2}
		stopping2 := application.NewCalls(h.store, disp, map[string]application.Upstream{"go-sdk": holdUp2}, tokens,
			[]application.QualifiedRoute{{Resource: issuesURL, ProtocolVersion: protocol, Transport: "streamable-http", Route: "go-sdk"}},
			application.CallOptions{SendTimeout: 30 * time.Second, Wait: 200 * time.Millisecond, ReconcileAge: 0, ReconcileBatch: 50}, h.clock, application.NewMetrics(prometheus.NewRegistry()), log)
		c2, _, err := stopping2.Create(ctx, h.cmd(agent), agent, domain.CallRequest{GrantID: g.GrantID, GrantRevision: g.Revision, Method: "create_issue", ArgumentRef: "inline",
			ArgumentDigest: domain.DigestBytes([]byte(`{"title":"at-the-bound"}`)), Arguments: []byte(`{"title":"at-the-bound"}`), OperationID: "op_1", AttemptID: "att_1", InstanceID: "inst_1", ExecutionEpoch: 1, Deadline: time.Now().Add(time.Hour)})
		require.NoError(t, err)
		require.Equal(t, domain.CallSent, c2.State)
		stopCtx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
		recorded = stopping2.Shutdown(stopCtx)
		cancel()
		require.Equal(t, 1, recorded)
		unknown, _ := stopping2.Get(ctx, agent, c2.CallID)
		require.Equal(t, domain.CallUnknown, unknown.State)
		require.NotNil(t, unknown.ObservedAt, "the UNKNOWN is observed at Control synchronously")
		require.Equal(t, []string{application.OutcomeUnknown}, disp.observed[c2.DispatchID])
		close(hold2)
		time.Sleep(200 * time.Millisecond) // the late sender finds its record no longer 'sent' and records nothing
		late, _ := stopping2.Get(ctx, agent, c2.CallID)
		require.Equal(t, domain.CallUnknown, late.State, "a late outcome never overwrites the recorded UNKNOWN")
		require.Equal(t, 1, holdUp2.count(`{"title":"at-the-bound"}`))
		disp.set(func(f *fakeToolDispatch) { f.state[c2.DispatchID] = "confirmed_not_sent" })
		_, err = calls.ReconcileCall(ctx, c2.CallID)
		require.NoError(t, err)
	})

	t.Run("a revocation committed between admission and the marker cancels the send", func(t *testing.T) {
		up.set(func(u *fakeUpstream) {
			u.onOpen = func() {
				admin("UPDATE grants SET state = 'revoking', revocation_command_id = 'rev-race', fenced_at = now() WHERE grant_id = '%s'", g.GrantID)
			}
		})
		c, r := call("search_issues", `{"query":"raced"}`)
		got, _, err := calls.Create(ctx, c, agent, r)
		require.NoError(t, err)
		require.Equal(t, domain.CallCanceled, got.State)
		require.Equal(t, domain.CallGrantNotExecutable, got.FailureCode)
		require.Equal(t, 0, up.count(`{"query":"raced"}`))
		up.set(func(u *fakeUpstream) { u.onOpen = nil })
		c, r = call("search_issues", `{"query":"after-revoke"}`)
		_, _, err = calls.Create(ctx, c, agent, r)
		require.ErrorIs(t, err, application.ErrForbidden, "a revoking grant admits no new call")
	})
}
