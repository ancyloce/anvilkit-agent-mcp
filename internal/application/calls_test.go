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

func (s *fakeSession) Send(_ context.Context, method string, args []byte) (application.UpstreamReply, error) {
	s.u.mu.Lock()
	defer s.u.mu.Unlock()
	s.u.sends[string(args)]++
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
		c, r := call("search_issues", `{"query":"refused"}`)
		_, _, err := calls.Create(ctx, c, application.Scope{TenantID: "tenant_a", ProjectID: "proj_b", ActorID: "agent-1"}, r)
		require.ErrorIs(t, err, domain.ErrNotFound, "another project's caller never sees the grant")
		require.Equal(t, 0, up.count(`{"query":"refused"}`))
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
