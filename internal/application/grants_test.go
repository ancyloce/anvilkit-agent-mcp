package application_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// fakeRegistry is Control's GrantPolicyService with its rules (idempotent
// receipts, tombstones for revocations before registration, convergence on
// counted senders) and injectable faults at each boundary: a call that
// fails before Control applied it, a call Control applied whose answer is
// lost, and a definitive refusal.
type fakeRegistry struct {
	mu        sync.Mutex
	policies  map[string]*fakePolicy
	fault     map[string]string // method -> "before" | "lost" | "refuse"
	calls     map[string][]string
	epoch     uint64
	inFlight  uint64
	unknown   uint64
	down      bool
	receiptOf map[string]string
}

type fakePolicy struct {
	digest     string
	receipt    string
	epoch      uint64
	registered bool
	revocation string // "" | fenced | converging | converged
	fencedAt   time.Time
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{policies: map[string]*fakePolicy{}, fault: map[string]string{}, calls: map[string][]string{}, receiptOf: map[string]string{}}
}

func key(grant string, rev uint64) string { return fmt.Sprintf("%s@%d", grant, rev) }

func (f *fakeRegistry) take(method, cmd string) string {
	f.calls[method] = append(f.calls[method], cmd)
	if f.down {
		return "before"
	}
	fault := f.fault[method]
	delete(f.fault, method)
	return fault
}

func (f *fakeRegistry) Register(_ context.Context, cmd application.ControlCommand, g domain.Grant) (string, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fault := f.take("register", cmd.CommandID)
	if fault == "before" {
		return "", 0, errors.New("unavailable")
	}
	if fault == "refuse" {
		return "", 0, fmt.Errorf("%w: refused", application.ErrRefused)
	}
	p, ok := f.policies[key(g.GrantID, g.Revision)]
	switch {
	case ok && !p.registered, ok && p.revocation != "":
		return "", 0, fmt.Errorf("%w: revoked", application.ErrRefused)
	case ok && p.digest != g.PolicyDigest:
		return "", 0, fmt.Errorf("%w: conflict", application.ErrRefused)
	case !ok:
		f.epoch++
		p = &fakePolicy{digest: g.PolicyDigest, receipt: "rcpt-" + g.GrantID, epoch: f.epoch, registered: true}
		f.policies[key(g.GrantID, g.Revision)] = p
	}
	if fault == "lost" {
		return "", 0, errors.New("deadline exceeded after send")
	}
	return p.receipt, p.epoch, nil
}

func (f *fakeRegistry) status(p *fakePolicy) application.Barrier {
	at := p.fencedAt
	return application.Barrier{State: p.revocation, InFlight: f.inFlight, Unknown: f.unknown, FencedAt: &at}
}

func (f *fakeRegistry) BeginRevocation(_ context.Context, cmd application.ControlCommand, grantID string, rev uint64) (application.Barrier, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fault := f.take("begin", cmd.CommandID)
	if fault == "before" {
		return application.Barrier{}, errors.New("unavailable")
	}
	p, ok := f.policies[key(grantID, rev)]
	if !ok {
		p = &fakePolicy{revocation: "converged", fencedAt: time.Now()}
		f.policies[key(grantID, rev)] = p
	} else if p.revocation == "" {
		p.revocation, p.fencedAt = "fenced", time.Now()
	}
	if fault == "lost" {
		return application.Barrier{}, errors.New("deadline exceeded after send")
	}
	return f.status(p), nil
}

func (f *fakeRegistry) Revocation(_ context.Context, grantID string, rev uint64) (application.Barrier, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.take("get", grantID) == "before" {
		return application.Barrier{}, errors.New("unavailable")
	}
	p, ok := f.policies[key(grantID, rev)]
	if !ok || p.revocation == "" {
		return application.Barrier{}, fmt.Errorf("%w: no revocation", application.ErrRefused)
	}
	if p.revocation != "converged" {
		if f.inFlight == 0 && f.unknown == 0 {
			p.revocation = "converged"
		} else {
			p.revocation = "converging"
		}
	}
	return f.status(p), nil
}

func (f *fakeRegistry) set(fn func(*fakeRegistry)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func grantRequest(d domain.Descriptor) domain.GrantRequest {
	exp := time.Now().Add(24 * time.Hour)
	return domain.GrantRequest{SubjectType: "project", SubjectID: "proj_a", ServerID: d.ServerID, DescriptorRev: d.Revision, DescriptorDigest: d.Digest,
		Methods: []string{"search_issues"}, ResourceSelectors: []string{"open-issues"}, Purpose: "triage", CostCap: domain.Money{Currency: "USD", Amount: 100}, ExpiresAt: &exp}
}

func (h *catalogHarness) executable(t *testing.T, grantID, tenant string) bool {
	t.Helper()
	var state domain.AuthorizationState
	err := h.store.InTx(context.Background(), func(ctx context.Context, tx postgres.Tx) error {
		var err error
		state, err = postgres.GrantAuthorization(ctx, tx.Q, "grant:"+grantID, tenant, h.clock.Now)
		return err
	})
	require.NoError(t, err)
	return state == domain.AuthorizationCurrent
}

func TestGrants(t *testing.T) {
	h := newCatalogHarness(t)
	ctx := context.Background()
	d := h.approved(t)

	t.Run("a grant binds an approved revision and becomes active only with Control's receipt", func(t *testing.T) {
		c := h.cmd(granter)
		g, existing, err := h.grants.Create(ctx, c, granter, grantRequest(d))
		require.NoError(t, err)
		require.False(t, existing)
		require.Equal(t, domain.GrantActive, g.State)
		require.Equal(t, "rcpt-"+g.GrantID, g.ControlReceiptID)
		require.NotZero(t, g.PolicyEpoch)
		require.Equal(t, g.ComputePolicyDigest(), g.PolicyDigest)
		require.Equal(t, d.CanonicalResource, g.Audience)
		require.Equal(t, "internal", g.DataClass, "the descriptor's class when none is asked")
		require.True(t, h.executable(t, g.GrantID, "tenant_a"))
		again, existing, err := h.grants.Create(ctx, c, granter, grantRequest(d))
		require.NoError(t, err)
		require.True(t, existing)
		require.Equal(t, g.GrantID, again.GrantID)
		conflict := c
		conflict.RequestDigest = domain.DigestBytes([]byte("other"))
		_, _, err = h.grants.Create(ctx, conflict, granter, grantRequest(d))
		require.ErrorIs(t, err, domain.ErrCommandConflict)
	})

	t.Run("a grant never exceeds its descriptor revision, class or the caller's role", func(t *testing.T) {
		for name, mutate := range map[string]func(*domain.GrantRequest){
			"unknown method":     func(r *domain.GrantRequest) { r.Methods = []string{"delete_issue"} },
			"unknown resource":   func(r *domain.GrantRequest) { r.ResourceSelectors = []string{"secrets"} },
			"unknown prompt":     func(r *domain.GrantRequest) { r.PromptSelectors = []string{"jailbreak"} },
			"higher data class":  func(r *domain.GrantRequest) { r.DataClass = "restricted" },
			"other project":      func(r *domain.GrantRequest) { r.SubjectID = "proj_b" },
			"stale digest":       func(r *domain.GrantRequest) { r.DescriptorDigest = domain.DigestBytes([]byte("old")) },
			"already expired":    func(r *domain.GrantRequest) { past := time.Now().Add(-time.Minute); r.ExpiresAt = &past },
			"unreviewed version": func(r *domain.GrantRequest) { r.DescriptorRev = 99 },
		} {
			req := grantRequest(d)
			mutate(&req)
			_, _, err := h.grants.Create(ctx, h.cmd(granter), granter, req)
			require.Error(t, err, name)
		}
		_, _, err := h.grants.Create(ctx, h.cmd(reviewer), reviewer, grantRequest(d))
		require.ErrorIs(t, err, application.ErrForbidden, "a reviewer never grants")
		_, _, err = h.grants.Create(ctx, h.cmd(member), member, grantRequest(d))
		require.ErrorIs(t, err, application.ErrForbidden)
	})

	t.Run("every registration boundary stays non-executable until Control's receipt, under the original identity", func(t *testing.T) {
		for _, fault := range []string{"before", "lost"} {
			h.registry.set(func(f *fakeRegistry) { f.fault["register"] = fault })
			g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, grantRequest(d))
			require.NoError(t, err)
			require.Equal(t, domain.GrantPending, g.State, fault)
			require.Equal(t, "REGISTRATION_UNCERTAIN", g.FailureCode)
			require.False(t, h.executable(t, g.GrantID, "tenant_a"), "an uncertain registration is never executable")
			_, err = h.grants.Reconcile(ctx, 0, 50)
			require.NoError(t, err)
			after, err := h.grants.Get(ctx, granter, g.GrantID)
			require.NoError(t, err)
			require.Equal(t, domain.GrantActive, after.State, fault)
			calls := h.registry.calls["register"]
			require.Equal(t, calls[len(calls)-1], calls[len(calls)-2], "the retry reuses the original command identity")
		}
		h.registry.set(func(f *fakeRegistry) { f.fault["register"] = "refuse" })
		g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, grantRequest(d))
		require.NoError(t, err)
		require.Equal(t, domain.GrantRegistrationFailed, g.State)
		require.False(t, h.executable(t, g.GrantID, "tenant_a"))
	})

	t.Run("a revocation racing an uncertain registration never makes the grant executable", func(t *testing.T) {
		h.registry.set(func(f *fakeRegistry) { f.fault["register"] = "before" })
		g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, grantRequest(d))
		require.NoError(t, err)
		require.Equal(t, domain.GrantPending, g.State)
		revoked, _, err := h.grants.Revoke(ctx, h.cmd(granter), granter, g.GrantID, 1, "user")
		require.NoError(t, err)
		require.Equal(t, domain.GrantRevoked, revoked.State, "Control records a tombstone for the unregistered revision")
		// The registration that was in flight arrives late: Control refuses it.
		_, _, err = h.registry.Register(ctx, application.ControlCommand{CommandID: g.RegistrationCmdID}, g)
		require.ErrorIs(t, err, application.ErrRefused)
		require.False(t, h.executable(t, g.GrantID, "tenant_a"))
	})

	t.Run("revocation blocks new admission at once and finalizes only after every sender converged", func(t *testing.T) {
		g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, grantRequest(d))
		require.NoError(t, err)
		require.Equal(t, domain.GrantActive, g.State)
		h.registry.set(func(f *fakeRegistry) { f.down = true })
		c := h.cmd(granter)
		r, existing, err := h.grants.Revoke(ctx, c, granter, g.GrantID, 1, "compromised")
		require.NoError(t, err)
		require.False(t, existing)
		require.Equal(t, domain.GrantRevoking, r.State, "committed before Control answered")
		require.Equal(t, "none", r.ControlState)
		require.False(t, h.executable(t, g.GrantID, "tenant_a"), "MCP denies new admission from the revocation commit")
		p, err := h.grants.Progress(ctx, granter, g.GrantID)
		require.NoError(t, err)
		require.True(t, p.NewAdmissionBlocked)
		require.False(t, p.SendersConverged, "blocked new admission is not convergence")
		again, existing, err := h.grants.Revoke(ctx, c, granter, g.GrantID, 1, "compromised")
		require.NoError(t, err)
		require.True(t, existing)
		require.Equal(t, domain.GrantRevoking, again.State)

		// Control comes back: the fence is installed, but a sender still holds a permission.
		h.registry.set(func(f *fakeRegistry) { f.down = false; f.inFlight = 1; f.fault["begin"] = "lost" })
		_, err = h.grants.Reconcile(ctx, 0, 50)
		require.NoError(t, err)
		mid, err := h.grants.Get(ctx, granter, g.GrantID)
		require.NoError(t, err)
		require.Equal(t, domain.GrantRevoking, mid.State, "a lost fence answer leaves the grant revoking")
		_, err = h.grants.Reconcile(ctx, 0, 50)
		require.NoError(t, err)
		mid, err = h.grants.Get(ctx, granter, g.GrantID)
		require.NoError(t, err)
		require.Equal(t, domain.GrantRevoking, mid.State)
		require.Equal(t, "converging", mid.ControlState)
		require.Equal(t, uint64(1), mid.InFlightCalls)
		var begins []string
		for _, c := range h.registry.calls["begin"] {
			if strings.Contains(c, g.GrantID) {
				begins = append(begins, c)
			}
		}
		require.GreaterOrEqual(t, len(begins), 2)
		require.Equal(t, begins[0], begins[len(begins)-1], "the fence is always installed under the original revocation command")

		// MCP's own open request of the grant also keeps it revoking.
		h.inst.Admin(t, fmt.Sprintf(`INSERT INTO tool_requests (call_id, tenant_id, grant_id, grant_revision, server_id, descriptor_revision, method, argument_ref, argument_digest, state, command_id, request_digest, deadline, send_marker_at)
			VALUES ('call-open', 'tenant_a', '%s', 1, '%s', 1, 'search_issues', 'ref', '%s', 'unknown', 'cmd-call', '%s', now() + interval '1 hour', now())`, g.GrantID, g.ServerID, domain.DigestBytes([]byte("a")), domain.DigestBytes([]byte("b"))))
		h.registry.set(func(f *fakeRegistry) { f.inFlight = 0 })
		_, err = h.grants.Reconcile(ctx, 0, 50)
		require.NoError(t, err)
		mid, err = h.grants.Get(ctx, granter, g.GrantID)
		require.NoError(t, err)
		require.Equal(t, domain.GrantRevoking, mid.State, "an unknown MCP request is not quiesced")
		require.Equal(t, "converged", mid.ControlState)
		h.inst.Admin(t, "UPDATE tool_requests SET state = 'failed' WHERE call_id = 'call-open'")
		_, err = h.grants.Reconcile(ctx, 0, 50)
		require.NoError(t, err)
		done, err := h.grants.Get(ctx, granter, g.GrantID)
		require.NoError(t, err)
		require.Equal(t, domain.GrantRevoked, done.State)
		require.NotNil(t, done.RevokedAt)
		p, err = h.grants.Progress(ctx, granter, g.GrantID)
		require.NoError(t, err)
		require.True(t, p.SendersConverged)
		require.GreaterOrEqual(t, countEvents(t, h.inst, "mcp.grant-revoked"), 2, "revoking and revoked are published")
		_, _, err = h.grants.Revoke(ctx, h.cmd(granter), granter, g.GrantID, 7, "")
		require.ErrorIs(t, err, domain.ErrRevisionMismatch)
	})

	t.Run("disabling a revision revokes its grants in the same transaction", func(t *testing.T) {
		g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, grantRequest(d))
		require.NoError(t, err)
		require.Equal(t, domain.GrantActive, g.State)
		_, _, err = h.catalog.Disable(ctx, h.cmd(reviewer), reviewer, d.ServerID, d.Revision, "incident")
		require.NoError(t, err)
		r, err := h.grants.Get(ctx, granter, g.GrantID)
		require.NoError(t, err)
		require.Equal(t, domain.GrantRevoking, r.State)
		require.Equal(t, "DESCRIPTOR_DISABLED", r.FailureCode)
		require.False(t, h.executable(t, g.GrantID, "tenant_a"))
		_, err = h.grants.Reconcile(ctx, 0, 50)
		require.NoError(t, err)
		r, err = h.grants.Get(ctx, granter, g.GrantID)
		require.NoError(t, err)
		require.Equal(t, domain.GrantRevoked, r.State)
		_, _, err = h.grants.Create(ctx, h.cmd(granter), granter, grantRequest(d))
		require.ErrorIs(t, err, domain.ErrForbidden, "no new grant on a disabled revision")
	})

	t.Run("expiry ends executability; grants are visible by subject", func(t *testing.T) {
		h.conn.set(issuesURL, liveIssues(`,"required":["query"]`))
		d2 := h.approved(t)
		require.Equal(t, uint64(2), d2.Revision)
		req := grantRequest(d2)
		exp := h.clock.Now().Add(time.Hour)
		req.ExpiresAt = &exp
		g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, req)
		require.NoError(t, err)
		require.True(t, h.executable(t, g.GrantID, "tenant_a"))
		h.clock.Advance(2 * time.Hour)
		require.False(t, h.executable(t, g.GrantID, "tenant_a"), "an expired grant is not executable before any sweep")
		_, err = h.grants.Reconcile(ctx, 0, 50)
		require.NoError(t, err)
		e, err := h.grants.Get(ctx, member, g.GrantID)
		require.NoError(t, err, "a project grant is visible in its project")
		require.Equal(t, domain.GrantExpired, e.State)
		_, err = h.grants.Get(ctx, outsider, g.GrantID)
		require.ErrorIs(t, err, domain.ErrNotFound)
		_, err = h.grants.Get(ctx, application.Scope{TenantID: "tenant_a", ProjectID: "proj_b", ActorID: "mia-member"}, g.GrantID)
		require.ErrorIs(t, err, domain.ErrNotFound)
	})
}

func TestGrantDimensions(t *testing.T) {
	exp := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	base := domain.Grant{GrantID: "g", Revision: 1, TenantID: "t", SubjectType: "project", SubjectID: "p", ServerID: "s", CanonicalResource: "https://a/mcp",
		Issuer: "https://idp", Audience: "https://a/mcp", ProtocolVersion: "2026-07-28", Transport: "streamable-http", DescriptorRevision: 1,
		DescriptorDigest: "sha256:1", Methods: []string{"m"}, ResourceSelectors: []string{"r"}, PromptSelectors: []string{"p"}, Purpose: "x",
		DataClass: "internal", CostCap: domain.Money{Currency: "USD", Amount: 1}, ExpiresAt: &exp}
	keys := map[string]bool{base.CacheKey(): true}
	digests := map[string]bool{base.ComputePolicyDigest(): true}
	for name, mutate := range map[string]func(*domain.Grant){
		"tenant": func(g *domain.Grant) { g.TenantID = "t2" }, "subject": func(g *domain.Grant) { g.SubjectID = "p2" },
		"resource": func(g *domain.Grant) { g.CanonicalResource = "https://b/mcp" }, "issuer": func(g *domain.Grant) { g.Issuer = "https://idp2" },
		"audience": func(g *domain.Grant) { g.Audience = "https://b/mcp" }, "protocol": func(g *domain.Grant) { g.ProtocolVersion = "2025-06-18" },
		"transport": func(g *domain.Grant) { g.Transport = "stdio" }, "descriptor": func(g *domain.Grant) { g.DescriptorDigest = "sha256:2" },
		"methods": func(g *domain.Grant) { g.Methods = []string{"m", "n"} }, "resources": func(g *domain.Grant) { g.ResourceSelectors = nil },
		"prompts": func(g *domain.Grant) { g.PromptSelectors = nil }, "purpose": func(g *domain.Grant) { g.Purpose = "y" },
		"data class": func(g *domain.Grant) { g.DataClass = "public" }, "cost cap": func(g *domain.Grant) { g.CostCap.Amount = 2 },
		"expiry": func(g *domain.Grant) { later := exp.Add(time.Second); g.ExpiresAt = &later }, "revision": func(g *domain.Grant) { g.Revision = 2 },
		"grant": func(g *domain.Grant) { g.GrantID = "g2" },
	} {
		g := base
		mutate(&g)
		require.False(t, keys[g.CacheKey()], "cache identity ignores %s", name)
		require.False(t, digests[g.ComputePolicyDigest()], "policy digest ignores %s", name)
		keys[g.CacheKey()], digests[g.ComputePolicyDigest()] = true, true
	}
	require.NotEqual(t, base.CacheKey(), base.ComputePolicyDigest(), "cache identity and policy digest are separate namespaces")
}
