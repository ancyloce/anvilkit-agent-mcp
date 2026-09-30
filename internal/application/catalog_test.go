package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/testdb"
)

// fakeConnection stands in for ContextForge: what a discovery of a
// resource reads, and how often it was asked.
type fakeConnection struct {
	mu    sync.Mutex
	live  map[string]domain.LiveServer
	calls int
}

func (f *fakeConnection) Discover(_ context.Context, resource string) (domain.LiveServer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	l, ok := f.live[resource]
	if !ok {
		return domain.LiveServer{}, errors.New("unreachable")
	}
	return l, nil
}

func (f *fakeConnection) set(resource string, l domain.LiveServer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.live[resource] = l
}

type fakeResolver map[string][]netip.Addr

func (r fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

const (
	issuesURL = "https://mcp.issues.example/mcp"
	protocol  = "2026-07-28"
)

func liveIssues(extraSchema string) domain.LiveServer {
	schema := `{"type":"object","properties":{"query":{"type":"string"}}` + extraSchema + `}`
	return domain.LiveServer{
		Name: "issues", Version: "1.4.0", ProtocolVersion: protocol, ConnectionRef: "contextforge:gw-1", Evidence: "fixture retrieval",
		Tools: []domain.LiveTool{
			{Name: "search_issues", InputSchema: json.RawMessage(schema), Annotations: json.RawMessage(`{"readOnlyHint":true}`)},
			{Name: "create_issue", InputSchema: json.RawMessage(`{"type":"object","properties":{"title":{"type":"string"}}}`)},
		},
		Resources: []domain.LiveNamed{{Name: "open-issues", URI: "issues://open"}},
		Prompts:   []domain.LiveNamed{{Name: "triage"}},
	}
}

func declaration() domain.Declaration {
	return domain.Declaration{
		CanonicalResource: issuesURL, Transport: "streamable-http", ProtocolVersion: protocol, Provenance: "registry:io.example/issues@1.4.0", DataClass: "internal",
		Tools: []domain.ToolDeclaration{
			{Method: "search_issues", UnitPrice: domain.Money{Currency: "USD", Amount: 0}, Idempotent: true},
			{Method: "create_issue", SideEffecting: true, UnitPrice: domain.Money{Currency: "USD", Amount: 5}},
		},
	}
}

type catalogHarness struct {
	inst     *testdb.Instance
	store    *postgres.Store
	conn     *fakeConnection
	catalog  *application.Catalog
	grants   *application.Grants
	registry *fakeRegistry
	clock    *fakeClock
	seq      int
}

func (h *catalogHarness) cmd(scope application.Scope) application.Command {
	h.seq++
	id := fmt.Sprintf("cmd-%d-%d", time.Now().UnixNano(), h.seq)
	return application.Command{TenantID: scope.TenantID, CommandID: id, ActorID: scope.ActorID, RequestDigest: domain.DigestBytes([]byte(id))}
}

var (
	manager  = application.Scope{TenantID: "tenant_a", ProjectID: "proj_a", ActorID: "carol-manager"}
	reviewer = application.Scope{TenantID: "tenant_a", ProjectID: "proj_a", ActorID: "rita-reviewer"}
	granter  = application.Scope{TenantID: "tenant_a", ProjectID: "proj_a", ActorID: "gus-granter"}
	member   = application.Scope{TenantID: "tenant_a", ProjectID: "proj_a", ActorID: "mia-member"}
	outsider = application.Scope{TenantID: "tenant_b", ProjectID: "proj_a", ActorID: "rita-reviewer"}
)

func newCatalogHarness(t *testing.T) *catalogHarness {
	t.Helper()
	inst := testdb.Start(t)
	store := postgres.NewStore(inst.Pool(t))
	authz, err := application.NewAuthorizer([]application.RoleBinding{
		{TenantID: "tenant_a", ActorID: "carol-manager", Role: application.RoleCatalogManager},
		{TenantID: "tenant_a", ActorID: "rita-reviewer", Role: application.RoleCatalogReviewer},
		{TenantID: "tenant_a", ActorID: "gus-granter", Role: application.RoleGrantManager},
		{TenantID: "tenant_b", ActorID: "rita-reviewer", Role: application.RoleCatalogManager},
	})
	require.NoError(t, err)
	conn := &fakeConnection{live: map[string]domain.LiveServer{issuesURL: liveIssues("")}}
	clock := &fakeClock{now: time.Now().UTC()}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := newFakeRegistry()
	grants := application.NewGrants(store, authz, registry, clock, log, application.NewMetrics(prometheus.NewRegistry()))
	resolver := fakeResolver{"mcp.issues.example": {netip.MustParseAddr("203.0.113.10")}, "internal.example": {netip.MustParseAddr("10.0.0.5")},
		"metadata.example": {netip.MustParseAddr("169.254.169.254")}, "fixture.local": {netip.MustParseAddr("127.0.0.1")}}
	policy := application.NetworkPolicy{AllowedHosts: []string{".issues.example", "internal.example", "metadata.example"}, PrivateHosts: []string{"fixture.local"}}
	return &catalogHarness{inst: inst, store: store, conn: conn, grants: grants, registry: registry, clock: clock,
		catalog: application.NewCatalog(store, conn, authz, policy, resolver, grants, clock, log)}
}

func (h *catalogHarness) approved(t *testing.T) domain.Descriptor {
	t.Helper()
	d, _, err := h.catalog.Discover(context.Background(), h.cmd(manager), manager, declaration())
	require.NoError(t, err)
	if d.State == domain.CatalogApproved {
		return d
	}
	d, _, err = h.catalog.Review(context.Background(), h.cmd(reviewer), reviewer, d.ServerID, d.Revision, d.Digest, domain.ReviewApprove, "")
	require.NoError(t, err)
	return d
}

func TestCatalog(t *testing.T) {
	h := newCatalogHarness(t)
	ctx := context.Background()

	t.Run("roles are separated and required", func(t *testing.T) {
		_, err := application.NewAuthorizer([]application.RoleBinding{
			{TenantID: "t", ActorID: "x", Role: application.RoleCatalogReviewer}, {TenantID: "t", ActorID: "x", Role: application.RoleGrantManager},
		})
		require.Error(t, err, "one principal never both reviews and grants")
		_, err = application.NewAuthorizer([]application.RoleBinding{{TenantID: "t", ActorID: "x", Role: "admin"}})
		require.Error(t, err)
		_, _, err = h.catalog.Discover(ctx, h.cmd(member), member, declaration())
		require.ErrorIs(t, err, application.ErrForbidden)
		_, _, err = h.catalog.Discover(ctx, h.cmd(reviewer), reviewer, declaration())
		require.ErrorIs(t, err, application.ErrForbidden, "a reviewer does not discover")
	})

	t.Run("discovery records the live descriptor as a revision awaiting review, idempotently", func(t *testing.T) {
		c := h.cmd(manager)
		d, existing, err := h.catalog.Discover(ctx, c, manager, declaration())
		require.NoError(t, err)
		require.False(t, existing)
		require.Equal(t, domain.CatalogReviewPending, d.State)
		require.Equal(t, uint64(1), d.Revision)
		require.Equal(t, "issues", d.ServerName)
		require.Equal(t, []string{"mcp.issues.example"}, d.NetworkScope, "the resource's own host is always in scope")
		require.Len(t, d.Tools, 2)
		tool, ok := d.Method("create_issue")
		require.True(t, ok)
		require.True(t, tool.SideEffecting)
		require.Regexp(t, `^sha256:[0-9a-f]{64}$`, tool.InputSchemaDigest)
		again, existing, err := h.catalog.Discover(ctx, c, manager, declaration())
		require.NoError(t, err)
		require.True(t, existing)
		require.Equal(t, d.Digest, again.Digest)
		other := c
		other.RequestDigest = domain.DigestBytes([]byte("other"))
		_, _, err = h.catalog.Discover(ctx, other, manager, declaration())
		require.ErrorIs(t, err, domain.ErrCommandConflict)
		same, existing, err := h.catalog.Discover(ctx, h.cmd(manager), manager, declaration())
		require.NoError(t, err)
		require.True(t, existing, "the same live descriptor is the same revision")
		require.Equal(t, uint64(1), same.Revision)
	})

	t.Run("the listing must agree with the live server; unsafe targets are never contacted", func(t *testing.T) {
		calls := h.conn.calls
		for name, mutate := range map[string]func(*domain.Declaration){
			"undeclared live method": func(d *domain.Declaration) { d.Tools = d.Tools[:1] },
			"missing declared method": func(d *domain.Declaration) {
				d.Tools = append(d.Tools, domain.ToolDeclaration{Method: "delete_issue", UnitPrice: domain.Money{Currency: "USD"}})
			},
			"expected digest":     func(d *domain.Declaration) { d.ExpectedDigest = domain.DigestBytes([]byte("x")) },
			"protocol version":    func(d *domain.Declaration) { d.ProtocolVersion = "2025-06-18" },
			"input schema claims": func(d *domain.Declaration) { d.Tools[0].InputSchemaDigest = domain.DigestBytes([]byte("y")) },
		} {
			decl := declaration()
			mutate(&decl)
			_, _, err := h.catalog.Discover(ctx, h.cmd(manager), manager, decl)
			require.ErrorIs(t, err, domain.ErrDescriptorMismatch, name)
		}
		require.Equal(t, calls+5, h.conn.calls)
		calls = h.conn.calls
		for name, resource := range map[string]string{
			"host outside the allowlist": "https://evil.example/mcp",
			"private address":            "https://internal.example/mcp",
			"metadata address":           "https://metadata.example/mcp",
			"plain http":                 "http://mcp.issues.example/mcp",
			"userinfo":                   "https://user:pw@mcp.issues.example/mcp",
			"literal loopback":           "https://127.0.0.1/mcp",
		} {
			decl := declaration()
			decl.CanonicalResource = resource
			_, _, err := h.catalog.Discover(ctx, h.cmd(manager), manager, decl)
			require.Error(t, err, name)
			require.True(t, errors.Is(err, application.ErrForbidden) || errors.Is(err, domain.ErrForbidden) || errors.Is(err, domain.ErrInvalid), "%s: %v", name, err)
		}
		stdio := declaration()
		stdio.Transport = "stdio"
		_, _, err := h.catalog.Discover(ctx, h.cmd(manager), manager, stdio)
		require.ErrorIs(t, err, application.ErrForbidden, "discovery never launches a package")
		require.Equal(t, calls, h.conn.calls, "no unsafe target reached the connection layer")
	})

	t.Run("review binds the exact digest; the discoverer never approves; decisions are published", func(t *testing.T) {
		d, err := h.catalog.Get(ctx, reviewer, idOfServer(t, h), 1)
		require.NoError(t, err)
		_, _, err = h.catalog.Review(ctx, h.cmd(reviewer), reviewer, d.ServerID, 1, domain.DigestBytes([]byte("stale")), domain.ReviewApprove, "")
		require.ErrorIs(t, err, domain.ErrDescriptorMismatch)
		_, _, err = h.catalog.Review(ctx, h.cmd(granter), granter, d.ServerID, 1, d.Digest, domain.ReviewApprove, "")
		require.ErrorIs(t, err, application.ErrForbidden, "a grant manager never reviews")
		// A manager who also reviews is refused on the revision they discovered.
		dual, err := application.NewAuthorizer([]application.RoleBinding{{TenantID: "tenant_a", ActorID: "carol-manager", Role: application.RoleCatalogManager}, {TenantID: "tenant_a", ActorID: "carol-manager", Role: application.RoleCatalogReviewer}})
		require.NoError(t, err)
		self := application.NewCatalog(h.store, h.conn, dual, application.NetworkPolicy{}, fakeResolver{}, h.grants, h.clock, slog.New(slog.NewTextHandler(io.Discard, nil)))
		_, _, err = self.Review(ctx, h.cmd(manager), manager, d.ServerID, 1, d.Digest, domain.ReviewApprove, "")
		require.ErrorIs(t, err, domain.ErrForbidden, "four eyes")

		approved, _, err := h.catalog.Review(ctx, h.cmd(reviewer), reviewer, d.ServerID, 1, d.Digest, domain.ReviewApprove, "reviewed")
		require.NoError(t, err)
		require.Equal(t, domain.CatalogApproved, approved.State)
		require.Equal(t, "rita-reviewer", approved.Reviewer)
		_, _, err = h.catalog.Review(ctx, h.cmd(reviewer), reviewer, d.ServerID, 1, d.Digest, domain.ReviewReject, "")
		require.ErrorIs(t, err, domain.ErrInvalidTransition)
		require.Equal(t, 1, countEvents(t, h.inst, "mcp.catalog-reviewed"))
	})

	t.Run("a changed server is a new revision awaiting review; the approved one is unchanged", func(t *testing.T) {
		h.conn.set(issuesURL, liveIssues(`,"required":["query"]`))
		d, existing, err := h.catalog.Discover(ctx, h.cmd(manager), manager, declaration())
		require.NoError(t, err)
		require.False(t, existing)
		require.Equal(t, uint64(2), d.Revision)
		require.Equal(t, domain.CatalogReviewPending, d.State)
		first, err := h.catalog.Get(ctx, member, d.ServerID, 1)
		require.NoError(t, err)
		require.Equal(t, domain.CatalogApproved, first.State)
		require.NotEqual(t, first.Digest, d.Digest)
	})

	t.Run("visibility: members see approved revisions of their tenant only", func(t *testing.T) {
		id := idOfServer(t, h)
		_, err := h.catalog.Get(ctx, member, id, 2)
		require.ErrorIs(t, err, domain.ErrNotFound, "a revision awaiting review is visible to the catalog roles only")
		_, err = h.catalog.Get(ctx, reviewer, id, 2)
		require.NoError(t, err)
		_, err = h.catalog.Get(ctx, outsider, id, 1)
		require.ErrorIs(t, err, domain.ErrNotFound)
		page, _, err := h.catalog.List(ctx, member, "", "", 50)
		require.NoError(t, err)
		require.Len(t, page, 1)
		page, _, err = h.catalog.List(ctx, reviewer, "", "", 50)
		require.NoError(t, err)
		require.Len(t, page, 2)
		page, _, err = h.catalog.List(ctx, outsider, "", "", 50)
		require.NoError(t, err)
		require.Empty(t, page)
	})
}

func idOfServer(t *testing.T, h *catalogHarness) string {
	t.Helper()
	var id string
	require.NoError(t, h.inst.Pool(t).QueryRow(context.Background(), "SELECT server_id FROM servers WHERE canonical_resource = $1", issuesURL).Scan(&id))
	return id
}

func countEvents(t *testing.T, inst *testdb.Instance, eventType string) int {
	t.Helper()
	var n int
	require.NoError(t, inst.Pool(t).QueryRow(context.Background(), "SELECT count(*) FROM outbox WHERE payload::text LIKE '%' || $1 || '%'", eventType).Scan(&n))
	return n
}
