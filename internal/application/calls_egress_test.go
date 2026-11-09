package application_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/upstream"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// callTimeResolver is what each host resolves to when the call's hop is
// dialed; a test changes it after discovery (DNS rebinding).
type callTimeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
}

func (r *callTimeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.answers[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("no such host %s", host)
}

func (r *callTimeResolver) set(host string, addrs ...netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[host] = addrs
}

// SEC-07 (security.md) at the application level (RB-A07): a granted call goes
// through Calls with MCP's real egress, the guarded client and the go-sdk
// route, not a fake upstream. When the call's hop is refused by the guard
// (the resource rebinding to a metadata address after discovery, a public
// host resolving to a private address, a redirect), the call is canceled
// EGRESS_REFUSED with its permission returned to Control as canceled and no
// usage, no tools/call reaches any server, and the refusal is counted by
// reason (RB-A26).
func TestCallsRefuseUnsafeEgressBeforeSending(t *testing.T) {
	h := newCatalogHarness(t)
	ctx := context.Background()

	// Server B: a DEVELOPMENT_ONLY private host (the harness allows
	// fixture.local) whose endpoint redirects every request elsewhere.
	var fixtureHits, fixtureToolCalls atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixtureHits.Add(1)
		var msg struct {
			Method string `json:"method"`
		}
		if body, err := io.ReadAll(r.Body); err == nil && json.Unmarshal(body, &msg) == nil && msg.Method == "tools/call" {
			fixtureToolCalls.Add(1)
		}
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer fixture.Close()
	fu, err := url.Parse(fixture.URL)
	require.NoError(t, err)
	redirecting := "http://" + net.JoinHostPort("fixture.local", fu.Port()) + "/mcp"
	h.conn.set(redirecting, liveIssues(""))

	approve := func(decl domain.Declaration) domain.Descriptor {
		d, _, err := h.catalog.Discover(ctx, h.cmd(manager), manager, decl)
		require.NoError(t, err)
		if d.State != domain.CatalogApproved {
			d, _, err = h.catalog.Review(ctx, h.cmd(reviewer), reviewer, d.ServerID, d.Revision, d.Digest, domain.ReviewApprove, "")
			require.NoError(t, err)
		}
		return d
	}
	grant := func(d domain.Descriptor) domain.Grant {
		g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, grantRequest(d))
		require.NoError(t, err)
		require.Equal(t, domain.GrantActive, g.State)
		return g
	}
	public := grant(approve(declaration()))
	declB := declaration()
	declB.CanonicalResource = redirecting
	private := grant(approve(declB))

	// The call-time view of the network: discovery saw mcp.issues.example at
	// a public address (the harness resolver); the guard sees what is set here.
	resolve := &callTimeResolver{answers: map[string][]netip.Addr{"fixture.local": {netip.MustParseAddr("127.0.0.1")}}}
	metrics := application.NewMetrics(prometheus.NewRegistry())
	guard := upstream.Guard{
		Policy:   application.NetworkPolicy{AllowedHosts: []string{".issues.example"}, PrivateHosts: []string{"fixture.local"}},
		Resolver: resolve, Refusals: metrics.EgressRefusals,
	}
	route := upstream.NewRoute(guard.Client(1<<20, 5*time.Second), "test", 1<<20).CountRefusals(metrics.EgressRefusals)
	disp := newFakeToolDispatch()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	calls := application.NewCalls(h.store, disp, map[string]application.Upstream{upstream.SDKRoute: route}, &fakeTokens{},
		[]application.QualifiedRoute{
			{Resource: issuesURL, ProtocolVersion: protocol, Transport: "streamable-http", Route: upstream.SDKRoute},
			{Resource: redirecting, ProtocolVersion: protocol, Transport: "streamable-http", Route: upstream.SDKRoute},
		},
		application.CallOptions{SendTimeout: 5 * time.Second, Wait: 5 * time.Second, ReconcileAge: 0, ReconcileBatch: 50}, h.clock, metrics, log)

	refusals := func(reason string) float64 { return metricValue(t, metrics.EgressRefusals.WithLabelValues(reason)) }
	allRefusals := func() float64 {
		sum := 0.0
		for _, r := range application.EgressRefusalReasons {
			sum += refusals(r)
		}
		return sum
	}
	canceled := func() float64 { return metricValue(t, metrics.CallTransitions.WithLabelValues("canceled")) }
	n := 0
	call := func(g domain.Grant) domain.Call {
		t.Helper()
		n++
		args := fmt.Sprintf(`{"query":"egress-%d"}`, n)
		r := domain.CallRequest{GrantID: g.GrantID, GrantRevision: g.Revision, Method: "search_issues", ArgumentRef: "inline",
			ArgumentDigest: domain.DigestBytes([]byte(args)), Arguments: []byte(args), OperationID: "op_egress", AttemptID: "att_egress",
			InstanceID: "inst_egress", ExecutionEpoch: 1, Deadline: time.Now().Add(time.Hour)}
		got, _, err := calls.Create(ctx, h.cmd(agent), agent, r)
		require.NoError(t, err)
		return got
	}
	refused := func(t *testing.T, g domain.Grant, reason string) {
		t.Helper()
		before, beforeAll, beforeCanceled := refusals(reason), allRefusals(), canceled()
		got := call(g)
		require.Equal(t, domain.CallCanceled, got.State)
		require.Equal(t, domain.CallEgressRefused, got.FailureCode)
		require.Equal(t, []string{application.OutcomeCanceled}, disp.observed[got.DispatchID], "the permission is returned unused")
		require.Equal(t, uint64(0), *disp.units[got.DispatchID])
		require.Len(t, disp.admits[got.CallID], 1, "admitted once, never re-admitted")
		// Each refused hop counts once; the SDK may try more than one hop of a
		// session (server/discover, then initialize), each refused alike.
		require.Greater(t, refusals(reason), before, "the %s refusal is counted", reason)
		require.Equal(t, refusals(reason)-before, allRefusals()-beforeAll, "no other reason counted")
		require.Equal(t, beforeCanceled+1, canceled())
	}

	t.Run("the resource rebinding to a metadata address after discovery", func(t *testing.T) {
		resolve.set("mcp.issues.example", netip.MustParseAddr("169.254.169.254"))
		refused(t, public, application.EgressAddress)
	})
	t.Run("an IPv4-mapped metadata address", func(t *testing.T) {
		resolve.set("mcp.issues.example", netip.MustParseAddr("::ffff:169.254.169.254"))
		refused(t, public, application.EgressAddress)
	})
	t.Run("a reviewed public host resolving to a private address", func(t *testing.T) {
		resolve.set("mcp.issues.example", netip.MustParseAddr("10.0.0.5"))
		refused(t, public, application.EgressAddress)
	})
	t.Run("a host that no longer resolves", func(t *testing.T) {
		resolve.set("mcp.issues.example")
		refused(t, public, application.EgressUnresolved)
	})
	t.Run("a redirect from the reviewed endpoint is never followed", func(t *testing.T) {
		before := fixtureHits.Load()
		refused(t, private, application.EgressRedirect)
		require.Greater(t, fixtureHits.Load(), before, "the session's opening requests reached the reviewed endpoint")
		require.Zero(t, fixtureToolCalls.Load(), "no tools/call was sent; the redirect target was never requested")
	})
}
