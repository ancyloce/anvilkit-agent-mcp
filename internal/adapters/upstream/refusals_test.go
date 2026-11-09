package upstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
)

// refusalCounts reads every reason's value of anvilkit_mcp_egress_refusals_total
// (zeros left out).
func refusalCounts(t *testing.T, c *prometheus.CounterVec) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, r := range application.EgressRefusalReasons {
		var m dto.Metric
		require.NoError(t, c.WithLabelValues(r).Write(&m))
		if v := m.GetCounter().GetValue(); v != 0 {
			out[r] = v
		}
	}
	return out
}

// RB-A26: every hop MCP's egress refuses (the guard of discovery,
// authorization and tool calls, the authorization metadata check and the
// route's network scope) is counted once under a fixed reason, before
// anything is sent; no host or address becomes a label value.
func TestEgressRefusalsAreCountedByReason(t *testing.T) {
	ctx := context.Background()
	reg := prometheus.NewRegistry()
	counter := application.NewMetrics(reg).EgressRefusals

	families, err := reg.Gather()
	require.NoError(t, err)
	var series []string
	for _, f := range families {
		if f.GetName() == "anvilkit_mcp_egress_refusals_total" {
			for _, m := range f.GetMetric() {
				require.Len(t, m.GetLabel(), 1)
				require.Equal(t, "reason", m.GetLabel()[0].GetName())
				require.Zero(t, m.GetCounter().GetValue())
				series = append(series, m.GetLabel()[0].GetValue())
			}
		}
	}
	require.ElementsMatch(t, application.EgressRefusalReasons, series, "every reason's series exists at 0 before any refusal")

	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://other.test/steal", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	r := resolver(map[string][][]netip.Addr{
		"mcp.test":    {{loop()}},
		"rebind.test": {{netip.MustParseAddr("169.254.169.254")}},
		"other.test":  {{loop()}},
		"api.example": {{netip.MustParseAddr("203.0.113.9")}},
	})
	guard := Guard{Policy: application.NetworkPolicy{
		PrivateHosts: []string{"mcp.test", "rebind.test", "other.test", "nowhere.test"},
		AllowedHosts: []string{"api.example"},
	}, Resolver: r, Refusals: counter}
	client := guard.Client(1024, 5*time.Second)

	expect := map[string]float64{}
	step := func(t *testing.T, reason string, run func() error) {
		t.Helper()
		before := hits.Load()
		err := run()
		require.Error(t, err)
		expect[reason]++
		require.Equal(t, expect, refusalCounts(t, counter), "exactly one %s refusal counted", reason)
		if reason != application.EgressRedirect {
			require.Equal(t, before, hits.Load(), "nothing reached the target")
		}
	}

	t.Run("the guard's hop refusals", func(t *testing.T) {
		get := func(url string) func() error {
			return func() error {
				resp, err := client.Get(url)
				if err == nil {
					resp.Body.Close()
				}
				return err
			}
		}
		step(t, application.EgressHostNotAllowed, get("https://unreviewed.example/"))
		step(t, application.EgressScheme, get("http://api.example/"))
		step(t, application.EgressUserinfo, get("https://user:pw@api.example/"))
		step(t, application.EgressUnresolved, get(hostURL(t, target, "nowhere.test", "/")))
		step(t, application.EgressAddress, get(hostURL(t, target, "rebind.test", "/")))
		// A metadata literal is no reviewed host: the host rule refuses it first.
		step(t, application.EgressHostNotAllowed, get("http://[::ffff:a9fe:a9fe]:80/"))
		step(t, application.EgressRedirect, get(hostURL(t, target, "mcp.test", "/redirect")))
		step(t, application.EgressMalformed, func() error {
			_, err := guard.DialContext(ctx, "tcp", "no-port")
			return err
		})
		resp, err := client.Get(hostURL(t, target, "mcp.test", "/"))
		require.NoError(t, err, "an allowed hop is not refused")
		resp.Body.Close()
		require.Equal(t, expect, refusalCounts(t, counter), "an allowed hop counts nothing")
	})

	t.Run("metadata-named authorization endpoints", func(t *testing.T) {
		a := NewAuthority(guard, client, nil, time.Now)
		check := func(url string) func() error { return func() error { return a.checkURL(ctx, url) } }
		step(t, application.EgressAddress, check("http://rebind.test/token"))
		step(t, application.EgressHostNotAllowed, check("https://unreviewed.example/jwks"))
		step(t, application.EgressScheme, check("http://api.example/token"))
		step(t, application.EgressUserinfo, check("https://user@api.example/token"))
		step(t, application.EgressMalformed, check("https:///token"))
		step(t, application.EgressUnresolved, check("http://nowhere.test/token"))
		require.NoError(t, a.checkURL(ctx, "https://api.example/token"), "an allowed endpoint is not refused")
	})

	t.Run("the route's network scope", func(t *testing.T) {
		route := NewRoute(client, "test", 1<<20).CountRefusals(counter)
		open := func(resource string, scope ...string) func() error {
			return func() error {
				_, err := route.Open(ctx, application.UpstreamTarget{Resource: resource, ProtocolVersion: "2025-11-25", NetworkScope: scope})
				return err
			}
		}
		step(t, application.EgressOutOfScope, open(hostURL(t, target, "mcp.test", "/mcp"), "other.test"))
		step(t, application.EgressMalformed, open("http://[::1/mcp"))
		hop := &scoped{base: http.DefaultTransport, scope: []string{"mcp.test"}, refusals: counter}
		step(t, application.EgressOutOfScope, func() error {
			req, err := http.NewRequest(http.MethodGet, hostURL(t, target, "other.test", "/"), nil)
			require.NoError(t, err)
			resp, err := hop.RoundTrip(req)
			if err == nil {
				resp.Body.Close()
			}
			return err
		})
	})
}
