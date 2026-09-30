package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// fakeResolver answers per host; a host's answers may change between
// lookups (DNS rebinding).
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	calls   map[string]int
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seq, ok := r.answers[host]
	if !ok {
		return nil, fmt.Errorf("no such host %s", host)
	}
	i := r.calls[host]
	r.calls[host]++
	if i >= len(seq) {
		i = len(seq) - 1
	}
	return seq[i], nil
}

func loop() netip.Addr { return netip.MustParseAddr("127.0.0.1") }

func resolver(m map[string][][]netip.Addr) *fakeResolver {
	return &fakeResolver{answers: m, calls: map[string]int{}}
}

// hostURL rewrites a test server URL to name host instead of 127.0.0.1.
func hostURL(t *testing.T, srv *httptest.Server, host, path string) string {
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return "http://" + net.JoinHostPort(host, u.Port()) + path
}

func TestEgress(t *testing.T) {
	var hits atomic.Int32
	var lastAuth atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		lastAuth.Store(r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
		case "/redirect":
			http.Redirect(w, r, "http://other.test/steal", http.StatusFound)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer target.Close()
	ctx := context.Background()
	policy := application.NetworkPolicy{PrivateHosts: []string{"mcp.test", "other.test", "rebind.test", "meta.test", "127.0.0.1"}}

	t.Run("only checked addresses are dialed; rebinding and metadata addresses are refused", func(t *testing.T) {
		r := resolver(map[string][][]netip.Addr{
			"mcp.test":    {{loop()}},
			"rebind.test": {{loop()}, {netip.MustParseAddr("169.254.169.254")}},
			"meta.test":   {{netip.MustParseAddr("::ffff:169.254.169.254")}},
		})
		c := Guard{Policy: policy, Resolver: r}.Client(1024, 5*time.Second)
		resp, err := c.Get(hostURL(t, target, "mcp.test", "/"))
		require.NoError(t, err)
		resp.Body.Close()
		require.NoError(t, application.NetworkPolicy{PrivateHosts: policy.PrivateHosts}.CheckTarget(ctx, r, hostURL(t, target, "rebind.test", "/mcp")), "the first answer passes the discovery check")
		before := hits.Load()
		_, err = c.Get(hostURL(t, target, "rebind.test", "/"))
		require.ErrorIs(t, err, ErrEgress, "the connection-time answer is checked again and refused")
		_, err = c.Get(hostURL(t, target, "meta.test", "/"))
		require.ErrorIs(t, err, ErrEgress, "an IPv4-mapped metadata address is refused")
		_, err = c.Get("http://[::ffff:a9fe:a9fe]:80/")
		require.ErrorIs(t, err, ErrEgress, "a literal metadata address is refused")
		require.Equal(t, before, hits.Load(), "nothing reached a refused host")
	})

	t.Run("public hosts need https and public addresses; unreviewed hosts are never contacted", func(t *testing.T) {
		r := resolver(map[string][][]netip.Addr{"api.example": {{netip.MustParseAddr("10.0.0.7")}}, "other.example": {{netip.MustParseAddr("203.0.113.9")}}})
		c := Guard{Policy: application.NetworkPolicy{AllowedHosts: []string{"api.example"}}, Resolver: r}.Client(1024, time.Second)
		_, err := c.Get("http://api.example/")
		require.ErrorIs(t, err, ErrEgress, "http to a public host")
		_, err = c.Get("https://api.example/")
		require.ErrorIs(t, err, ErrEgress, "a reviewed public host that resolves privately")
		_, err = c.Get("https://other.example/")
		require.ErrorIs(t, err, ErrEgress, "an unreviewed host")
		_, err = c.Get("https://user:pw@api.example/")
		require.ErrorIs(t, err, ErrEgress)
	})

	t.Run("redirects are refused, bearer tokens stay on their origin, bodies are bounded", func(t *testing.T) {
		r := resolver(map[string][][]netip.Addr{"mcp.test": {{loop()}}, "other.test": {{loop()}}})
		base := Guard{Policy: policy, Resolver: r}.Client(1024, 5*time.Second)
		origin := strings.TrimSuffix(hostURL(t, target, "mcp.test", ""), "/")
		c := WithBearer(base, origin, "upstream-token")
		before := hits.Load()
		_, err := c.Get(hostURL(t, target, "mcp.test", "/redirect"))
		require.ErrorIs(t, err, ErrEgress)
		require.Equal(t, before+1, hits.Load(), "the redirect target was never requested")
		require.Equal(t, "Bearer upstream-token", lastAuth.Load())
		req, _ := http.NewRequest(http.MethodGet, hostURL(t, target, "other.test", "/"), nil)
		req.Header.Set("Authorization", "Bearer inbound-anvilkit-token")
		resp, err := c.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, "", lastAuth.Load(), "another origin gets no token, and a caller's header is dropped")
		resp, err = c.Get(hostURL(t, target, "mcp.test", "/big"))
		require.NoError(t, err)
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		require.ErrorIs(t, err, ErrBodyTooLarge)
	})
}

// authServer is an authorization server fixture: its metadata can be
// substituted per test.
type authServer struct {
	srv       *httptest.Server
	meta      atomic.Value // map[string]any
	tokens    atomic.Int32
	resources sync.Map
}

func newAuthServer(t *testing.T) *authServer {
	a := &authServer{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(a.meta.Load())
		case "/token":
			require.NoError(t, r.ParseForm())
			id, secret, _ := r.BasicAuth()
			if secret != "s3cret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			n := a.tokens.Add(1)
			a.resources.Store(fmt.Sprint(n), r.Form.Get("resource"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": fmt.Sprintf("tok-%s-%d", id, n), "token_type": "Bearer", "expires_in": 3600})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func TestAuthority(t *testing.T) {
	ctx := context.Background()
	as := newAuthServer(t)
	// The SDK's metadata fetch itself also requires https or a loopback
	// address, so the dev issuer is a loopback literal.
	issuer := as.srv.URL
	var prm atomic.Value
	var resourceHits atomic.Int32
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resourceHits.Add(1)
		if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") {
			if v := prm.Load(); v != nil {
				_ = json.NewEncoder(w).Encode(v)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer rs.Close()
	resource := hostURL(t, rs, "mcp.test", "/mcp")
	r := resolver(map[string][][]netip.Addr{"mcp.test": {{loop()}}, "as.test": {{loop()}}, "meta.test": {{netip.MustParseAddr("169.254.169.254")}}})
	guard := Guard{Policy: application.NetworkPolicy{PrivateHosts: []string{"mcp.test", "127.0.0.1", "meta.test"}}, Resolver: r}
	client := guard.Client(1<<20, 5*time.Second)
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("s3cret\n"), 0o600))
	auth := NewAuthority(guard, client, []Credential{{Resource: resource, Issuer: issuer, ClientID: "mcp-a", ClientSecretFile: secret}}, time.Now)
	goodMeta := map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
		"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}}
	grant := func(tenant string) domain.Grant {
		return domain.Grant{GrantID: "g-" + tenant, Revision: 1, TenantID: tenant, ServerID: "srv", CanonicalResource: resource, Issuer: issuer, Audience: resource, Methods: []string{"m"}}
	}

	t.Run("an unprotected server has no issuer and needs no token", func(t *testing.T) {
		got, err := auth.Issuer(ctx, resource)
		require.NoError(t, err)
		require.Empty(t, got)
		tok, err := auth.Token(ctx, domain.Grant{CanonicalResource: resource})
		require.NoError(t, err)
		require.Empty(t, tok)
	})

	t.Run("tokens are bound to the resource and cached per grant security dimensions", func(t *testing.T) {
		prm.Store(map[string]any{"resource": resource, "authorization_servers": []string{issuer}})
		as.meta.Store(goodMeta)
		got, err := auth.Issuer(ctx, resource)
		require.NoError(t, err)
		require.Equal(t, issuer, got)
		a1, err := auth.Token(ctx, grant("tenant_a"))
		require.NoError(t, err)
		a2, err := auth.Token(ctx, grant("tenant_a"))
		require.NoError(t, err)
		require.Equal(t, a1, a2)
		b, err := auth.Token(ctx, grant("tenant_b"))
		require.NoError(t, err)
		require.NotEqual(t, a1, b, "another tenant's grant never reuses a cached token")
		require.Equal(t, int32(2), as.tokens.Load())
		v, _ := as.resources.Load("1")
		require.Equal(t, resource, v, "the token request names the resource (RFC 8707)")
	})

	t.Run("substituted metadata is refused before any token request", func(t *testing.T) {
		before := as.tokens.Load()
		prm.Store(map[string]any{"resource": "https://evil.example/mcp", "authorization_servers": []string{issuer}})
		_, err := auth.Token(ctx, grant("tenant_c"))
		require.ErrorIs(t, err, ErrAuthority, "protected resource metadata for another resource")
		prm.Store(map[string]any{"resource": resource, "authorization_servers": []string{"http://meta.test/"}})
		_, err = auth.Token(ctx, grant("tenant_c"))
		require.ErrorIs(t, err, ErrAuthority, "an authorization server at a metadata address")
		prm.Store(map[string]any{"resource": resource, "authorization_servers": []string{issuer}})
		for name, meta := range map[string]map[string]any{
			"another issuer":           {"issuer": "https://evil.example", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}},
			"token endpoint substitut": {"issuer": issuer, "token_endpoint": "http://meta.test/token", "jwks_uri": issuer + "/jwks", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}},
			"jwks substitution":        {"issuer": issuer, "token_endpoint": issuer + "/token", "jwks_uri": "https://unreviewed.example/jwks", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}},
		} {
			as.meta.Store(meta)
			_, err := auth.Token(ctx, grant("tenant_c"))
			require.ErrorIs(t, err, ErrAuthority, name)
		}
		require.Equal(t, before, as.tokens.Load(), "no token was requested under substituted metadata")
		as.meta.Store(goodMeta)
		_, err = auth.Token(ctx, domain.Grant{GrantID: "g-x", TenantID: "tenant_c", CanonicalResource: resource, Issuer: "http://127.0.0.1:1"})
		require.True(t, errors.Is(err, ErrAuthority), "a grant whose issuer the resource no longer names")
	})
}
