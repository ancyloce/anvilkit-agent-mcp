package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

// scopeServer is an authorization server whose token responses carry the
// scope member a case sets (or none), beside a protected resource naming it.
type scopeServer struct {
	issuer, resource string
	tokens           atomic.Int32
	mu               sync.Mutex
	member           any  // the token response's scope member
	present          bool // whether the member is sent at all
	requested        string
}

func (s *scopeServer) respond(member any, present bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.member, s.present = member, present
}

func (s *scopeServer) lastRequested() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requested
}

func newScopeServer(t *testing.T) *scopeServer {
	s := &scopeServer{}
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": s.issuer, "authorization_endpoint": s.issuer + "/authorize", "token_endpoint": s.issuer + "/token",
				"jwks_uri": s.issuer + "/jwks", "response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}})
		case "/token":
			require.NoError(t, r.ParseForm())
			n := s.tokens.Add(1)
			body := map[string]any{"access_token": fmt.Sprintf("tok-%d", n), "token_type": "Bearer", "expires_in": 3600}
			s.mu.Lock()
			s.requested = r.Form.Get("scope")
			if s.present {
				body["scope"] = s.member
			}
			s.mu.Unlock()
			_ = json.NewEncoder(w).Encode(body)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(as.Close)
	// The SDK's metadata fetch requires https or a loopback address: the
	// issuer is the loopback literal.
	s.issuer = as.URL
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") {
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": s.resource, "authorization_servers": []string{s.issuer}})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(rs.Close)
	s.resource = hostURL(t, rs, "mcp.test", "/mcp")
	return s
}

// RB-S03: the scope an authorization server grants is compared with the
// reviewed credential's request before the token is cached or used.
func TestTokenScopeStaysWithinTheReviewedCredential(t *testing.T) {
	ctx := context.Background()
	s := newScopeServer(t)
	guard := Guard{Policy: application.NetworkPolicy{PrivateHosts: []string{"mcp.test", "127.0.0.1"}},
		Resolver: resolver(map[string][][]netip.Addr{"mcp.test": {{loop()}}})}
	client := guard.Client(1<<20, 5*time.Second)
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("s3cret\n"), 0o600))
	credential := func(scopes ...string) []Credential {
		return []Credential{{Resource: s.resource, Issuer: s.issuer, ClientID: "mcp-a", ClientSecretFile: secret, Scopes: scopes}}
	}
	auth := NewAuthority(guard, client, credential("tools.read", "tools.call"), time.Now)
	seq := 0
	grant := func() domain.Grant {
		seq++
		return domain.Grant{GrantID: fmt.Sprintf("g-%d", seq), Revision: 1, TenantID: "tenant_a", ServerID: "srv",
			CanonicalResource: s.resource, Issuer: s.issuer, Audience: s.resource, Methods: []string{"m"}}
	}

	for _, c := range []struct {
		name    string
		member  any
		present bool
	}{
		{"omitted: the requested scope (RFC 6749 §5.1)", nil, false},
		{"equal", "tools.read tools.call", true},
		{"reordered with extra spaces", "tools.call  tools.read", true},
		{"narrower", "tools.read", true},
		{"empty", "", true},
	} {
		t.Run("accepted: "+c.name, func(t *testing.T) {
			s.respond(c.member, c.present)
			g := grant()
			before := s.tokens.Load()
			tok, err := auth.Token(ctx, g)
			require.NoError(t, err)
			require.NotEmpty(t, tok)
			require.Equal(t, "tools.read tools.call", s.lastRequested(), "the request names the reviewed scopes")
			again, err := auth.Token(ctx, g)
			require.NoError(t, err)
			require.Equal(t, tok, again)
			require.Equal(t, before+1, s.tokens.Load(), "the accepted token is cached")
		})
	}

	for _, c := range []struct {
		name   string
		member any
	}{
		{"wider", "tools.read tools.call tools.admin"},
		{"another scope", "tools.admin"},
		{"not a string", []string{"tools.read"}},
	} {
		t.Run("refused: "+c.name, func(t *testing.T) {
			s.respond(c.member, true)
			g := grant()
			before := s.tokens.Load()
			tok, err := auth.Token(ctx, g)
			require.ErrorIs(t, err, ErrAuthority)
			require.Empty(t, tok)
			require.NotContains(t, err.Error(), "tools.admin", "the granted scopes are upstream text and never quoted")
			_, err = auth.Token(ctx, g)
			require.ErrorIs(t, err, ErrAuthority)
			require.Equal(t, before+2, s.tokens.Load(), "a refused token is never cached")
		})
	}

	t.Run("refused: a wider discovery token", func(t *testing.T) {
		s.respond("tools.read tools.admin", true)
		tok, _, err := auth.DiscoveryToken(ctx, s.resource)
		require.ErrorIs(t, err, ErrAuthority)
		require.Empty(t, tok)
	})

	t.Run("refused: a default scope beyond a credential that requests none", func(t *testing.T) {
		none := NewAuthority(guard, client, credential(), time.Now)
		s.respond("tools.read", true)
		_, err := none.Token(ctx, grant())
		require.ErrorIs(t, err, ErrAuthority)
		require.Empty(t, s.lastRequested(), "no scope was requested")
		s.respond(nil, false)
		tok, err := none.Token(ctx, grant())
		require.NoError(t, err)
		require.NotEmpty(t, tok)
	})
}
