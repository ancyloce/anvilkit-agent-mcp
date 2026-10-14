package upstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// TestDiscoveryOfAProtectedServer (P2.5 AC3): a server that answers 401 to
// initialize and tools/list without a token is discovered through MCP's own
// egress with the reviewed credential; every Authorization header the
// fixture saw is a token the authorization server issued for that resource
// (an inbound AnvilKit credential never reaches it), and without a reviewed
// credential nothing is sent to the MCP endpoint at all.
func TestDiscoveryOfAProtectedServer(t *testing.T) {
	ctx := context.Background()
	as := newAuthServer(t)
	issuer := as.srv.URL
	as.meta.Store(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
		"response_types_supported": []string{"code"}, "code_challenge_methods_supported": []string{"S256"}})

	server := mcp.NewServer(&mcp.Implementation{Name: "protected-fixture", Version: "3.1"}, nil)
	server.AddTool(&mcp.Tool{Name: "search_issues", InputSchema: searchSchema, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{}, nil
		})
	server.AddResource(&mcp.Resource{Name: "board", URI: "issues://board"}, func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{}, nil
	})
	// The fixture is reached under a reviewed name (mcp.test) on a loopback
	// listener; the SDK's own localhost DNS-rebinding guard is the fixture's,
	// not what is tested here.
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{DisableLocalhostProtection: true})
	var mu sync.Mutex
	var seen []string
	var mcpRequests, unauthorized int
	var resource string
	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") {
			_ = json.NewEncoder(w).Encode(map[string]any{"resource": resource, "authorization_servers": []string{issuer}})
			return
		}
		mu.Lock()
		mcpRequests++
		got := r.Header.Get("Authorization")
		seen = append(seen, got)
		if !strings.HasPrefix(got, "Bearer tok-mcp-discovery-") {
			unauthorized++
			mu.Unlock()
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+resource+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	defer rs.Close()
	resource = hostURL(t, rs, "mcp.test", "/mcp")
	guard := Guard{Policy: application.NetworkPolicy{PrivateHosts: []string{"mcp.test", "127.0.0.1"}}, Resolver: resolver(map[string][][]netip.Addr{"mcp.test": {{loop()}}})}
	client := guard.Client(1<<20, 10*time.Second)
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("s3cret\n"), 0o600))

	t.Run("without a reviewed credential nothing reaches the MCP endpoint", func(t *testing.T) {
		d := NewDiscoverer(client, NewAuthority(guard, client, nil, time.Now), "test", time.Now)
		_, err := d.Discover(ctx, resource, "2025-11-25")
		require.ErrorIs(t, err, application.ErrForbidden)
		mu.Lock()
		defer mu.Unlock()
		require.Zero(t, mcpRequests)
	})

	t.Run("the reviewed credential discovers the protected server", func(t *testing.T) {
		auth := NewAuthority(guard, client, []Credential{{Resource: resource, Issuer: issuer, ClientID: "mcp-discovery", ClientSecretFile: secret}}, time.Now)
		require.True(t, auth.HasCredential(resource))
		live, err := NewDiscoverer(client, auth, "test", time.Now).Discover(ctx, resource, "2025-11-25")
		require.NoError(t, err)
		require.Equal(t, "protected-fixture", live.Name)
		require.Equal(t, "3.1", live.Version)
		require.Equal(t, "2025-11-25", live.ProtocolVersion)
		require.Equal(t, issuer, live.Issuer)
		require.Len(t, live.Tools, 1)
		require.Equal(t, []domain.LiveNamed{{Name: "board", URI: "issues://board"}}, live.Resources)
		// The descriptor built from this read is what the call-time lock compares.
		desc, err := domain.BuildDescriptor(domain.Declaration{CanonicalResource: resource, Transport: "streamable-http", ProtocolVersion: "2025-11-25", DataClass: "internal",
			Tools: []domain.ToolDeclaration{{Method: "search_issues", UnitPrice: domain.Money{Currency: "USD"}}}}, live)
		require.NoError(t, err)
		readOnly, err := domain.AnnotationsDigest(json.RawMessage(`{"readOnlyHint":true}`))
		require.NoError(t, err)
		require.Equal(t, readOnly, desc.Tools[0].AnnotationsDigest)
		mu.Lock()
		defer mu.Unlock()
		require.NotZero(t, mcpRequests)
		require.Zero(t, unauthorized, "every MCP request carried the issued token (initialize and tools/list included)")
		for _, h := range seen {
			require.True(t, strings.HasPrefix(h, "Bearer tok-mcp-discovery-"), "only the token issued for this resource reaches it, got %q", h)
		}
		v, _ := as.resources.Load("1")
		require.Equal(t, resource, v, "the token request names the resource (RFC 8707)")
	})
}
