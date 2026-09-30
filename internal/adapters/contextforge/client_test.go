package contextforge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A ContextForge double with the v1 routes discovery uses.
type double struct {
	mu        sync.Mutex
	gateways  []map[string]any
	refreshes int
	auth      []string
	upstream  int // status of handshake/registration (0: ok)
}

func (d *double) handler() http.Handler {
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("POST /v1/mcp-servers/test-handshake", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if len(d.gateways) == 0 || body["baseUrl"] != d.gateways[0]["url"] {
			write(w, 200, map[string]any{"success": false, "error": "The MCP server URL is not allowed for testing."})
			return
		}
		if d.upstream != 0 {
			write(w, d.upstream, map[string]any{"message": "Failed to initialize"})
			return
		}
		write(w, 200, map[string]any{"success": true, "negotiationPath": "discover", "protocolVersion": "2026-07-28", "serverName": "issues", "serverVersion": "1.4.0"})
	})
	mux.HandleFunc("GET /v1/gateways", func(w http.ResponseWriter, r *http.Request) { write(w, 200, d.gateways) })
	mux.HandleFunc("POST /v1/gateways", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["transport"] != "STREAMABLEHTTP" || body["visibility"] != "private" {
			write(w, 400, map[string]any{"message": "bad request"})
			return
		}
		g := map[string]any{"id": "gw-1", "name": body["name"], "url": body["url"]}
		d.gateways = append(d.gateways, g)
		write(w, 200, g)
	})
	mux.HandleFunc("POST /v1/gateways/{id}/tools/refresh", func(w http.ResponseWriter, r *http.Request) {
		d.refreshes++
		write(w, 200, map[string]any{})
	})
	mux.HandleFunc("GET /v1/tools", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, []map[string]any{
			{"originalName": "search_issues", "gatewayId": "gw-1", "enabled": true, "inputSchema": map[string]any{"type": "object"}},
			{"originalName": "disabled_tool", "gatewayId": "gw-1", "enabled": false},
			{"originalName": "foreign_tool", "gatewayId": "gw-2", "enabled": true},
		})
	})
	mux.HandleFunc("GET /v1/resources", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, []map[string]any{{"name": "open-issues", "uri": "issues://open", "gatewayId": "gw-1"}})
	})
	mux.HandleFunc("GET /v1/prompts", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, []map[string]any{{"name": "gw-1-triage", "originalName": "triage", "gatewayId": "gw-1"}})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.auth = append(d.auth, r.Header.Get("Authorization"))
		mux.ServeHTTP(w, r)
	})
}

func TestDiscover(t *testing.T) {
	d := &double{}
	srv := httptest.NewServer(d.handler())
	defer srv.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("tok-1\n"), 0o600))
	c := New(srv.URL, tokenFile, 5*time.Second)
	ctx := context.Background()

	live, err := c.Discover(ctx, "https://mcp.issues.example/mcp")
	require.NoError(t, err)
	require.Equal(t, "2026-07-28", live.ProtocolVersion)
	require.Equal(t, "contextforge:gw-1", live.ConnectionRef)
	require.Len(t, live.Tools, 1, "only the gateway's own enabled tools")
	require.Equal(t, "search_issues", live.Tools[0].Name)
	require.Equal(t, "triage", live.Prompts[0].Name, "the upstream prompt name, not the gateway-prefixed one")
	require.Equal(t, "issues://open", live.Resources[0].URI)
	require.Equal(t, 0, d.refreshes)

	// A rediscovery reuses the gateway (ContextForge refuses a second
	// registration of the same URL) and refreshes it; a rotated token is used.
	require.NoError(t, os.WriteFile(tokenFile, []byte("tok-2"), 0o600))
	_, err = c.Discover(ctx, "https://mcp.issues.example/mcp")
	require.NoError(t, err)
	require.Equal(t, 1, d.refreshes)
	require.Len(t, d.gateways, 1)
	require.Equal(t, "Bearer tok-1", d.auth[0])
	require.Equal(t, "Bearer tok-2", d.auth[len(d.auth)-1])

	d.upstream = http.StatusBadGateway
	_, err = c.Discover(ctx, "https://mcp.issues.example/mcp")
	require.ErrorIs(t, err, ErrUpstream)
}

func TestNoRedirectAndMissingToken(t *testing.T) {
	var hit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("secret"), 0o600))
	_, err := New(redirect.URL, tokenFile, time.Second).Discover(context.Background(), "https://x.example/mcp")
	require.Error(t, err)
	require.False(t, hit, "a redirect is never followed, so the token never reaches another host")
	_, err = New(redirect.URL, filepath.Join(t.TempDir(), "absent"), time.Second).Discover(context.Background(), "https://x.example/mcp")
	require.True(t, errors.Is(err, ErrUnavailable))
}
