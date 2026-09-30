// Package contextforge is MCP's client of the ContextForge connection layer
// (B13, DD-08): discovery reuses ContextForge's MCP connections (handshake,
// gateway registration, tool/resource/prompt listings) while AnvilKit keeps
// the catalog, the review and the grants. ContextForge's own visibility,
// OAuth success or UI never authorize anything here. One ContextForge
// gateway serves one canonical resource (ContextForge refuses a second
// registration of the same URL), so a rediscovery refreshes that gateway
// instead of registering it again. The API token is read from a mounted
// file for every request, so a rotated token is picked up without a restart.
package contextforge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// ErrUnavailable: ContextForge could not be asked or answered outside its
// contract; ErrUpstream: the upstream server could not be reached or did
// not speak MCP (ContextForge's 502).
var (
	ErrUnavailable = errors.New("CONNECTION_LAYER_UNAVAILABLE")
	ErrUpstream    = errors.New("UPSTREAM_UNREACHABLE")
)

type Client struct {
	base      string
	tokenFile string
	http      *http.Client
}

// New builds the client; the HTTP client follows no redirect, so a request
// and its bearer token never reach another host.
func New(baseURL, tokenFile string, timeout time.Duration) *Client {
	return &Client{
		base:      strings.TrimRight(baseURL, "/"),
		tokenFile: tokenFile,
		http: &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) (int, error) {
	token, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return 0, fmt.Errorf("%w: token file: %v", ErrUnavailable, err)
	}
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %s %s: %v", ErrUnavailable, method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%w: %s %s: %v", ErrUnavailable, method, path, err)
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("contextforge %s %s answered %d: %s", method, path, resp.StatusCode, truncate(raw))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%w: %s %s: %v", ErrUnavailable, method, path, err)
		}
	}
	return resp.StatusCode, nil
}

func truncate(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r < ' ' {
			return ' '
		}
		return r
	}, string(b))
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

type handshake struct {
	Error           string `json:"error"`
	Success         bool   `json:"success"`
	NegotiationPath string `json:"negotiationPath"`
	ProtocolVersion string `json:"protocolVersion"`
	ServerName      string `json:"serverName"`
	ServerVersion   string `json:"serverVersion"`
	ErrorMessage    string `json:"errorMessage"`
}

type gateway struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type tool struct {
	OriginalName string          `json:"originalName"`
	InputSchema  json.RawMessage `json:"inputSchema"`
	OutputSchema json.RawMessage `json:"outputSchema"`
	Annotations  json.RawMessage `json:"annotations"`
	GatewayID    string          `json:"gatewayId"`
	Enabled      bool            `json:"enabled"`
}

type named struct {
	Name         string `json:"name"`
	OriginalName string `json:"originalName"`
	URI          string `json:"uri"`
	GatewayID    string `json:"gatewayId"`
}

// Discover asks ContextForge to speak to the canonical resource: the
// handshake yields the negotiated protocol version and the server
// identity, the gateway (created once per resource, refreshed afterwards)
// yields the live tools, resources and prompts. Nothing here authorizes
// or executes a tool.
func (c *Client) Discover(ctx context.Context, resource string) (domain.LiveServer, error) {
	// Registration first: ContextForge's handshake probe only speaks to
	// registered gateways (its default test policy), and it stores the URL
	// in its own normalized form, which the probe then uses.
	gw, err := c.gatewayFor(ctx, resource, true)
	if err != nil {
		return domain.LiveServer{}, err
	}
	var hs handshake
	if code, err := c.do(ctx, http.MethodPost, "/v1/mcp-servers/test-handshake", map[string]any{"baseUrl": gw.URL}, &hs); err != nil {
		if code == http.StatusBadGateway || code == http.StatusUnprocessableEntity {
			return domain.LiveServer{}, fmt.Errorf("%w: %v", ErrUpstream, err)
		}
		return domain.LiveServer{}, err
	}
	if !hs.Success {
		return domain.LiveServer{}, fmt.Errorf("%w: handshake failed: %s%s", ErrUpstream, hs.ErrorMessage, hs.Error)
	}
	q := "?gateway_id=" + url.QueryEscape(gw.ID) + "&limit=0"
	var tools []tool
	if _, err := c.do(ctx, http.MethodGet, "/v1/tools"+q, nil, &tools); err != nil {
		return domain.LiveServer{}, err
	}
	var resources, prompts []named
	if _, err := c.do(ctx, http.MethodGet, "/v1/resources"+q, nil, &resources); err != nil {
		return domain.LiveServer{}, err
	}
	if _, err := c.do(ctx, http.MethodGet, "/v1/prompts"+q, nil, &prompts); err != nil {
		return domain.LiveServer{}, err
	}
	live := domain.LiveServer{
		Name: hs.ServerName, Version: hs.ServerVersion, ProtocolVersion: hs.ProtocolVersion, ConnectionRef: "contextforge:" + gw.ID,
		Evidence: fmt.Sprintf("contextforge gateway %s via %s at %s", gw.ID, hs.NegotiationPath, time.Now().UTC().Format(time.RFC3339)),
	}
	for _, t := range tools {
		if t.GatewayID != gw.ID || !t.Enabled {
			continue
		}
		live.Tools = append(live.Tools, domain.LiveTool{Name: t.OriginalName, InputSchema: t.InputSchema, OutputSchema: t.OutputSchema, Annotations: t.Annotations})
	}
	for _, r := range resources {
		if r.GatewayID == gw.ID {
			live.Resources = append(live.Resources, domain.LiveNamed{Name: r.Name, URI: r.URI})
		}
	}
	for _, p := range prompts {
		if p.GatewayID == gw.ID {
			name := p.OriginalName
			if name == "" {
				name = p.Name
			}
			live.Prompts = append(live.Prompts, domain.LiveNamed{Name: name})
		}
	}
	return live, nil
}

// gatewayFor returns the connection of the resource: the existing gateway
// refreshed from the live server, or a new registration (which discovers
// synchronously).
func (c *Client) gatewayFor(ctx context.Context, resource string, mayRegister bool) (gateway, error) {
	var all []gateway
	if _, err := c.do(ctx, http.MethodGet, "/v1/gateways?limit=0&include_inactive=false", nil, &all); err != nil {
		return gateway{}, err
	}
	name, err := gatewayName(resource)
	if err != nil {
		return gateway{}, err
	}
	for _, g := range all {
		if g.Name == name {
			path := "/v1/gateways/" + url.PathEscape(g.ID) + "/tools/refresh?include_resources=true&include_prompts=true"
			if code, err := c.do(ctx, http.MethodPost, path, nil, nil); err != nil {
				if code == http.StatusConflict {
					return gateway{}, fmt.Errorf("%w: a refresh of gateway %s is running", ErrUnavailable, g.ID)
				}
				if code == http.StatusBadGateway {
					return gateway{}, fmt.Errorf("%w: %v", ErrUpstream, err)
				}
				return gateway{}, err
			}
			return g, nil
		}
	}
	if !mayRegister {
		return gateway{}, fmt.Errorf("%w: gateway of %s conflicts but is not listed", ErrUnavailable, resource)
	}
	var created gateway
	code, err := c.do(ctx, http.MethodPost, "/v1/gateways", map[string]any{
		"name": name, "url": resource, "transport": "STREAMABLEHTTP", "visibility": "private",
		"description": "AnvilKit catalog connection; AnvilKit grants decide every use", "tags": []string{"anvilkit"},
	}, &created)
	switch {
	case err == nil:
		return created, nil
	case code == http.StatusBadGateway:
		return gateway{}, fmt.Errorf("%w: %v", ErrUpstream, err)
	case code == http.StatusConflict:
		// A concurrent discovery registered it first: use that one.
		return c.gatewayFor(ctx, resource, false)
	}
	return gateway{}, err
}

func shortHash(s string) string {
	d, _ := domain.CanonicalDigest(json.RawMessage(fmt.Sprintf("%q", s)))
	return strings.TrimPrefix(d, "sha256:")[:12]
}

// gatewayName is the name MCP registers a resource's connection under
// (ContextForge normalizes the stored URL, so the name identifies it).
func gatewayName(resource string) (string, error) {
	u, err := url.Parse(resource)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: resource %q", domain.ErrInvalid, resource)
	}
	return "anvilkit-" + strings.NewReplacer(".", "-", ":", "-").Replace(u.Host) + "-" + shortHash(resource), nil
}
