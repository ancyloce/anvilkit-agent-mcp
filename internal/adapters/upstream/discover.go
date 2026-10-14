package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/contextforge"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// Discoverer is discovery through MCP's own guarded egress (P2.5, DD-08
// §1): the connection layer of a protected resource whose reviewed
// credential MCP holds. ContextForge's gateway registration cannot present
// that credential, so such a resource is read here: its protected-resource
// metadata names the issuer, the reviewed credential obtains a token bound
// to exactly that resource (RFC 8707), and one SDK session pinned to the
// listing's declared protocol version lists the tools, resources and
// prompts. The token goes to the resource's origin only; no inbound
// AnvilKit credential is ever available to this client, and every hop is
// the guarded client's (reviewed hosts, checked addresses, no redirects,
// bounded bodies).
type Discoverer struct {
	client    *http.Client
	authority *Authority
	version   string
	now       func() time.Time
}

// maxListed bounds each listing a discovery reads.
const maxListed = 4096

func NewDiscoverer(client *http.Client, authority *Authority, version string, now func() time.Time) *Discoverer {
	return &Discoverer{client: client, authority: authority, version: version, now: now}
}

// Discover reads the live server. An authorization failure (metadata
// substituted, no reviewed credential, token refused) is FORBIDDEN; a
// server that cannot be reached or initialized is UPSTREAM_UNREACHABLE.
func (d *Discoverer) Discover(ctx context.Context, resource, protocolVersion string) (domain.LiveServer, error) {
	u, err := url.Parse(resource)
	if err != nil || u.Host == "" {
		return domain.LiveServer{}, fmt.Errorf("%w: canonical resource %q", domain.ErrInvalid, resource)
	}
	token, issuer, err := d.authority.DiscoveryToken(ctx, resource)
	if err != nil {
		return domain.LiveServer{}, fmt.Errorf("%w: discovery authorization: %v", application.ErrForbidden, err)
	}
	httpClient := WithBearer(d.client, u.Scheme+"://"+u.Host, token)
	client := mcp.NewClient(&mcp.Implementation{Name: "anvilkit-agent-mcp", Version: d.version}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
	transport := &mcp.StreamableClientTransport{Endpoint: resource, HTTPClient: httpClient, MaxRetries: -1, DisableStandaloneSSE: true}
	cs, err := client.Connect(ctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: protocolVersion})
	if err != nil {
		return domain.LiveServer{}, fmt.Errorf("%w: %s: %v", contextforge.ErrUpstream, resource, err)
	}
	defer cs.Close()
	init := cs.InitializeResult()
	live := domain.LiveServer{
		ProtocolVersion: init.ProtocolVersion, Issuer: issuer, ConnectionRef: "egress:" + resource,
		Evidence: fmt.Sprintf("egress:%s@%s", resource, d.now().UTC().Format(time.RFC3339)),
	}
	if init.ServerInfo != nil {
		live.Name, live.Version = init.ServerInfo.Name, init.ServerInfo.Version
	}
	for t, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return domain.LiveServer{}, fmt.Errorf("%w: tools/list: %v", contextforge.ErrUpstream, err)
		}
		if len(live.Tools) == maxListed {
			return domain.LiveServer{}, fmt.Errorf("%w: more than %d tools", domain.ErrInvalid, maxListed)
		}
		lt := domain.LiveTool{Name: t.Name}
		if lt.InputSchema, err = json.Marshal(t.InputSchema); err != nil {
			return domain.LiveServer{}, fmt.Errorf("%w: input schema of %s: %v", domain.ErrInvalid, t.Name, err)
		}
		if t.OutputSchema != nil {
			if lt.OutputSchema, err = json.Marshal(t.OutputSchema); err != nil {
				return domain.LiveServer{}, fmt.Errorf("%w: output schema of %s: %v", domain.ErrInvalid, t.Name, err)
			}
		}
		if t.Annotations != nil {
			if lt.Annotations, err = json.Marshal(t.Annotations); err != nil {
				return domain.LiveServer{}, fmt.Errorf("%w: annotations of %s: %v", domain.ErrInvalid, t.Name, err)
			}
		}
		live.Tools = append(live.Tools, lt)
	}
	if init.Capabilities != nil && init.Capabilities.Resources != nil {
		for r, err := range cs.Resources(ctx, nil) {
			if err != nil {
				return domain.LiveServer{}, fmt.Errorf("%w: resources/list: %v", contextforge.ErrUpstream, err)
			}
			if len(live.Resources) == maxListed {
				return domain.LiveServer{}, fmt.Errorf("%w: more than %d resources", domain.ErrInvalid, maxListed)
			}
			live.Resources = append(live.Resources, domain.LiveNamed{Name: r.Name, URI: r.URI})
		}
	}
	if init.Capabilities != nil && init.Capabilities.Prompts != nil {
		for p, err := range cs.Prompts(ctx, nil) {
			if err != nil {
				return domain.LiveServer{}, fmt.Errorf("%w: prompts/list: %v", contextforge.ErrUpstream, err)
			}
			if len(live.Prompts) == maxListed {
				return domain.LiveServer{}, fmt.Errorf("%w: more than %d prompts", domain.ErrInvalid, maxListed)
			}
			live.Prompts = append(live.Prompts, domain.LiveNamed{Name: p.Name})
		}
	}
	return live, nil
}
