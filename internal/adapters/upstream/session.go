package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// Route is the selected send route of the official Go SDK (v1.8.0) over
// Streamable HTTP. Per session: the protocol version is pinned to the grant's
// and the negotiated one must equal it; SSE reconnection (MaxRetries) and the
// standalone GET stream are disabled; the HTTP client is the guarded one
// (no redirects, no proxy, bounded bodies, connected-address checks). A
// session is opened per call and never reused, so a connection never
// carries another call's permission.
type Route struct {
	client  *http.Client
	version string
}

// SDKRoute is the route's name in the qualification list.
const SDKRoute = "go-sdk"

func NewRoute(client *http.Client, version string) *Route {
	return &Route{client: client, version: version}
}

// Open connects, checks the negotiated protocol version and compares the
// live input schema of the method with the reviewed descriptor's. Nothing
// has been sent to the tool when Open returns.
func (r *Route) Open(ctx context.Context, t application.UpstreamTarget) (application.UpstreamSession, error) {
	u, err := url.Parse(t.Resource)
	if err != nil {
		return nil, qualify(domain.CallEgressRefused, err)
	}
	// The token's audience is the resource; it goes to that origin only.
	origin := u.Scheme + "://" + u.Host
	httpClient := WithBearer(r.client, origin, t.Token)
	client := mcp.NewClient(&mcp.Implementation{Name: "anvilkit-agent-mcp", Version: r.version}, &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{}})
	transport := &mcp.StreamableClientTransport{Endpoint: t.Resource, HTTPClient: httpClient, MaxRetries: -1, DisableStandaloneSSE: true}
	cs, err := client.Connect(ctx, transport, &mcp.ClientSessionOptions{ProtocolVersion: t.ProtocolVersion})
	if err != nil {
		return nil, qualify(domain.CallUpstreamUnavailable, err)
	}
	fail := func(code string, err error) (application.UpstreamSession, error) {
		cs.Close()
		return nil, qualify(code, err)
	}
	if got := cs.InitializeResult().ProtocolVersion; got != t.ProtocolVersion {
		return fail(domain.CallProtocolMismatch, fmt.Errorf("negotiated protocol %s, the grant binds %s", got, t.ProtocolVersion))
	}
	var tool *mcp.Tool
	for tl, err := range cs.Tools(ctx, nil) {
		if err != nil {
			return fail(domain.CallUpstreamUnavailable, err)
		}
		if tl.Name == t.Method {
			tool = tl
			break
		}
	}
	if tool == nil {
		return fail(domain.CallSchemaDrift, fmt.Errorf("the server no longer lists %s", t.Method))
	}
	raw, err := json.Marshal(tool.InputSchema)
	if err != nil {
		return fail(domain.CallSchemaDrift, err)
	}
	digest, err := domain.CanonicalDigest(raw)
	if err != nil || digest != t.InputSchemaDigest {
		return fail(domain.CallSchemaDrift, fmt.Errorf("live input schema of %s is %s, the reviewed revision has %s", t.Method, digest, t.InputSchemaDigest))
	}
	return &session{cs: cs}, nil
}

func qualify(code string, err error) error {
	if errors.Is(err, ErrEgress) {
		code = domain.CallEgressRefused
	}
	return &application.NotSentError{Code: code, Err: err}
}

type session struct{ cs *mcp.ClientSession }

func (s *session) Close() { _ = s.cs.Close() }

// Send makes the one tools/call of the call. A JSON-RPC error answered by
// the server is a definite refusal; anything else that is not a result
// (transport failure, timeout, oversized or malformed response) leaves the
// outcome unknown.
func (s *session) Send(ctx context.Context, method string, args []byte) (application.UpstreamReply, error) {
	res, err := s.cs.CallTool(ctx, &mcp.CallToolParams{Name: method, Arguments: json.RawMessage(args)})
	if err != nil {
		var werr *jsonrpc.Error
		if errors.As(err, &werr) && answered(err, werr) {
			native, _ := json.Marshal(map[string]any{"error": map[string]any{"code": werr.Code, "message": bounded(werr.Message, 1024)}})
			return application.UpstreamReply{Native: native}, &application.AnsweredError{Code: domain.CallProtocolError, Err: err}
		}
		code := domain.CallOutcomeUnknown
		if errors.Is(err, ErrBodyTooLarge) {
			code = domain.CallResultTooLarge
		}
		return application.UpstreamReply{}, &application.UnknownError{Code: code, Err: err}
	}
	native, err := json.Marshal(res)
	if err != nil {
		return application.UpstreamReply{}, &application.UnknownError{Code: domain.CallOutcomeUnknown, Err: err}
	}
	result, err := Normalize(res)
	if err != nil {
		return application.UpstreamReply{Native: native}, &application.UnknownError{Code: domain.CallOutcomeUnknown, Err: err}
	}
	return application.UpstreamReply{Result: result, Native: native, IsError: res.IsError}, nil
}

// localCodes are the JSON-RPC codes the SDK builds itself for failures of
// its own side (unknown, client/server closing, rejected by transport): an
// error carrying one of them is not the server's answer.
var localCodes = map[int64]bool{-32001: true, -32003: true, -32004: true, -32005: true}

// answered reports whether err is a JSON-RPC error the server actually
// sent: a code the SDK never builds locally and no transport failure
// anywhere in the chain. Anything else leaves the outcome unknown.
func answered(err error, werr *jsonrpc.Error) bool {
	if localCodes[werr.Code] {
		return false
	}
	var uerr *url.Error
	var nerr net.Error
	return !errors.As(err, &uerr) && !errors.As(err, &nerr) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) &&
		!errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) && !errors.Is(err, ErrBodyTooLarge)
}

func bounded(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Normalize maps a tool result to AnvilKit's bounded typed result: text is
// kept as text, binary content (images, audio, blobs) is reduced to its
// type, size and digest, links and embedded resources keep their URI as
// data only (nothing ever follows them), structured content is kept as
// JSON. The whole result is labeled untrusted.
func Normalize(res *mcp.CallToolResult) ([]byte, error) {
	type block struct {
		Type     string `json:"type"`
		Text     string `json:"text,omitempty"`
		MIMEType string `json:"mimeType,omitempty"`
		Size     int    `json:"size,omitempty"`
		Digest   string `json:"digest,omitempty"`
		URI      string `json:"uri,omitempty"`
		Name     string `json:"name,omitempty"`
	}
	blocks := make([]block, 0, len(res.Content))
	for _, c := range res.Content {
		switch v := c.(type) {
		case *mcp.TextContent:
			blocks = append(blocks, block{Type: "text", Text: v.Text})
		case *mcp.ImageContent:
			blocks = append(blocks, block{Type: "image", MIMEType: v.MIMEType, Size: len(v.Data), Digest: domain.DigestBytes(v.Data)})
		case *mcp.AudioContent:
			blocks = append(blocks, block{Type: "audio", MIMEType: v.MIMEType, Size: len(v.Data), Digest: domain.DigestBytes(v.Data)})
		case *mcp.ResourceLink:
			blocks = append(blocks, block{Type: "resource_link", URI: v.URI, Name: v.Name, MIMEType: v.MIMEType})
		case *mcp.EmbeddedResource:
			b := block{Type: "resource"}
			if v.Resource != nil {
				b.URI, b.MIMEType, b.Text = v.Resource.URI, v.Resource.MIMEType, v.Resource.Text
				if len(v.Resource.Blob) > 0 {
					b.Size, b.Digest = len(v.Resource.Blob), domain.DigestBytes(v.Resource.Blob)
				}
			}
			blocks = append(blocks, b)
		default:
			raw, _ := json.Marshal(c)
			blocks = append(blocks, block{Type: "unsupported", Size: len(raw), Digest: domain.DigestBytes(raw)})
		}
	}
	out := map[string]any{"untrusted": true, "isError": res.IsError, "content": blocks}
	if res.StructuredContent != nil {
		out["structuredContent"] = res.StructuredContent
	}
	return json.Marshal(out)
}
