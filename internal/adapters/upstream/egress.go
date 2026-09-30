// Package upstream is MCP's own egress to upstream MCP servers and their
// authorization servers (DD-08 §3-§5): every hop — the protected resource
// metadata, the authorization server metadata, the token endpoint, the MCP
// endpoint — goes through one guarded HTTP client that
//
//   - admits only reviewed hosts (http only for the DEVELOPMENT_ONLY private
//     hosts),
//   - resolves each host once and dials the checked addresses only, then
//     verifies the connected peer address again (DNS rebinding between the
//     check and the connection cannot move the connection),
//   - follows no redirect (a redirect is refused, so no request and no
//     Authorization header ever reaches another host), uses no proxy,
//   - bounds every response body, and
//   - attaches a bearer token only to requests for the origin it was issued
//     for; inbound AnvilKit credentials are never available to it.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
)

// ErrEgress marks a hop the network policy refused; nothing was sent to it.
var ErrEgress = errors.New("EGRESS_REFUSED")

// Guard is the network policy applied at connection time.
type Guard struct {
	Policy   application.NetworkPolicy
	Resolver application.Resolver
	Dialer   *net.Dialer
}

// DialContext resolves the host, checks every address, dials the checked
// addresses only and checks the peer it actually connected to.
func (g Guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEgress, err)
	}
	private, err := g.Policy.CheckHost(host)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEgress, err)
	}
	var addrs []netip.Addr
	if a, perr := netip.ParseAddr(strings.Trim(host, "[]")); perr == nil {
		addrs = []netip.Addr{a}
	} else if addrs, err = g.Resolver.LookupNetIP(ctx, "ip", host); err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("%w: host %s does not resolve", ErrEgress, host)
	}
	for _, a := range addrs {
		if err := application.CheckAddr(host, a, private); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEgress, err)
		}
	}
	d := g.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: 10 * time.Second}
	}
	var last error
	for _, a := range addrs {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		if err != nil {
			last = err
			continue
		}
		peer, perr := netip.ParseAddrPort(conn.RemoteAddr().String())
		if perr != nil || peer.Addr().Unmap() != a.Unmap() || application.CheckAddr(host, peer.Addr(), private) != nil {
			conn.Close()
			return nil, fmt.Errorf("%w: host %s connected to %s, not the checked %s", ErrEgress, host, conn.RemoteAddr(), a)
		}
		return conn, nil
	}
	return nil, last
}

// Client builds the guarded HTTP client. maxBody bounds every response
// body; timeout bounds every request.
func (g Guard) Client(maxBody int64, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &guardedTransport{guard: g, maxBody: maxBody, base: &http.Transport{
			Proxy: nil, DialContext: g.DialContext, ForceAttemptHTTP2: true,
			MaxIdleConns: 16, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
			ResponseHeaderTimeout: timeout, MaxResponseHeaderBytes: 64 << 10,
		}},
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			return fmt.Errorf("%w: redirect to %s refused", ErrEgress, req.URL.Redacted())
		},
	}
}

type guardedTransport struct {
	guard   Guard
	base    http.RoundTripper
	maxBody int64
}

func (t *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	private, err := t.guard.Policy.CheckHost(req.URL.Hostname())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEgress, err)
	}
	if req.URL.Scheme != "https" && !(private && req.URL.Scheme == "http") {
		return nil, fmt.Errorf("%w: scheme %s for %s", ErrEgress, req.URL.Scheme, req.URL.Host)
	}
	if req.URL.User != nil {
		return nil, fmt.Errorf("%w: credentials in a URL", ErrEgress)
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = &boundedBody{rc: resp.Body, left: t.maxBody}
	return resp, nil
}

// ErrBodyTooLarge: a response exceeded the bound; the reader stops.
var ErrBodyTooLarge = errors.New("RESPONSE_TOO_LARGE")

type boundedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		// One more byte than allowed tells a full body from an oversized one.
		var one [1]byte
		if n, _ := b.rc.Read(one[:]); n > 0 {
			return 0, ErrBodyTooLarge
		}
		return 0, io.EOF
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	return n, err
}

func (b *boundedBody) Close() error { return b.rc.Close() }

// bearer attaches a token to requests for exactly one origin; any other
// request goes out without it.
type bearer struct {
	base   http.RoundTripper
	origin string
	token  string
}

func (b *bearer) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Del("Authorization")
	if b.token != "" && originOf(req.URL.Scheme, req.URL.Host) == b.origin {
		req.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(req)
}

func originOf(scheme, host string) string { return strings.ToLower(scheme + "://" + host) }

// WithBearer returns a client sharing c's transport that adds the token to
// requests for origin only.
func WithBearer(c *http.Client, origin, token string) *http.Client {
	out := *c
	out.Transport = &bearer{base: c.Transport, origin: strings.ToLower(origin), token: token}
	return &out
}
