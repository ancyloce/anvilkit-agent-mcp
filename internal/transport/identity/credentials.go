package identity

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sync"

	"google.golang.org/grpc/credentials"
)

// PeerInfo is the AuthInfo of an mTLS connection: the standard TLSInfo
// plus the parsed workload identity (or why there is none) and the root
// that verified the peer's chain.
type PeerInfo struct {
	credentials.TLSInfo
	Principal Principal
	// Err is why the verified certificate carries no workload identity.
	Err  error
	Root *x509.Certificate
}

// AuthType reports the transport security type ("tls").
func (p PeerInfo) AuthType() string { return "tls" }

// connTracker remembers every accepted server connection by the root that
// verified its peer, so a reload that retires a root closes exactly those
// connections (the clients reconnect under the current trust).
type connTracker struct {
	mu    sync.Mutex
	conns map[[32]byte]map[net.Conn]struct{}
}

func (t *connTracker) add(root *x509.Certificate, c net.Conn) {
	fp := sha256.Sum256(root.Raw)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conns == nil {
		t.conns = map[[32]byte]map[net.Conn]struct{}{}
	}
	if t.conns[fp] == nil {
		t.conns[fp] = map[net.Conn]struct{}{}
	}
	t.conns[fp][c] = struct{}{}
}

func (t *connTracker) remove(root *x509.Certificate, c net.Conn) {
	fp := sha256.Sum256(root.Raw)
	t.mu.Lock()
	defer t.mu.Unlock()
	if set := t.conns[fp]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(t.conns, fp)
		}
	}
}

// closeRetired closes the connections whose root is no longer trusted.
func (t *connTracker) closeRetired(current *Material) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for fp, set := range t.conns {
		if _, ok := current.Roots[fp]; ok {
			continue
		}
		for c := range set {
			_ = c.Close()
			n++
		}
		delete(t.conns, fp)
	}
	return n
}

// trackedConn removes itself from the tracker when closed.
type trackedConn struct {
	net.Conn
	root    *x509.Certificate
	tracker *connTracker
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() { c.tracker.remove(c.root, c.Conn) })
	return c.Conn.Close()
}

// serverCreds is a credentials.TransportCredentials whose every handshake
// uses the Reloader's current material: TLS 1.3 only, client certificates
// required and verified against the current CA bundle, no session tickets
// (a resumed session would skip the current trust).
type serverCreds struct {
	reloader *Reloader
	tracker  *connTracker
}

// NewServerCredentials returns rotating server credentials. Retiring a CA
// from the bundle closes the connections it had verified.
func NewServerCredentials(r *Reloader) credentials.TransportCredentials {
	s := &serverCreds{reloader: r, tracker: &connTracker{}}
	r.OnChange(func(_, current *Material) {
		if n := s.tracker.closeRetired(current); n > 0 {
			r.log.Info("closed connections of retired trust", "connections", n)
		}
	})
	return s
}

func (s *serverCreds) config() *tls.Config {
	m := s.reloader.Current()
	return &tls.Config{
		Certificates:           []tls.Certificate{m.Certificate},
		ClientCAs:              m.Pool,
		ClientAuth:             tls.RequireAndVerifyClientCert,
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}
}

func (s *serverCreds) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := credentials.NewTLS(s.config()).ServerHandshake(raw)
	if err != nil {
		return nil, nil, err
	}
	tlsInfo, ok := info.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		_ = conn.Close()
		return nil, nil, errors.New("identity: peer chain not verified")
	}
	chain := tlsInfo.State.VerifiedChains[0]
	root := chain[len(chain)-1]
	peer := PeerInfo{TLSInfo: tlsInfo, Root: root}
	peer.Principal, peer.Err = PeerPrincipal(chain[0])
	tracked := &trackedConn{Conn: conn, root: root, tracker: s.tracker}
	s.tracker.add(root, conn)
	return tracked, peer, nil
}

func (s *serverCreds) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("identity: server credentials cannot dial")
}

func (s *serverCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls", SecurityVersion: "1.3", ServerName: ""}
}

func (s *serverCreds) Clone() credentials.TransportCredentials { return s }

func (s *serverCreds) OverrideServerName(string) error { return nil }

// clientCreds dials with the Reloader's current certificate and CA bundle
// and verifies the server through standard hostname verification against
// ServerName (a DNS SAN); no session cache, so nothing resumes under
// retired trust.
type clientCreds struct {
	reloader   *Reloader
	serverName string
}

// NewClientCredentials returns rotating client credentials; serverName is
// the DNS SAN the server certificate must carry.
func NewClientCredentials(r *Reloader, serverName string) (credentials.TransportCredentials, error) {
	if serverName == "" {
		return nil, errors.New("identity: server_name is required for hostname verification")
	}
	return &clientCreds{reloader: r, serverName: serverName}, nil
}

func (c *clientCreds) config() *tls.Config {
	m := c.reloader.Current()
	return &tls.Config{
		Certificates: []tls.Certificate{m.Certificate},
		RootCAs:      m.Pool,
		ServerName:   c.serverName,
		MinVersion:   tls.VersionTLS13,
	}
}

func (c *clientCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return credentials.NewTLS(c.config()).ClientHandshake(ctx, authority, raw)
}

func (c *clientCreds) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("identity: client credentials cannot serve")
}

func (c *clientCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls", SecurityVersion: "1.3", ServerName: c.serverName}
}

func (c *clientCreds) Clone() credentials.TransportCredentials {
	return &clientCreds{reloader: c.reloader, serverName: c.serverName}
}

// OverrideServerName keeps the configured name: the reviewed server_name is
// the verification target, never the dialed authority.
func (c *clientCreds) OverrideServerName(string) error { return nil }

// ClientTLSConfig is a standard tls.Config snapshot for non-gRPC clients:
// the certificate follows the Reloader on every handshake, the roots are
// the bundle at the time of the call. Connections that outlive a CA
// retirement are rebuilt by their owner from a fresh snapshot (Reloader
// OnChange); HTTPTransport does that per connection.
func ClientTLSConfig(r *Reloader, serverName string) *tls.Config {
	m := r.Current()
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: serverName,
		RootCAs:    m.Pool,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert := r.Current().Certificate
			return &cert, nil
		},
	}
}

// HTTPTransport is an http.Transport whose every new TLS connection uses the
// Reloader's current material with standard verification; a CA retirement
// closes the idle pool so the next request handshakes under current trust.
func HTTPTransport(r *Reloader, serverName string) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = nil
	t.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		raw, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, ClientTLSConfig(r, serverName))
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return conn, nil
	}
	r.OnChange(func(previous, current *Material) {
		if len(RetiredRoots(previous, current)) > 0 {
			t.CloseIdleConnections()
		}
	})
	return t
}
