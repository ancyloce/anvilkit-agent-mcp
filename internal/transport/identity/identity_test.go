package identity_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity/identitytest"
)

const td = "anvilkit.local"

var (
	apiURI  = identitytest.SPIFFE(td, "anvilkit-apps", "anvilkit-agent-api")
	wfURI   = identitytest.SPIFFE(td, "anvilkit-apps", "anvilkit-agent-workflow")
	ctrlURI = identitytest.SPIFFE(td, "anvilkit-apps", "anvilkit-agent-control")
	apiWL   = identity.Workload{Namespace: "anvilkit-apps", ServiceAccount: "anvilkit-agent-api"}
)

func TestParseSPIFFE(t *testing.T) {
	good, err := identity.ParseSPIFFE(mustURL(t, apiURI))
	require.NoError(t, err)
	require.Equal(t, identity.Principal{TrustDomain: td, Namespace: "anvilkit-apps", ServiceAccount: "anvilkit-agent-api"}, good)
	for _, bad := range []string{
		"https://anvilkit.local/ns/anvilkit-apps/sa/anvilkit-agent-api",
		"spiffe://anvilkit.local/sa/anvilkit-agent-api",
		"spiffe://anvilkit.local/ns/anvilkit-apps/sa/anvilkit-agent-api/extra",
		"spiffe://anvilkit.local/ns/Anvilkit-Apps/sa/anvilkit-agent-api",
		"spiffe://anvilkit.local:443/ns/anvilkit-apps/sa/anvilkit-agent-api",
		"spiffe://user@anvilkit.local/ns/anvilkit-apps/sa/anvilkit-agent-api",
		"spiffe://anvilkit.local/ns/anvilkit-apps/sa/anvilkit-agent-api?x=1",
		"spiffe:///ns/anvilkit-apps/sa/anvilkit-agent-api",
		"spiffe://anvilkit.local/ns//sa/anvilkit-agent-api",
	} {
		_, err := identity.ParseSPIFFE(mustURL(t, bad))
		require.Error(t, err, bad)
	}
}

func TestPeerPrincipalRequiresExactlyOneURI(t *testing.T) {
	ca := identitytest.NewCA(t, "ca")
	for name, uris := range map[string][]string{"none": nil, "two": {apiURI, wfURI}, "foreign scheme": {"https://x.invalid/a"}} {
		leaf := ca.Issue(t, "x", uris)
		m, err := identity.Parse(leaf.CertPEM, leaf.KeyPEM, ca.PEM, time.Now())
		require.NoError(t, err)
		_, err = identity.PeerPrincipal(m.Leaf)
		require.Error(t, err, name)
	}
}

func TestMaterialRejectsDefects(t *testing.T) {
	ca := identitytest.NewCA(t, "ca")
	leaf := ca.Issue(t, "x", []string{apiURI})
	other := ca.Issue(t, "y", []string{apiURI})
	_, err := identity.Parse(leaf.CertPEM, other.KeyPEM, ca.PEM, time.Now())
	require.ErrorContains(t, err, "certificate and key", "mismatched key")
	_, err = identity.Parse(leaf.CertPEM, leaf.KeyPEM, []byte("not pem"), time.Now())
	require.ErrorContains(t, err, "no certificate", "empty bundle")
	_, err = identity.Parse(leaf.CertPEM, leaf.KeyPEM, leaf.CertPEM, time.Now())
	require.ErrorContains(t, err, "non-CA", "a leaf is not a CA")
	expired := ca.IssueFor(t, "x", []string{apiURI}, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	_, err = identity.Parse(expired.CertPEM, expired.KeyPEM, ca.PEM, time.Now())
	require.ErrorContains(t, err, "not valid", "expired leaf")
	m, err := identity.Parse(leaf.CertPEM, leaf.KeyPEM, ca.PEM, time.Now())
	require.NoError(t, err)
	require.True(t, m.TrustsRoot(ca.Cert))
}

// fixture is an mTLS health server under a Reloader with a policy that
// admits the API only.
type fixture struct {
	srvDir   string
	reloader *identity.Reloader
	addr     string
	handled  int
	server   *grpc.Server
}

func start(t *testing.T, ca *identitytest.CA, bundle []byte, policy identity.Policy, maxAge time.Duration) *fixture {
	t.Helper()
	f := &fixture{srvDir: filepath.Join(t.TempDir(), "srv")}
	identitytest.Mount(t, f.srvDir, ca.Issue(t, "anvilkit-agent-control", []string{ctrlURI}, "anvilkit-agent-control"), bundle)
	cert, key, caFile := identitytest.Files(f.srvDir)
	r, err := identity.New(identity.Files{CertFile: cert, KeyFile: key, CAFile: caFile}, 50*time.Millisecond, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NoError(t, err)
	r.Start()
	t.Cleanup(r.Stop)
	f.reloader = r
	authz, err := identity.NewAuthorizer(td, policy)
	require.NoError(t, err)
	opts := []grpc.ServerOption{grpc.Creds(identity.NewServerCredentials(r)), grpc.ChainUnaryInterceptor(authz.Unary(), func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		f.handled++
		return h(ctx, req)
	}), grpc.ChainStreamInterceptor(authz.Stream())}
	if maxAge > 0 {
		opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: maxAge, MaxConnectionAgeGrace: time.Second}))
	}
	f.server = grpc.NewServer(opts...)
	grpc_health_v1.RegisterHealthServer(f.server, health.NewServer())
	require.NoError(t, authz.Check(f.server))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = f.server.Serve(ln) }()
	t.Cleanup(f.server.Stop)
	f.addr = ln.Addr().String()
	return f
}

func clientDir(t *testing.T, ca *identitytest.CA, bundle []byte, cn string, uris []string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), cn)
	identitytest.Mount(t, dir, ca.Issue(t, cn, uris), bundle)
	return dir
}

func dial(t *testing.T, addr, dir string) (grpc_health_v1.HealthClient, *grpc.ClientConn) {
	t.Helper()
	cert, key, ca := identitytest.Files(dir)
	r, err := identity.New(identity.Files{CertFile: cert, KeyFile: key, CAFile: ca}, 50*time.Millisecond, nil)
	require.NoError(t, err)
	creds, err := identity.NewClientCredentials(r, "anvilkit-agent-control")
	require.NoError(t, err)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return grpc_health_v1.NewHealthClient(conn), conn
}

func check(c grpc_health_v1.HealthClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	return err
}

func TestHandshakeRefusals(t *testing.T) {
	ca := identitytest.NewCA(t, "ca")
	f := start(t, ca, ca.PEM, identity.Policy{"/grpc.health.v1.Health/Check": {apiWL}, "/grpc.health.v1.Health/Watch": {apiWL}, "/grpc.health.v1.Health/List": {apiWL}}, 0)

	// plaintext
	conn, err := grpc.NewClient(f.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	err = check(grpc_health_v1.NewHealthClient(conn))
	require.Equal(t, codes.Unavailable, status.Code(err), "plaintext dial is refused at the handshake: %v", err)
	conn.Close()

	// no client certificate
	conn, err = grpc.NewClient(f.addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: poolOf(t, ca.PEM), ServerName: "anvilkit-agent-control", MinVersion: tls.VersionTLS13})))
	require.NoError(t, err)
	err = check(grpc_health_v1.NewHealthClient(conn))
	require.Equal(t, codes.Unavailable, status.Code(err), "no client certificate is refused at the handshake: %v", err)
	conn.Close()

	// certificate of another CA
	other := identitytest.NewCA(t, "other")
	c, _ := dial(t, f.addr, clientDir(t, other, ca.PEM, "anvilkit-agent-api", []string{apiURI}))
	err = check(c)
	require.Equal(t, codes.Unavailable, status.Code(err), "foreign CA is refused at the handshake: %v", err)
	require.Equal(t, 0, f.handled, "no handler ran")

	// server certificate from another CA is refused by the client (hostname verification intact)
	c, _ = dial(t, f.addr, clientDir(t, ca, other.PEM, "anvilkit-agent-api", []string{apiURI}))
	err = check(c)
	require.Equal(t, codes.Unavailable, status.Code(err), "client refuses a server it does not trust: %v", err)
}

func TestAuthorizationBeforeHandler(t *testing.T) {
	ca := identitytest.NewCA(t, "ca")
	f := start(t, ca, ca.PEM, identity.Policy{"/grpc.health.v1.Health/Check": {apiWL}, "/grpc.health.v1.Health/Watch": {apiWL}, "/grpc.health.v1.Health/List": {apiWL}}, 0)

	c, _ := dial(t, f.addr, clientDir(t, ca, ca.PEM, "anvilkit-agent-api", []string{apiURI}))
	require.NoError(t, check(c), "the allowed workload is served")
	require.Equal(t, 1, f.handled)

	for name, uris := range map[string][]string{
		"unauthorized workload": {wfURI},
		"wrong trust domain":    {identitytest.SPIFFE("other.invalid", "anvilkit-apps", "anvilkit-agent-api")},
		"wrong namespace":       {identitytest.SPIFFE(td, "anvilkit-components", "anvilkit-agent-api")},
	} {
		c, _ := dial(t, f.addr, clientDir(t, ca, ca.PEM, "anvilkit-agent-api", uris))
		err := check(c)
		require.Equal(t, codes.PermissionDenied, status.Code(err), "%s: %v", name, err)
	}
	for name, uris := range map[string][]string{"no URI SAN": nil, "two URI SANs": {apiURI, wfURI}} {
		c, _ := dial(t, f.addr, clientDir(t, ca, ca.PEM, "anvilkit-agent-api", uris))
		err := check(c)
		require.Equal(t, codes.Unauthenticated, status.Code(err), "%s: %v", name, err)
	}
	require.Equal(t, 1, f.handled, "no refused call reached the handler")
}

func TestPolicyCompleteness(t *testing.T) {
	authz, err := identity.NewAuthorizer(td, identity.Policy{"/grpc.health.v1.Health/Check": {apiWL}, "/x.Y/Z": {apiWL}})
	require.NoError(t, err)
	s := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(s, health.NewServer())
	err = authz.Check(s)
	require.ErrorContains(t, err, "/grpc.health.v1.Health/Watch")
	require.ErrorContains(t, err, "/x.Y/Z")
	_, err = identity.NewAuthorizer("Bad_Domain", identity.Policy{})
	require.Error(t, err)
	_, err = identity.NewAuthorizer(td, identity.Policy{"/a.B/C": nil})
	require.Error(t, err, "an empty entry is a mistake, not a deny")
}

// TestRotation covers AC4: leaf replacement under the same CA, the
// transition bundle, retirement of the old CA, invalid updates, long-lived
// connections and the absence of session resumption.
func TestRotation(t *testing.T) {
	ca1 := identitytest.NewCA(t, "ca1")
	ca2 := identitytest.NewCA(t, "ca2")
	both := append(append([]byte{}, ca1.PEM...), ca2.PEM...)
	policy := identity.Policy{"/grpc.health.v1.Health/Check": {apiWL}, "/grpc.health.v1.Health/Watch": {apiWL}, "/grpc.health.v1.Health/List": {apiWL}}
	f := start(t, ca1, ca1.PEM, policy, 0)
	api1 := clientDir(t, ca1, ca1.PEM, "anvilkit-agent-api", []string{apiURI})
	c1, longLived := dial(t, f.addr, api1)
	require.NoError(t, check(c1))

	// 1. server leaf and key replaced under the same CA: new connections work, the old CA's clients keep working
	identitytest.Mount(t, f.srvDir, ca1.Issue(t, "anvilkit-agent-control", []string{ctrlURI}, "anvilkit-agent-control"), ca1.PEM)
	waitReload(t, f.reloader)
	c, _ := dial(t, f.addr, api1)
	require.NoError(t, check(c), "fresh connection after the leaf swap")
	require.NoError(t, check(c1), "the long-lived connection survives a leaf swap")

	// 2. client leaf replaced under the same CA
	identitytest.Mount(t, api1, ca1.Issue(t, "anvilkit-agent-api", []string{apiURI}), ca1.PEM)
	time.Sleep(120 * time.Millisecond)
	c, _ = dial(t, f.addr, api1)
	require.NoError(t, check(c), "client leaf rotated")

	// 3. transition: the server trusts both CAs and serves a ca2 leaf; clients that trust both accept it
	identitytest.Mount(t, f.srvDir, ca2.Issue(t, "anvilkit-agent-control", []string{ctrlURI}, "anvilkit-agent-control"), both)
	waitReload(t, f.reloader)
	require.Len(t, f.reloader.Current().Roots, 2)
	api1both := clientDir(t, ca1, both, "anvilkit-agent-api", []string{apiURI})
	api2 := clientDir(t, ca2, ca2.PEM, "anvilkit-agent-api", []string{apiURI})
	c, _ = dial(t, f.addr, api1both)
	require.NoError(t, check(c), "a ca1 client trusting both CAs is admitted during the transition")
	c, _ = dial(t, f.addr, api2)
	require.NoError(t, check(c), "a ca2 client is admitted during the transition")
	c, _ = dial(t, f.addr, api1)
	require.Equal(t, codes.Unavailable, status.Code(check(c)), "a client trusting only ca1 refuses the ca2 server leaf")
	require.NoError(t, check(c1), "the long-lived ca1 connection survives the transition (ca1 still trusted)")

	// 4. an invalid update (mismatched key) leaves the valid configuration active
	bad := ca2.Issue(t, "anvilkit-agent-control", []string{ctrlURI}, "anvilkit-agent-control")
	bad.KeyPEM = ca2.Issue(t, "other", []string{ctrlURI}).KeyPEM
	before := f.reloader.Current()
	identitytest.Mount(t, f.srvDir, bad, both)
	require.Eventually(t, func() bool { return f.reloader.Failures() > 0 }, 2*time.Second, 20*time.Millisecond)
	require.True(t, before.Equal(f.reloader.Current()), "the previous material stays active")
	c, _ = dial(t, f.addr, api2)
	require.NoError(t, check(c), "the server keeps serving the last valid material")
	// a missing file mid-swap is also rejected without effect
	require.NoError(t, os.Remove(filepath.Join(f.srvDir, "ca.crt")))
	time.Sleep(120 * time.Millisecond)
	require.True(t, before.Equal(f.reloader.Current()))
	require.NoError(t, os.Symlink(filepath.Join("..data", "ca.crt"), filepath.Join(f.srvDir, "ca.crt")))

	// 5. ca1 retired: new ca1 connections are refused, the long-lived ca1 connection is closed, ca2 keeps working
	identitytest.Mount(t, f.srvDir, ca2.Issue(t, "anvilkit-agent-control", []string{ctrlURI}, "anvilkit-agent-control"), ca2.PEM)
	waitReload(t, f.reloader)
	require.Len(t, f.reloader.Current().Roots, 1)
	c, _ = dial(t, f.addr, api1both)
	require.Equal(t, codes.Unavailable, status.Code(check(c)), "a ca1 leaf is refused after retirement")
	require.Eventually(t, func() bool {
		err := check(c1)
		return err != nil
	}, 3*time.Second, 50*time.Millisecond, "the long-lived ca1 connection was closed")
	_ = longLived
	c, _ = dial(t, f.addr, api2)
	require.NoError(t, check(c), "ca2 unaffected")

	// 6. no session resumption: a raw TLS client that tries to resume a session obtained before the retirement must fail
	cache := tls.NewLRUClientSessionCache(4)
	cfg := func(dir string) *tls.Config {
		cert, key, caFile := identitytest.Files(dir)
		m, err := identity.Load(identity.Files{CertFile: cert, KeyFile: key, CAFile: caFile}, time.Now())
		require.NoError(t, err)
		return &tls.Config{Certificates: []tls.Certificate{m.Certificate}, RootCAs: m.Pool, ServerName: "anvilkit-agent-control", MinVersion: tls.VersionTLS13, ClientSessionCache: cache}
	}
	conn, err := tls.Dial("tcp", f.addr, cfg(api2))
	require.NoError(t, err)
	require.NoError(t, conn.Handshake())
	require.False(t, conn.ConnectionState().DidResume)
	conn.Close()
	conn, err = tls.Dial("tcp", f.addr, cfg(api2))
	require.NoError(t, err)
	require.NoError(t, conn.Handshake())
	require.False(t, conn.ConnectionState().DidResume, "the server issues no session tickets, so nothing can resume under retired trust")
	conn.Close()
}

// TestMaxConnectionAge: a connection never outlives the configured bound,
// which is the retirement guarantee for clients whose trust the server
// did not retire but whose own material changed.
func TestMaxConnectionAge(t *testing.T) {
	ca := identitytest.NewCA(t, "ca")
	f := start(t, ca, ca.PEM, identity.Policy{"/grpc.health.v1.Health/Check": {apiWL}, "/grpc.health.v1.Health/Watch": {apiWL}, "/grpc.health.v1.Health/List": {apiWL}}, 300*time.Millisecond)
	c, conn := dial(t, f.addr, clientDir(t, ca, ca.PEM, "anvilkit-agent-api", []string{apiURI}))
	require.NoError(t, check(c))
	time.Sleep(700 * time.Millisecond)
	require.NoError(t, check(c), "the client transparently reconnected after the age bound")
	_ = conn
}

func TestHTTPTransportFollowsRotation(t *testing.T) {
	ca1 := identitytest.NewCA(t, "ca1")
	ca2 := identitytest.NewCA(t, "ca2")
	srvLeaf := ca1.Issue(t, "anvilkit-agent-model-proxy", []string{identitytest.SPIFFE(td, "anvilkit-apps", "anvilkit-agent-model-proxy")}, "anvilkit-agent-model-proxy")
	srvCert, err := tls.X509KeyPair(srvLeaf.CertPEM, srvLeaf.KeyPEM)
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientCAs: poolOf(t, ca1.PEM), ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13})
	require.NoError(t, err)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
				c.Close()
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	dir := clientDir(t, ca1, ca1.PEM, "anvilkit-agent-control", []string{ctrlURI})
	cert, key, caFile := identitytest.Files(dir)
	r, err := identity.New(identity.Files{CertFile: cert, KeyFile: key, CAFile: caFile}, 50*time.Millisecond, nil)
	require.NoError(t, err)
	r.Start()
	t.Cleanup(r.Stop)
	tr := identity.HTTPTransport(r, "anvilkit-agent-model-proxy")
	get := func() error {
		req, _ := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
		resp, err := tr.RoundTrip(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
	require.NoError(t, get())
	// the client now trusts ca2 only: the ca1 server is refused on the next connection
	identitytest.Mount(t, dir, ca1.Issue(t, "anvilkit-agent-control", []string{ctrlURI}), ca2.PEM)
	waitReload(t, r)
	err = get()
	var unknown x509.UnknownAuthorityError
	require.True(t, errors.As(err, &unknown) || err != nil, "server of a retired CA refused: %v", err)
}

func waitReload(t *testing.T, r *identity.Reloader) {
	t.Helper()
	before := r.Current()
	require.Eventually(t, func() bool { return !before.Equal(r.Current()) }, 2*time.Second, 20*time.Millisecond, "reload observed")
}

func poolOf(t *testing.T, pemBytes []byte) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	require.True(t, p.AppendCertsFromPEM(pemBytes))
	return p
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return u
}
