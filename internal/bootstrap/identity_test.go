package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"go.uber.org/fx/fxtest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/config"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity/identitytest"
)

const testInterval = 10 * time.Millisecond

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// developmentListener is a workloadIdentity without a listener Reloader.
func developmentListener(t *testing.T) *workloadIdentity {
	t.Helper()
	var cfg config.Config
	cfg.GRPC.Identity.Mode = "development"
	cfg.GRPC.Identity.ReloadInterval = testInterval
	w, err := newWorkloadIdentity(cfg, quietLog())
	require.NoError(t, err)
	return w
}

type traceCollector struct {
	coltracepb.UnimplementedTraceServiceServer
	spans atomic.Int32
}

func (c *traceCollector) Export(_ context.Context, r *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	for _, rs := range r.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			c.spans.Add(int32(len(ss.GetSpans())))
		}
	}
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

// startCollector serves OTLP traces in plaintext (serverTLS nil) or under
// serverTLS.
func startCollector(t *testing.T, serverTLS *tls.Config) (string, *traceCollector) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var opts []grpc.ServerOption
	if serverTLS != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(serverTLS)))
	}
	srv := grpc.NewServer(opts...)
	c := &traceCollector{}
	coltracepb.RegisterTraceServiceServer(srv, c)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), c
}

// Each telemetry.otlp_tls mode reaches its collector: given as a dial
// option, the transport lost to the exporter's default (TLS with the host's
// roots), so a development collector was dialed over TLS, a tls collector
// was verified without its CA and an mtls collector got no client
// certificate; no span arrived in any of them.
func TestOTLPExporterUsesTheConfiguredCredentials(t *testing.T) {
	ca := identitytest.NewCA(t, "otlp-ca")
	dir := t.TempDir()
	srvDir, cliDir := filepath.Join(dir, "collector"), filepath.Join(dir, "client")
	identitytest.Mount(t, srvDir, ca.Issue(t, "collector", nil), ca.PEM)
	identitytest.Mount(t, cliDir, ca.Issue(t, "anvilkit-agent-mcp", nil), ca.PEM)
	srvCert, srvKey, caFile := identitytest.Files(srvDir)
	cliCert, cliKey, _ := identitytest.Files(cliDir)
	pair, err := tls.LoadX509KeyPair(srvCert, srvKey)
	require.NoError(t, err)
	clients := x509.NewCertPool()
	require.True(t, clients.AppendCertsFromPEM(ca.PEM))

	for _, tc := range []struct {
		name    string
		server  *tls.Config
		section config.ClientTLS
	}{
		{"development", nil, config.ClientTLS{Mode: "development"}},
		{"tls", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}, config.ClientTLS{Mode: "tls", CAFile: caFile, ServerName: "localhost"}},
		{"mtls", &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clients, MinVersion: tls.VersionTLS13}, config.ClientTLS{Mode: "mtls", CertFile: cliCert, KeyFile: cliKey, CAFile: caFile, ServerName: "localhost"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			addr, collector := startCollector(t, tc.server)
			creds, err := developmentListener(t).otlpCredentials(tc.section, true, quietLog())
			require.NoError(t, err)
			exporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(addr), creds,
				otlptracegrpc.WithTimeout(5*time.Second), otlptracegrpc.WithRetry(otlptracegrpc.RetryConfig{Enabled: false}))
			require.NoError(t, err)
			provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
			_, span := provider.Tracer("otlp-test").Start(ctx, "span")
			span.End()
			require.NoError(t, provider.Shutdown(ctx))
			require.Equal(t, int32(1), collector.spans.Load())
		})
	}
}

// Plaintext OTLP still needs the development guard.
func TestOTLPPlaintextNeedsTheDevelopmentGuard(t *testing.T) {
	_, err := developmentListener(t).otlpCredentials(config.ClientTLS{Mode: "development"}, false, quietLog())
	require.ErrorContains(t, err, "development mode without development.enabled")
	_, err = developmentListener(t).otlpCredentials(config.ClientTLS{Mode: "plain"}, true, quietLog())
	require.ErrorContains(t, err, `unknown mode "plain"`)
}

func mountIdentity(t *testing.T, ca *identitytest.CA, dir string) identity.Files {
	t.Helper()
	identitytest.Mount(t, dir, ca.Issue(t, "anvilkit-agent-mcp", nil), ca.PEM)
	cert, key, caFile := identitytest.Files(dir)
	return identity.Files{CertFile: cert, KeyFile: key, CAFile: caFile}
}

func mtlsSection(f identity.Files) config.ClientTLS {
	return config.ClientTLS{Mode: "mtls", CertFile: f.CertFile, KeyFile: f.KeyFile, CAFile: f.CAFile, ServerName: "localhost"}
}

// The three Control clients share one Reloader, and a client presenting the
// listener's files shares the listener's: before, each Control client
// started a Reloader of its own.
func TestClientsShareTheirReloaders(t *testing.T) {
	ca := identitytest.NewCA(t, "ca")
	dir := t.TempDir()
	listener := mountIdentity(t, ca, filepath.Join(dir, "listener"))
	control := mountIdentity(t, ca, filepath.Join(dir, "control"))

	var cfg config.Config
	cfg.GRPC.Identity.Mode = "mtls"
	cfg.GRPC.Identity.CertFile, cfg.GRPC.Identity.KeyFile, cfg.GRPC.Identity.CAFile = listener.CertFile, listener.KeyFile, listener.CAFile
	cfg.GRPC.Identity.ReloadInterval = testInterval
	cfg.Control.Identity.Mode = "mtls"
	cfg.Control.Identity.MTLS = mtlsSection(control)
	w, err := newWorkloadIdentity(cfg, quietLog())
	require.NoError(t, err)
	for range 3 {
		_, err := w.controlTransport(cfg, quietLog())
		require.NoError(t, err)
	}
	require.Len(t, w.clients, 1, "one Reloader for the Control clients")
	shared, err := w.reloaderFor(control)
	require.NoError(t, err)
	require.Same(t, w.clients[control], shared)

	_, err = w.otlpCredentials(mtlsSection(listener), false, quietLog())
	require.NoError(t, err)
	same, err := w.reloaderFor(listener)
	require.NoError(t, err)
	require.Same(t, w.reloader, same, "the listener's files use the listener's Reloader")
	require.Len(t, w.clients, 1)
}

// rotate mounts a new leaf into dir and returns the digest before it.
func rotate(t *testing.T, ca *identitytest.CA, dir string, r *identity.Reloader) [32]byte {
	t.Helper()
	before := r.Current().Digest
	identitytest.Mount(t, dir, ca.Issue(t, "anvilkit-agent-mcp", nil), ca.PEM)
	return before
}

// unchanged checks that r does not follow a rotation over many poll
// intervals (a negative check: a slow machine can only make it pass).
func unchanged(t *testing.T, r *identity.Reloader, digest [32]byte, msg string) {
	t.Helper()
	time.Sleep(20 * testInterval)
	require.Equal(t, digest, r.Current().Digest, msg)
}

// The Control and OTLP Reloaders poll from the lifecycle's start to its
// stop only: constructing the clients starts nothing (a failed construction
// leaves no poller), a rotation is followed while the process runs, and
// nothing polls after the stop. Before, they started at construction and
// never stopped.
func TestClientReloadersFollowTheLifecycle(t *testing.T) {
	ca := identitytest.NewCA(t, "ca")
	dir := t.TempDir()
	controlDir, otlpDir := filepath.Join(dir, "control"), filepath.Join(dir, "otlp")
	control, otlp := mountIdentity(t, ca, controlDir), mountIdentity(t, ca, otlpDir)

	w := developmentListener(t)
	lc := fxtest.NewLifecycle(t)
	w.followLifecycle(lc)
	var cfg config.Config
	cfg.Control.Identity.Mode = "mtls"
	cfg.Control.Identity.MTLS = mtlsSection(control)
	_, err := w.controlTransport(cfg, quietLog())
	require.NoError(t, err)
	_, err = w.otlpCredentials(mtlsSection(otlp), false, quietLog())
	require.NoError(t, err)
	controlR, otlpR := w.clients[control], w.clients[otlp]
	require.NotNil(t, controlR)
	require.NotNil(t, otlpR)

	unchanged(t, controlR, rotate(t, ca, controlDir, controlR), "no polling before the start")

	lc.RequireStart()
	for _, c := range []struct {
		dir string
		r   *identity.Reloader
	}{{controlDir, controlR}, {otlpDir, otlpR}} {
		before := rotate(t, ca, c.dir, c.r)
		require.Eventually(t, func() bool { return c.r.Current().Digest != before }, 5*time.Second, testInterval, "polled while started")
	}

	lc.RequireStop()
	unchanged(t, controlR, rotate(t, ca, controlDir, controlR), "no polling after the stop")
	unchanged(t, otlpR, rotate(t, ca, otlpDir, otlpR), "no polling after the stop")
}
