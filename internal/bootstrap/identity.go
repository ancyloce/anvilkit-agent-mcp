package bootstrap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.uber.org/fx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/config"
	grpctransport "github.com/ancyloce/anvilkit-agent-mcp/internal/transport/grpc"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity"
)

// workloadIdentity owns the process's certificate Reloaders (P0.1): the
// listener's (grpc.identity's files; nil under the DEVELOPMENT_ONLY
// plaintext listener) and one per further set of files that a
// process-lifetime client presents (the Control clients, OTLP). A client
// whose files are the listener's shares the listener's Reloader, and the
// Control clients share one Reloader. Construction starts no polling:
// followLifecycle polls them all from the start to the stop of the process,
// so a failed construction or start leaves no poller behind. A generation's
// NATS Reloader is the generation's own (runtime.natsIdentity).
type workloadIdentity struct {
	reloader  *identity.Reloader
	listener  identity.Files
	interval  time.Duration
	log       *slog.Logger
	mu        sync.Mutex
	clients   map[identity.Files]*identity.Reloader
	following bool
}

func newWorkloadIdentity(cfg config.Config, log *slog.Logger) (*workloadIdentity, error) {
	id := cfg.GRPC.Identity
	w := &workloadIdentity{interval: id.ReloadInterval, log: log, clients: map[identity.Files]*identity.Reloader{}}
	if id.Mode == "development" {
		log.Warn("DEVELOPMENT_ONLY listener identity: plaintext gRPC, no caller is authenticated or authorized; qualifies no production identity")
		return w, nil
	}
	w.listener = identity.Files{CertFile: id.CertFile, KeyFile: id.KeyFile, CAFile: id.CAFile}
	r, err := identity.New(w.listener, id.ReloadInterval, log)
	if err != nil {
		return nil, fmt.Errorf("grpc.identity: %w", err)
	}
	w.reloader = r
	return w, nil
}

// followLifecycle polls every Reloader of w from the lifecycle's start to
// its stop. The one-shot operator path does not call it: its connections
// end before any rotation matters.
func (w *workloadIdentity) followLifecycle(lc fx.Lifecycle) {
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error { w.start(); return nil },
		OnStop:  func(context.Context) error { w.stop(); return nil },
	})
}

func (w *workloadIdentity) start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.following = true
	for _, r := range w.owned() {
		r.Start()
	}
}

func (w *workloadIdentity) stop() {
	w.mu.Lock()
	w.following = false
	owned := w.owned()
	w.mu.Unlock()
	for _, r := range owned {
		r.Stop()
	}
}

// owned lists the Reloaders of w; the caller holds mu.
func (w *workloadIdentity) owned() []*identity.Reloader {
	out := make([]*identity.Reloader, 0, len(w.clients)+1)
	if w.reloader != nil {
		out = append(out, w.reloader)
	}
	for _, r := range w.clients {
		out = append(out, r)
	}
	return out
}

// reloaderFor is the Reloader of a client's files: the listener's for the
// listener's files, otherwise the one w owns for that set (created on first
// use, polled while w follows the lifecycle).
func (w *workloadIdentity) reloaderFor(f identity.Files) (*identity.Reloader, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.reloader != nil && f == w.listener {
		return w.reloader, nil
	}
	if r, ok := w.clients[f]; ok {
		return r, nil
	}
	r, err := identity.New(f, w.interval, w.log)
	if err != nil {
		return nil, err
	}
	w.clients[f] = r
	if w.following {
		r.Start()
	}
	return r, nil
}

// server is the listener identity or nil for the development listener.
func (w *workloadIdentity) server(cfg config.Config) *grpctransport.Identity {
	if w.reloader == nil {
		return nil
	}
	return &grpctransport.Identity{Reloader: w.reloader, TrustDomain: cfg.TrustDomain(), Policy: grpctransport.Policy(), MaxConnectionAge: cfg.GRPC.Identity.MaxConnectionAge}
}

// controlTransport is the dial option of the Control clients: the rotating
// workload certificate with hostname verification of Control, or plaintext
// under the development guard.
func (w *workloadIdentity) controlTransport(cfg config.Config, log *slog.Logger) (grpc.DialOption, error) {
	switch cfg.Control.Identity.Mode {
	case "development":
		if !cfg.Development.Enabled {
			return nil, errors.New("control.identity: development mode without development.enabled")
		}
		log.Warn("DEVELOPMENT_ONLY plaintext transport", "connection", "control")
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	case "mtls":
		m := cfg.ControlMTLS()
		r, err := w.reloaderFor(identity.Files{CertFile: m.CertFile, KeyFile: m.KeyFile, CAFile: m.CAFile})
		if err != nil {
			return nil, fmt.Errorf("control.identity: %w", err)
		}
		creds, err := identity.NewClientCredentials(r, m.ServerName)
		if err != nil {
			return nil, fmt.Errorf("control.identity: %w", err)
		}
		return grpc.WithTransportCredentials(creds), nil
	}
	return nil, fmt.Errorf("control.identity.mode %q", cfg.Control.Identity.Mode)
}

// otlpCredentials is the exporter option of telemetry.otlp_tls. It is
// handed to the exporter itself (WithInsecure, WithTLSCredentials): a dial
// option alone loses to the exporter's default (TLS with the host's roots),
// which dialed a development collector over TLS, a tls one without its CA
// and an mtls one without the client certificate. Plaintext needs the
// development guard; mtls rotates with w.
func (w *workloadIdentity) otlpCredentials(t config.ClientTLS, development bool, log *slog.Logger) (otlptracegrpc.Option, error) {
	const name = "telemetry.otlp_tls"
	switch t.Mode {
	case "development":
		if !development {
			return nil, fmt.Errorf("%s: development mode without development.enabled", name)
		}
		log.Warn("DEVELOPMENT_ONLY plaintext transport", "connection", name)
		return otlptracegrpc.WithInsecure(), nil
	case "tls":
		pool, err := caPool(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return otlptracegrpc.WithTLSCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool, ServerName: t.ServerName, MinVersion: tls.VersionTLS13})), nil
	case "mtls":
		r, err := w.reloaderFor(identity.Files{CertFile: t.CertFile, KeyFile: t.KeyFile, CAFile: t.CAFile})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		creds, err := identity.NewClientCredentials(r, t.ServerName)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return otlptracegrpc.WithTLSCredentials(creds), nil
	}
	return nil, fmt.Errorf("%s: unknown mode %q", name, t.Mode)
}

// clientTLSConfig is the tls.Config of a generation's NATS connection under
// a tls or mtls ClientTLS section: the bundle read once, the client
// certificate following its files on every handshake under mtls. The mtls
// Reloader (nil under tls; polling at interval) is returned unstarted and
// belongs to the caller, which polls it while the generation is active and
// stops it on retirement.
func clientTLSConfig(name string, t config.ClientTLS, interval time.Duration, log *slog.Logger) (*tls.Config, *identity.Reloader, error) {
	switch t.Mode {
	case "tls":
		pool, err := caPool(t.CAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		return &tls.Config{RootCAs: pool, ServerName: t.ServerName, MinVersion: tls.VersionTLS13}, nil, nil
	case "mtls":
		r, err := identity.New(identity.Files{CertFile: t.CertFile, KeyFile: t.KeyFile, CAFile: t.CAFile}, interval, log)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		return identity.ClientTLSConfig(r, t.ServerName), r, nil
	}
	return nil, nil, fmt.Errorf("%s: mode %q has no TLS configuration", name, t.Mode)
}

func caPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("ca bundle holds no certificate")
	}
	return pool, nil
}
