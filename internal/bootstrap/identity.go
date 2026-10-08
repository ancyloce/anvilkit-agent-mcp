package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/config"
	grpctransport "github.com/ancyloce/anvilkit-agent-mcp/internal/transport/grpc"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity"
)

// workloadIdentity is the process's identity material (P0.1): the Reloader
// of grpc.identity's files, which the listener and the Control clients
// share, or nil under the DEVELOPMENT_ONLY plaintext listener.
type workloadIdentity struct {
	reloader *identity.Reloader
}

func newWorkloadIdentity(cfg config.Config, log *slog.Logger) (*workloadIdentity, error) {
	id := cfg.GRPC.Identity
	if id.Mode == "development" {
		log.Warn("DEVELOPMENT_ONLY listener identity: plaintext gRPC, no caller is authenticated or authorized; qualifies no production identity")
		return &workloadIdentity{}, nil
	}
	r, err := identity.New(identity.Files{CertFile: id.CertFile, KeyFile: id.KeyFile, CAFile: id.CAFile}, id.ReloadInterval, log)
	if err != nil {
		return nil, fmt.Errorf("grpc.identity: %w", err)
	}
	return &workloadIdentity{reloader: r}, nil
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
		r := w.reloader
		if r == nil || m.CertFile != cfg.GRPC.Identity.CertFile || m.KeyFile != cfg.GRPC.Identity.KeyFile || m.CAFile != cfg.GRPC.Identity.CAFile {
			var err error
			r, err = identity.New(identity.Files{CertFile: m.CertFile, KeyFile: m.KeyFile, CAFile: m.CAFile}, cfg.GRPC.Identity.ReloadInterval, log)
			if err != nil {
				return nil, fmt.Errorf("control.identity: %w", err)
			}
			r.Start()
		}
		creds, err := identity.NewClientCredentials(r, m.ServerName)
		if err != nil {
			return nil, fmt.Errorf("control.identity: %w", err)
		}
		return grpc.WithTransportCredentials(creds), nil
	}
	return nil, fmt.Errorf("control.identity.mode %q", cfg.Control.Identity.Mode)
}

// clientTransport is the gRPC transport credential of an outbound
// connection (OTLP) under a ClientTLS section.
func clientTransport(name string, t config.ClientTLS, development bool, log *slog.Logger) (grpc.DialOption, error) {
	switch t.Mode {
	case "development":
		if !development {
			return nil, fmt.Errorf("%s: development mode without development.enabled", name)
		}
		log.Warn("DEVELOPMENT_ONLY plaintext transport", "connection", name)
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	case "tls", "mtls":
		cfg, err := clientTLSConfig(name, t, log)
		if err != nil {
			return nil, err
		}
		return grpc.WithTransportCredentials(credentials.NewTLS(cfg)), nil
	}
	return nil, fmt.Errorf("%s: unknown mode %q", name, t.Mode)
}

// clientTLSConfig is the tls.Config of a tls or mtls ClientTLS section
// (NATS, OTLP): the bundle read once, the client certificate following its
// files on every handshake under mtls.
func clientTLSConfig(name string, t config.ClientTLS, log *slog.Logger) (*tls.Config, error) {
	switch t.Mode {
	case "tls":
		pool, err := caPool(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return &tls.Config{RootCAs: pool, ServerName: t.ServerName, MinVersion: tls.VersionTLS13}, nil
	case "mtls":
		r, err := identity.New(identity.Files{CertFile: t.CertFile, KeyFile: t.KeyFile, CAFile: t.CAFile}, 0, log)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		r.Start()
		return identity.ClientTLSConfig(r, t.ServerName), nil
	}
	return nil, fmt.Errorf("%s: mode %q has no TLS configuration", name, t.Mode)
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
