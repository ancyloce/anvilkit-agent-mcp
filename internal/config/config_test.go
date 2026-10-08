package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const reviewed = "../../config.yaml"

// identityEnv places the mounted identity files (P0.1); the loader does
// not read them.
var identityEnv = []string{
	"ANVILKIT_MCP_IDENTITY_CERT_FILE=/etc/anvilkit/identity/tls.crt",
	"ANVILKIT_MCP_IDENTITY_KEY_FILE=/etc/anvilkit/identity/tls.key",
	"ANVILKIT_MCP_IDENTITY_CA_FILE=/etc/anvilkit/identity/ca.crt",
}

func TestLoadReviewedFile(t *testing.T) {
	g, err := LoadFrom(reviewed, append([]string{"ANVILKIT_MCP_DATABASE_URL=postgres://u:p@127.0.0.1:5432/anvilkit_mcp", "ANVILKIT_MCP_NATS_URL=nats://127.0.0.1:4222"}, identityEnv...), 1)
	if err != nil {
		t.Fatal(err)
	}
	if g.Config.Tasks.MaxAttempts != 3 || g.Config.GRPC.Listen != "127.0.0.1:9106" || g.Number != 1 || !strings.HasPrefix(g.Digest, "sha256:") {
		t.Fatalf("%+v", g)
	}
	if strings.Contains(g.Digest, "p@") || strings.Contains(g.Inputs(), "postgres://") {
		t.Fatal("digests never carry the secret")
	}
}

func TestRejections(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := append([]string{"ANVILKIT_MCP_DATABASE_URL=postgres://u:p@127.0.0.1:5432/anvilkit_mcp", "ANVILKIT_MCP_NATS_URL=nats://127.0.0.1:4222"}, identityEnv...)
	cases := []struct {
		name string
		file string
		env  []string
		want string
	}{
		{"unknown key", "grpc:\n  listen: 127.0.0.1:1\n  bogus: 1\n", base, "bogus"},
		{"mtls listener needs files", "development:\n  enabled: true\n", base[:2], "grpc.identity.cert_file, key_file and ca_file are required"},
		{"trust domain outside development", "{}\n", append([]string{}, base...), "grpc.identity.trust_domain is required outside development"},
		{"development listener needs the guard", "grpc:\n  identity:\n    mode: development\n    trust_domain: anvilkit.local\n", base, "grpc.identity.mode development (plaintext, no caller identity) requires development.enabled"},
		{"nats development needs the guard", "grpc:\n  identity:\n    trust_domain: anvilkit.local\noutbox:\n  nats:\n    tls:\n      mode: development\n", base, "outbox.nats.tls.mode development (plaintext) requires development.enabled"},
		{"nats tls needs the bundle", "grpc:\n  identity:\n    trust_domain: anvilkit.local\n", base, "outbox.nats.tls.ca_file is required"},
		{"control development needs the guard", "grpc:\n  identity:\n    trust_domain: anvilkit.local\noutbox:\n  nats:\n    tls:\n      ca_file: /ca\ncontrol:\n  identity:\n    mode: development\n", append(append([]string{}, base...), "ANVILKIT_MCP_CONTROL_ADDRESS=127.0.0.1:9101"), "control.identity.mode development (plaintext) requires development.enabled"},
		{"bad trust domain", "development:\n  enabled: true\ngrpc:\n  identity:\n    trust_domain: Not_Valid\n", base, "grpc.identity.trust_domain"},
		{"guard is file-only", "development:\n  enabled: true\n", append(append([]string{}, base...), "ANVILKIT_MCP_DEVELOPMENT_ENABLED=true"), "not allowed overrides"},
		{"health is not the business listener", "development:\n  enabled: true\nhealth:\n  listen: 127.0.0.1:9106\n", base, "health.listen must not be grpc.listen"},
		{"secret in file", "database:\n  url: postgres://x\n", base, "secret"},
		{"placement in file", "outbox:\n  nats:\n    url: nats://x\n", base, "placement"},
		{"unknown env", "{}\n", append(append([]string{}, base...), "ANVILKIT_MCP_SURPRISE=1"), "not allowed overrides"},
		{"missing secret", "{}\n", []string{"ANVILKIT_MCP_NATS_URL=nats://127.0.0.1:4222"}, "database.url is required"},
		{"cross-field sweep vs lease", "tasks:\n  max_lease: 1s\n  sweep_interval: 2s\n", base, "shorter than tasks.max_lease"},
		{"range", "tasks:\n  max_input_bytes: 70000\n", base, "max_input_bytes"},
		{"nats required with forwarder", "{}\n", []string{"ANVILKIT_MCP_DATABASE_URL=postgres://u:p@127.0.0.1:5432/anvilkit_mcp"}, "outbox.nats.url is required"},
		{"snapshot missing", "apollo:\n  mode: snapshot\n", base, "apollo snapshot"},
	}
	for _, c := range cases {
		_, err := LoadFrom(write(c.name+".yaml", c.file), c.env, 1)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}

func TestSecretFileAndApolloSnapshot(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "database-url")
	if err := os.WriteFile(secret, []byte("postgres://u:one@127.0.0.1:5432/anvilkit_mcp\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snapshot := filepath.Join(dir, "apollo.json")
	good := `{"schemaVersion":1,"appId":"anvilkit-agent-mcp","cluster":"default","namespace":"application","releaseKey":"20260917120000-0123456789ab","fetchedAt":"` + now.Format(time.RFC3339) + `","expiresAt":"` + now.Add(time.Hour).Format(time.RFC3339) + `","configurations":{"tasks.max_attempts":"5"}}`
	if err := os.WriteFile(snapshot, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(file, []byte("apollo:\n  mode: snapshot\noutbox:\n  nats:\n    tls:\n      ca_file: /etc/anvilkit/nats-ca/ca.crt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := append([]string{"ANVILKIT_MCP_DATABASE_URL_FILE=" + secret, "ANVILKIT_MCP_NATS_URL=nats://127.0.0.1:4222", "ANVILKIT_MCP_APOLLO_SNAPSHOT_FILE=" + snapshot, "ANVILKIT_MCP_IDENTITY_TRUST_DOMAIN=anvilkit.local"}, identityEnv...)
	g1, err := LoadFrom(file, env, 1)
	if err != nil {
		t.Fatal(err)
	}
	if g1.Config.Tasks.MaxAttempts != 5 || g1.ApolloRelease != "20260917120000-0123456789ab" || g1.Config.Database.URL != "postgres://u:one@127.0.0.1:5432/anvilkit_mcp" {
		t.Fatalf("%+v", g1.Config)
	}
	// The environment stays above the snapshot; a rotated secret changes only the secret revision.
	if err := os.WriteFile(secret, []byte("postgres://u:two@127.0.0.1:5432/anvilkit_mcp"), 0o600); err != nil {
		t.Fatal(err)
	}
	g2, err := LoadFrom(file, env, 2)
	if err != nil {
		t.Fatal(err)
	}
	if g2.Digest != g1.Digest || g2.SecretRevision == g1.SecretRevision || g2.Inputs() == g1.Inputs() {
		t.Fatal("secret rotation must change the secret revision and nothing else")
	}
	// Snapshot rejections: expired, wrong app, secret key, unknown field, bad release key.
	bad := map[string]string{
		"expired":     strings.Replace(good, `"expiresAt":"`+now.Add(time.Hour).Format(time.RFC3339), `"expiresAt":"`+now.Add(-time.Minute).Format(time.RFC3339), 1),
		"wrong app":   strings.Replace(good, "anvilkit-agent-mcp", "anvilkit-agent-control", 1),
		"secret key":  strings.Replace(good, `"tasks.max_attempts":"5"`, `"database.url":"postgres://x"`, 1),
		"unknown":     strings.Replace(good, `"schemaVersion":1,`, `"schemaVersion":1,"extra":true,`, 1),
		"release key": strings.Replace(good, "20260917120000-0123456789ab", "release-1", 1),
	}
	for name, content := range bad {
		if err := os.WriteFile(snapshot, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFrom(file, env, 3); err == nil {
			t.Errorf("%s: snapshot accepted", name)
		}
	}
}

func TestTelemetryPlacement(t *testing.T) {
	base := append([]string{"ANVILKIT_MCP_DATABASE_URL=postgres://u:p@127.0.0.1:5432/anvilkit_mcp", "ANVILKIT_MCP_NATS_URL=nats://127.0.0.1:4222"}, identityEnv...)
	g, err := LoadFrom(reviewed, append(append([]string{}, base...), "ANVILKIT_MCP_TELEMETRY_OTLP_ENDPOINT=collector:4317"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if g.Config.Telemetry.OTLPEndpoint != "collector:4317" || g.Config.Telemetry.SampleRatio != 1 {
		t.Fatalf("%+v", g.Config.Telemetry)
	}
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("telemetry:\n  sample_ratio: 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFrom(p, base, 1); err == nil || !strings.Contains(err.Error(), "telemetry.sample_ratio") {
		t.Fatalf("an out-of-range sample ratio is rejected, got %v", err)
	}
}

// TestIdentityDefaultsAndGuard (P0.1): the reviewed file keeps the listener
// and the Control clients on mTLS while the guard admits only the named
// plaintext development transports; the development trust domain applies
// only under the guard; the Control client inherits the listener's files.
func TestIdentityDefaultsAndGuard(t *testing.T) {
	base := append([]string{"ANVILKIT_MCP_DATABASE_URL=postgres://u:p@127.0.0.1:5432/anvilkit_mcp", "ANVILKIT_MCP_NATS_URL=nats://127.0.0.1:4222"}, identityEnv...)
	g, err := LoadFrom(reviewed, base, 1)
	if err != nil {
		t.Fatal(err)
	}
	c := g.Config
	if c.GRPC.Identity.Mode != "mtls" || c.Control.Identity.Mode != "mtls" || !c.Development.Enabled || c.Outbox.NATS.TLS.Mode != "development" || c.TrustDomain() != "anvilkit.local" {
		t.Fatalf("%+v", c)
	}
	if m := c.ControlMTLS(); m.CertFile != "/etc/anvilkit/identity/tls.crt" || m.ServerName != "anvilkit-agent-control" {
		t.Fatalf("control inherits the listener's files: %+v", m)
	}
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte("grpc:\n  identity:\n    trust_domain: prod.example\noutbox:\n  nats:\n    tls:\n      ca_file: /etc/anvilkit/nats-ca/ca.crt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err = LoadFrom(p, base, 1)
	if err != nil {
		t.Fatalf("production shape without the guard: %v", err)
	}
	if g.Config.Development.Enabled || g.Config.TrustDomain() != "prod.example" {
		t.Fatalf("%+v", g.Config)
	}
}
