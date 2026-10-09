package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
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
	if err := os.WriteFile(secret, []byte("postgres://u:one@127.0.0.1:5432/anvilkit_mcp?sslmode=verify-full\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, _ := natsCredentials(t, dir)
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
	env := append([]string{"ANVILKIT_MCP_DATABASE_URL_FILE=" + secret, "ANVILKIT_MCP_NATS_URL=nats://127.0.0.1:4222", "ANVILKIT_MCP_NATS_CREDS_FILE=" + creds, "ANVILKIT_MCP_APOLLO_SNAPSHOT_FILE=" + snapshot, "ANVILKIT_MCP_IDENTITY_TRUST_DOMAIN=anvilkit.local"}, identityEnv...)
	g1, err := LoadFrom(file, env, 1)
	if err != nil {
		t.Fatal(err)
	}
	if g1.Config.Tasks.MaxAttempts != 5 || g1.ApolloRelease != "20260917120000-0123456789ab" || g1.Config.Database.URL != "postgres://u:one@127.0.0.1:5432/anvilkit_mcp?sslmode=verify-full" {
		t.Fatalf("%+v", g1.Config)
	}
	// The environment stays above the snapshot; a rotated secret changes only the secret revision.
	if err := os.WriteFile(secret, []byte("postgres://u:two@127.0.0.1:5432/anvilkit_mcp?sslmode=verify-full"), 0o600); err != nil {
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
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("grpc:\n  identity:\n    trust_domain: prod.example\noutbox:\n  nats:\n    tls:\n      ca_file: /etc/anvilkit/nats-ca/ca.crt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, _ := natsCredentials(t, dir)
	production := append([]string{"ANVILKIT_MCP_DATABASE_URL=postgres://u:p@db.example:5432/anvilkit_mcp?sslmode=verify-full", "ANVILKIT_MCP_NATS_URL=tls://nats.example:4222", "ANVILKIT_MCP_NATS_CREDS_FILE=" + creds}, identityEnv...)
	g, err = LoadFrom(p, production, 1)
	if err != nil {
		t.Fatalf("production shape without the guard: %v", err)
	}
	if g.Config.Development.Enabled || g.Config.TrustDomain() != "prod.example" {
		t.Fatalf("%+v", g.Config)
	}
}

// natsCredentials writes a NATS user .creds file and a bare NKey user seed
// (preceded by an empty line) of a fresh user key. The JWT is a placeholder:
// the loader classifies the file, the server verifies the JWT.
func natsCredentials(t *testing.T, dir string) (creds, seed string) {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := kp.Seed()
	if err != nil {
		t.Fatal(err)
	}
	creds, seed = filepath.Join(dir, "user.creds"), filepath.Join(dir, "user.nk")
	content := "-----BEGIN NATS USER JWT-----\neyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.e30.c2ln\n------END NATS USER JWT------\n\n" +
		"************************* IMPORTANT *************************\nNKEY Seed printed below can be used to sign and prove identity.\n\n" +
		"-----BEGIN USER NKEY SEED-----\n" + string(raw) + "\n------END USER NKEY SEED------\n"
	if err := os.WriteFile(creds, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seed, []byte("\n"+string(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return creds, seed
}

// TestNATSCredentialsAndTLSOverrides (P0.6): the NATS TLS section and the
// credential placement come from the environment; the credential is read
// and classified at load (a .creds file or a bare NKey seed, anything else
// rejected without echoing it), required outside development, optional but
// still used under the guard, and its rotation changes only the secret
// revision.
func TestNATSCredentialsAndTLSOverrides(t *testing.T) {
	dir := t.TempDir()
	creds, seed := natsCredentials(t, dir)
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	garbage := write("garbage", "\n  not-a-credential-SECRETVALUE\n")
	prod := write("prod.yaml", "grpc:\n  identity:\n    trust_domain: prod.example\n")
	base := append([]string{
		"ANVILKIT_MCP_DATABASE_URL=postgres://u:p@db.example:5432/anvilkit_mcp?sslmode=verify-full", "ANVILKIT_MCP_NATS_URL=tls://nats.example:4222",
		"ANVILKIT_MCP_NATS_TLS_MODE=mtls", "ANVILKIT_MCP_NATS_TLS_CA_FILE=/etc/anvilkit/nats/ca.crt", "ANVILKIT_MCP_NATS_TLS_CERT_FILE=/etc/anvilkit/nats/tls.crt",
		"ANVILKIT_MCP_NATS_TLS_KEY_FILE=/etc/anvilkit/nats/tls.key", "ANVILKIT_MCP_NATS_TLS_SERVER_NAME=nats.anvilkit-system.svc",
	}, identityEnv...)
	with := func(extra ...string) []string { return append(append([]string{}, base...), extra...) }

	g, err := LoadFrom(prod, with("ANVILKIT_MCP_NATS_CREDS_FILE="+creds), 1)
	if err != nil {
		t.Fatal(err)
	}
	n := g.Config.Outbox.NATS
	want := ClientTLS{Mode: "mtls", CAFile: "/etc/anvilkit/nats/ca.crt", CertFile: "/etc/anvilkit/nats/tls.crt", KeyFile: "/etc/anvilkit/nats/tls.key", ServerName: "nats.anvilkit-system.svc"}
	if n.TLS != want || n.CredsFile != creds || n.CredsKind != NATSCredsUser {
		t.Fatalf("environment overrides and classification: %+v", n)
	}
	gs, err := LoadFrom(prod, with("ANVILKIT_MCP_NATS_CREDS_FILE="+seed), 1)
	if err != nil {
		t.Fatal(err)
	}
	if gs.Config.Outbox.NATS.CredsKind != NATSCredsNKey {
		t.Fatalf("a bare seed is an NKey credential: %+v", gs.Config.Outbox.NATS)
	}
	// A rotated credential file changes the secret revision and nothing else.
	raw, err := os.ReadFile(creds)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(creds, []byte(strings.Replace(string(raw), ".e30.", ".e301.", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	g2, err := LoadFrom(prod, with("ANVILKIT_MCP_NATS_CREDS_FILE="+creds), 2)
	if err != nil {
		t.Fatal(err)
	}
	if g2.Digest != g.Digest || g2.SecretRevision == g.SecretRevision {
		t.Fatal("a credential rotation must change the secret revision and nothing else")
	}

	cases := []struct {
		name, file string
		env        []string
		want       string
	}{
		{"credential required outside development", prod, with(), "outbox.nats.creds_file is required outside development"},
		{"garbage", prod, with("ANVILKIT_MCP_NATS_CREDS_FILE=" + garbage), "outbox.nats.creds_file: neither a NATS user credentials file (.creds) nor an NKey user seed"},
		{"missing file", prod, with("ANVILKIT_MCP_NATS_CREDS_FILE=" + filepath.Join(dir, "absent")), "outbox.nats.creds_file: open"},
		{"placement in file", write("in-file.yaml", "outbox:\n  nats:\n    creds_file: "+creds+"\n"), with(), "placement"},
		{"plaintext outside development", prod, with("ANVILKIT_MCP_NATS_CREDS_FILE="+creds, "ANVILKIT_MCP_NATS_TLS_MODE=development"), "outbox.nats.tls.mode development (plaintext) requires development.enabled"},
		{"tls needs the bundle", prod, append(with("ANVILKIT_MCP_NATS_CREDS_FILE="+creds), "ANVILKIT_MCP_NATS_TLS_MODE=tls", "ANVILKIT_MCP_NATS_TLS_CA_FILE="), "outbox.nats.tls.ca_file is required"},
	}
	for _, c := range cases {
		_, err := LoadFrom(c.file, c.env, 1)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		} else if strings.Contains(err.Error(), "SECRETVALUE") {
			t.Errorf("%s: the credential content was echoed: %v", c.name, err)
		}
	}

	// Under the guard no credential is admitted, a mounted one is still
	// classified and used, a broken one is still rejected.
	dev := write("dev.yaml", "development:\n  enabled: true\noutbox:\n  nats:\n    tls:\n      mode: development\n")
	devEnv := append([]string{"ANVILKIT_MCP_DATABASE_URL=postgres://u:p@127.0.0.1:5432/anvilkit_mcp?sslmode=disable", "ANVILKIT_MCP_NATS_URL=nats://127.0.0.1:4222"}, identityEnv...)
	gd, err := LoadFrom(dev, devEnv, 1)
	if err != nil || gd.Config.Outbox.NATS.CredsFile != "" {
		t.Fatalf("development without a credential: %v", err)
	}
	gd, err = LoadFrom(dev, append(append([]string{}, devEnv...), "ANVILKIT_MCP_NATS_CREDS_FILE="+seed), 1)
	if err != nil || gd.Config.Outbox.NATS.CredsKind != NATSCredsNKey {
		t.Fatalf("development with a credential: %v %+v", err, gd.Config.Outbox.NATS)
	}
	if _, err := LoadFrom(dev, append(append([]string{}, devEnv...), "ANVILKIT_MCP_NATS_CREDS_FILE="+garbage), 1); err == nil {
		t.Fatal("a broken credential is rejected under the guard too")
	}
	// Without the forwarder there is no NATS connection and nothing to read.
	off := write("off.yaml", "grpc:\n  identity:\n    trust_domain: prod.example\noutbox:\n  forwarder_enabled: false\n")
	if _, err := LoadFrom(off, append([]string{"ANVILKIT_MCP_DATABASE_URL=postgres://u:p@db.example:5432/anvilkit_mcp?sslmode=verify-full"}, identityEnv...), 1); err != nil {
		t.Fatalf("forwarder disabled: %v", err)
	}
}

// TestDatabaseTLSPolicy (P0.6): outside development the database URL, from
// the environment or the mounted file, must verify the server
// (sslmode=verify-full); the error names the mode, never the URL.
// Development keeps the foundation's sslmode=disable.
func TestDatabaseTLSPolicy(t *testing.T) {
	dir := t.TempDir()
	creds, _ := natsCredentials(t, dir)
	prod := filepath.Join(dir, "prod.yaml")
	if err := os.WriteFile(prod, []byte("grpc:\n  identity:\n    trust_domain: prod.example\noutbox:\n  nats:\n    tls:\n      ca_file: /etc/anvilkit/nats/ca.crt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(extra ...string) []string {
		return append(append([]string{"ANVILKIT_MCP_NATS_URL=tls://nats.example:4222", "ANVILKIT_MCP_NATS_CREDS_FILE=" + creds}, identityEnv...), extra...)
	}
	const rule = "database.url: sslmode must be verify-full outside development"
	for dsn, want := range map[string]string{
		"postgres://u:hunter2@db.example:5432/anvilkit_mcp":                                     rule + ` (got "")`,
		"postgres://u:hunter2@db.example:5432/anvilkit_mcp?sslmode=disable":                     rule + ` (got "disable")`,
		"postgres://u:hunter2@db.example:5432/anvilkit_mcp?sslmode=require":                     rule + ` (got "require")`,
		"postgresql://u:hunter2@db.example:5432/anvilkit_mcp?sslmode=verify-ca":                 rule + ` (got "verify-ca")`,
		"host=db.example user=u password=hunter2 dbname=anvilkit_mcp sslmode=verify-full":       "database.url must be a postgres URL",
		"postgres://u:hunter2@db.example:5432/anvilkit_mcp?sslmode=verify-full&sslmode=disable": rule + ` (got "disable")`,
		"postgres://u:hunter2@db.example:5432/anvilkit_mcp?sslmode=disable&sslmode=verify-full": "",
		"postgres://u:hunter2@db.example:5432/anvilkit_mcp?sslmode=verify-full&ssl=true":        "database.url: the ssl parameter is not accepted outside development",
	} {
		_, err := LoadFrom(prod, env("ANVILKIT_MCP_DATABASE_URL="+dsn), 1)
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: %v", dsn, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: got %v, want %q", dsn, err, want)
		case err != nil && strings.Contains(err.Error(), "hunter2"):
			t.Errorf("the URL was echoed: %v", err)
		}
	}
	g, err := LoadFrom(prod, env("ANVILKIT_MCP_DATABASE_URL=postgresql://u:p@db.example:5432/anvilkit_mcp?sslmode=verify-full&sslrootcert=/etc/anvilkit/postgres-ca/ca.crt"), 1)
	if err != nil || g.Config.Development.Enabled {
		t.Fatalf("verify-full outside development: %v", err)
	}
	secret := filepath.Join(dir, "database-url")
	if err := os.WriteFile(secret, []byte("postgres://u:hunter2@db.example:5432/anvilkit_mcp?sslmode=disable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFrom(prod, env("ANVILKIT_MCP_DATABASE_URL_FILE="+secret), 1); err == nil || !strings.Contains(err.Error(), rule+` (got "disable")`) || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("the mounted URL follows the same rule: %v", err)
	}
	if _, err := LoadFrom(reviewed, append([]string{"ANVILKIT_MCP_DATABASE_URL=postgres://u:p@127.0.0.1:5432/anvilkit_mcp?sslmode=disable", "ANVILKIT_MCP_NATS_URL=nats://127.0.0.1:4222"}, identityEnv...), 1); err != nil {
		t.Fatalf("development keeps sslmode=disable: %v", err)
	}
}
