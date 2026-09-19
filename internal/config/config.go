// Package config builds MCP's immutable configuration generations with
// koanf (A09, DD-09 §4). Precedence is defaults < the service's reviewed,
// secret-free configuration file < a validated, unexpired Apollo snapshot
// (non-secret keys only) < the allowlisted ANVILKIT_MCP_* environment
// overrides. A candidate is validated as a whole (unknown keys, required
// values, ranges, cross-field rules) and either becomes a complete
// generation or is rejected; nothing starts on a rejected candidate and no
// shared value is ever mutated field by field. The database URL is a
// secret: it arrives from the environment or from a mounted secret file
// (the OpenBao/CSI injection path) and is never accepted from the file,
// the snapshot or the logs.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const (
	envPrefix         = "ANVILKIT_MCP_"
	EnvConfigFile     = "ANVILKIT_MCP_CONFIG"
	DefaultConfigFile = "config.yaml"
)

// GRPC is the internal listener (BackgroundTaskService) and its bounds.
type GRPC struct {
	Listen          string        `koanf:"listen"`
	Capacity        int           `koanf:"capacity"`
	ShutdownTimeout time.Duration `koanf:"shutdown_timeout"`
}

// Health is the plaintext probe and metrics listener.
type Health struct {
	Listen string `koanf:"listen"`
}

// Database holds the app-role connection: URL (env-only) or URLFile, a
// mounted secret whose rotation produces a new generation.
type Database struct {
	URL     string `koanf:"url"`
	URLFile string `koanf:"url_file"`
	MaxConn int32  `koanf:"max_conn"`
}

// Tasks are the owner's reviewed bounds of the background lane
// (DEVELOPMENT_ONLY values until ENV-05 fixes them): the input bound of a
// ClaimTaskResponse, the longest lease, the retry delay and bound, the
// lease sweep interval and the reconstruction age the relay uses.
type Tasks struct {
	MaxInputBytes int           `koanf:"max_input_bytes"`
	MaxLease      time.Duration `koanf:"max_lease"`
	RetryDelay    time.Duration `koanf:"retry_delay"`
	MaxAttempts   uint32        `koanf:"max_attempts"`
	SweepInterval time.Duration `koanf:"sweep_interval"`
}

// Outbox is the forwarder module: the watermill-sql subscriber over the
// outbox/outbox_offsets tables and the JetStream publisher.
type Outbox struct {
	ForwarderEnabled bool          `koanf:"forwarder_enabled"`
	ConsumerGroup    string        `koanf:"consumer_group"`
	PollInterval     time.Duration `koanf:"poll_interval"`
	AckDeadline      time.Duration `koanf:"ack_deadline"`
	ResendInterval   time.Duration `koanf:"resend_interval"`
	BatchSize        int           `koanf:"batch_size"`
	NATS             NATS          `koanf:"nats"`
}

type NATS struct {
	URL            string        `koanf:"url"`
	PublishTimeout time.Duration `koanf:"publish_timeout"`
	Name           string        `koanf:"name"`
}

// Control is the placement of the original-dispatch query for
// external-effect leases (DD-09 §1); without an address the owner has no
// evidence and never reassigns such a lease.
type Control struct {
	Address string        `koanf:"address"`
	Timeout time.Duration `koanf:"timeout"`
}

// Apollo is the non-secret central configuration (A10): this build
// consumes a validated snapshot file (the reviewed export of a release;
// packages/profile-schemas/apollo-snapshot.schema.json) whose keys are
// koanf paths; an expired or invalid snapshot rejects the candidate.
type Apollo struct {
	Mode         string `koanf:"mode"`
	SnapshotFile string `koanf:"snapshot_file"`
	AppID        string `koanf:"app_id"`
}

const (
	ApolloDisabled     = "disabled"
	ApolloModeSnapshot = "snapshot"
)

// Reload governs the generation watcher: how often the secret file and the
// snapshot are re-read and how long a drained generation's clients may
// take to close.
type Reload struct {
	Interval   time.Duration `koanf:"interval"`
	DrainLimit time.Duration `koanf:"drain_limit"`
}

type Config struct {
	GRPC     GRPC     `koanf:"grpc"`
	Health   Health   `koanf:"health"`
	Database Database `koanf:"database"`
	Tasks    Tasks    `koanf:"tasks"`
	Outbox   Outbox   `koanf:"outbox"`
	Control  Control  `koanf:"control"`
	Apollo   Apollo   `koanf:"apollo"`
	Reload   Reload   `koanf:"reload"`
}

var defaults = map[string]any{
	"grpc.listen":                 "127.0.0.1:9106",
	"grpc.capacity":               64,
	"grpc.shutdown_timeout":       "20s",
	"health.listen":               "127.0.0.1:9116",
	"database.max_conn":           8,
	"tasks.max_input_bytes":       65536,
	"tasks.max_lease":             "10m",
	"tasks.retry_delay":           "5s",
	"tasks.max_attempts":          3,
	"tasks.sweep_interval":        "2s",
	"outbox.forwarder_enabled":    true,
	"outbox.consumer_group":       "anvilkit-agent-mcp-forwarder",
	"outbox.poll_interval":        "500ms",
	"outbox.ack_deadline":         "30s",
	"outbox.resend_interval":      "1s",
	"outbox.batch_size":           100,
	"outbox.nats.publish_timeout": "5s",
	"outbox.nats.name":            "anvilkit-agent-mcp",
	"control.timeout":             "5s",
	"apollo.mode":                 ApolloDisabled,
	"apollo.app_id":               "anvilkit-agent-mcp",
	"reload.interval":             "2s",
	"reload.drain_limit":          "30s",
}

// envOverrides is the complete set of accepted environment variables:
// deployment placement and the secrets. Any other ANVILKIT_MCP_* variable
// rejects the candidate.
var envOverrides = map[string]string{
	"ANVILKIT_MCP_LISTEN":               "grpc.listen",
	"ANVILKIT_MCP_HEALTH_LISTEN":        "health.listen",
	"ANVILKIT_MCP_DATABASE_URL":         "database.url",
	"ANVILKIT_MCP_DATABASE_URL_FILE":    "database.url_file",
	"ANVILKIT_MCP_NATS_URL":             "outbox.nats.url",
	"ANVILKIT_MCP_CONTROL_ADDRESS":      "control.address",
	"ANVILKIT_MCP_APOLLO_SNAPSHOT_FILE": "apollo.snapshot_file",
}

// secretKeys may only arrive through the environment or the secret file.
var secretKeys = []string{"database.url"}

// placementKeys are per-deployment values refused inside the reviewed file
// and inside a snapshot (they identify an environment, never a release).
var placementKeys = []string{"database.url_file", "outbox.nats.url", "control.address", "apollo.snapshot_file"}

// Generation is one complete, validated configuration: the typed snapshot,
// its number in this process, the digest of every non-secret input as
// merged, the revision of the secrets it was built with and the digests of
// the profiles it carries. Tasks freeze what they need from it at claim;
// the current generation only governs new admission.
type Generation struct {
	Number         uint64
	Config         Config
	Digest         string
	SecretRevision string
	Profiles       map[string]string
	ApolloRelease  string
	BuiltAt        time.Time
	ExpiresAt      time.Time
}

// Load builds the first generation from the process environment.
func Load() (Generation, error) {
	path := os.Getenv(EnvConfigFile)
	if path == "" {
		path = DefaultConfigFile
	}
	return LoadFrom(path, os.Environ(), 1)
}

// LoadFrom is Load with explicit inputs (tests and the reload watcher).
func LoadFrom(path string, environ []string, number uint64) (Generation, error) {
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(defaults, "."), nil); err != nil {
		return Generation{}, err
	}
	reviewed := koanf.New(".")
	if err := reviewed.Load(file.Provider(path), yaml.Parser()); err != nil {
		return Generation{}, fmt.Errorf("config file %s: %w", path, err)
	}
	for _, key := range append(append([]string{}, secretKeys...), placementKeys...) {
		if reviewed.Exists(key) {
			return Generation{}, fmt.Errorf("config file %s: %s is a secret or a placement and is accepted only from the environment", path, key)
		}
	}
	if err := k.Merge(reviewed); err != nil {
		return Generation{}, err
	}
	// The environment decides the Apollo snapshot placement, so it is read
	// first for that single key; the snapshot then sits below the rest of
	// the environment.
	env := koanf.New(".")
	if err := applyEnv(env, environ); err != nil {
		return Generation{}, err
	}
	release := ""
	var expiresAt time.Time
	mode := k.String("apollo.mode")
	if env.Exists("apollo.mode") {
		mode = env.String("apollo.mode")
	}
	snapshotFile := env.String("apollo.snapshot_file")
	if mode == ApolloModeSnapshot {
		snap, err := LoadApolloSnapshot(snapshotFile, k.String("apollo.app_id"), time.Now())
		if err != nil {
			return Generation{}, err
		}
		for key := range snap.Configurations {
			for _, forbidden := range append(append([]string{}, secretKeys...), placementKeys...) {
				if key == forbidden {
					return Generation{}, fmt.Errorf("apollo snapshot %s: %s is a secret or a placement and never comes from Apollo", snapshotFile, key)
				}
			}
		}
		values := make(map[string]any, len(snap.Configurations))
		for key, value := range snap.Configurations {
			values[key] = value
		}
		if err := k.Load(confmap.Provider(values, "."), nil); err != nil {
			return Generation{}, err
		}
		release = snap.ReleaseKey
		expiresAt, _ = time.Parse(time.RFC3339Nano, snap.ExpiresAt)
	}
	if err := k.Merge(env); err != nil {
		return Generation{}, err
	}
	var c Config
	if err := k.UnmarshalWithConf("", &c, koanf.UnmarshalConf{DecoderConfig: &mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.ComposeDecodeHookFunc(mapstructure.StringToTimeDurationHookFunc(), mapstructure.StringToTimeHookFunc(time.RFC3339)),
		ErrorUnused:      true,
		WeaklyTypedInput: true,
		Result:           &c,
	}}); err != nil {
		return Generation{}, fmt.Errorf("config: %w", err)
	}
	if c.Database.URL == "" && c.Database.URLFile != "" {
		raw, err := os.ReadFile(c.Database.URLFile)
		if err != nil {
			return Generation{}, fmt.Errorf("config: database.url_file: %w", err)
		}
		c.Database.URL = strings.TrimSpace(string(raw))
	}
	if err := c.validate(); err != nil {
		return Generation{}, err
	}
	digest, err := nonSecretDigest(k)
	if err != nil {
		return Generation{}, err
	}
	return Generation{
		Number: number, Config: c, Digest: digest, SecretRevision: secretRevision(c), Profiles: map[string]string{"local-check-v1": digestOf("local-check-v1")},
		ApolloRelease: release, BuiltAt: time.Now(), ExpiresAt: expiresAt,
	}, nil
}

// Inputs returns the values whose change produces a new generation: the
// digest of the non-secret inputs and the secret revision. The watcher
// compares them without holding either value in a log line.
func (g Generation) Inputs() string {
	return g.Digest + "/" + g.SecretRevision + "/" + g.ApolloRelease + "/" + g.ExpiresAt.Format(time.RFC3339Nano)
}

func applyEnv(k *koanf.Koanf, environ []string) error {
	var unknown []string
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, envPrefix) || name == EnvConfigFile {
			continue
		}
		key, ok := envOverrides[name]
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		if err := k.Set(key, value); err != nil {
			return err
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("config: environment variables are not allowed overrides: %s", strings.Join(unknown, ", "))
	}
	return nil
}

func nonSecretDigest(k *koanf.Koanf) (string, error) {
	all := k.All()
	for _, key := range secretKeys {
		delete(all, key)
	}
	raw, err := json.Marshal(all)
	if err != nil {
		return "", err
	}
	return digestOf(string(raw)), nil
}

func secretRevision(c Config) string {
	return digestOf("database.url=" + c.Database.URL)
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (c Config) validate() error {
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	check(c.GRPC.Listen != "", "grpc.listen is required")
	check(c.GRPC.Capacity > 0 && c.GRPC.Capacity <= 4096, "grpc.capacity must be within [1, 4096]")
	check(c.GRPC.ShutdownTimeout > 0 && c.GRPC.ShutdownTimeout <= 5*time.Minute, "grpc.shutdown_timeout must be within (0, 5m]")
	check(c.Health.Listen != "", "health.listen is required")
	check(c.Database.URL != "", "database.url is required (ANVILKIT_MCP_DATABASE_URL or ANVILKIT_MCP_DATABASE_URL_FILE)")
	if c.Database.URL != "" {
		u, err := url.Parse(c.Database.URL)
		check(err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql"), "database.url must be a postgres URL")
	}
	check(c.Database.MaxConn >= 1 && c.Database.MaxConn <= 256, "database.max_conn must be within [1, 256]")
	check(c.Tasks.MaxInputBytes > 0 && c.Tasks.MaxInputBytes <= 65536, "tasks.max_input_bytes must be within (0, 65536] (ClaimTaskResponse.input)")
	check(c.Tasks.MaxLease > 0 && c.Tasks.MaxLease <= time.Hour, "tasks.max_lease must be within (0, 1h] (ClaimTaskRequest.lease_seconds)")
	check(c.Tasks.RetryDelay >= 0 && c.Tasks.RetryDelay <= time.Hour, "tasks.retry_delay must be within [0, 1h]")
	check(c.Tasks.MaxAttempts >= 1 && c.Tasks.MaxAttempts <= 100, "tasks.max_attempts must be within [1, 100]")
	check(c.Tasks.SweepInterval > 0 && c.Tasks.SweepInterval <= time.Minute, "tasks.sweep_interval must be within (0, 1m]")
	check(c.Tasks.SweepInterval < c.Tasks.MaxLease, "tasks.sweep_interval must be shorter than tasks.max_lease")
	check(c.Outbox.ConsumerGroup != "", "outbox.consumer_group is required")
	check(c.Outbox.PollInterval > 0 && c.Outbox.PollInterval <= time.Minute, "outbox.poll_interval must be within (0, 1m]")
	check(c.Outbox.AckDeadline > 0 && c.Outbox.AckDeadline <= 5*time.Minute, "outbox.ack_deadline must be within (0, 5m]")
	check(c.Outbox.ResendInterval > 0 && c.Outbox.ResendInterval <= time.Minute, "outbox.resend_interval must be within (0, 1m]")
	check(c.Outbox.BatchSize >= 1 && c.Outbox.BatchSize <= 1000, "outbox.batch_size must be within [1, 1000]")
	check(!c.Outbox.ForwarderEnabled || c.Outbox.NATS.URL != "", "outbox.nats.url is required while the forwarder is enabled (ANVILKIT_MCP_NATS_URL)")
	if c.Outbox.NATS.URL != "" {
		u, err := url.Parse(c.Outbox.NATS.URL)
		check(err == nil && (u.Scheme == "nats" || u.Scheme == "tls"), "outbox.nats.url must be a nats:// or tls:// URL")
	}
	check(c.Outbox.NATS.PublishTimeout > 0 && c.Outbox.NATS.PublishTimeout <= time.Minute, "outbox.nats.publish_timeout must be within (0, 1m]")
	check(c.Control.Timeout > 0 && c.Control.Timeout <= time.Minute, "control.timeout must be within (0, 1m]")
	check(c.Apollo.Mode == ApolloDisabled || c.Apollo.Mode == ApolloModeSnapshot, "apollo.mode must be disabled or snapshot")
	check(c.Apollo.Mode != ApolloModeSnapshot || c.Apollo.SnapshotFile != "", "apollo.snapshot_file is required in snapshot mode (ANVILKIT_MCP_APOLLO_SNAPSHOT_FILE)")
	check(c.Apollo.AppID != "", "apollo.app_id is required")
	check(c.Reload.Interval > 0 && c.Reload.Interval <= time.Minute, "reload.interval must be within (0, 1m]")
	check(c.Reload.DrainLimit > 0 && c.Reload.DrainLimit <= 10*time.Minute, "reload.drain_limit must be within (0, 10m]")
	if len(errs) > 0 {
		return fmt.Errorf("config: %w", errors.Join(errs...))
	}
	return nil
}
