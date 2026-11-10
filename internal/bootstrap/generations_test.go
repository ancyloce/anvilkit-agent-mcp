package bootstrap

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/config"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity/identitytest"
)

// P1.2 (MCP-07): a candidate generation that changes a key a swap cannot
// apply is rejected by name; the sections a swap owns are reloadable.
func TestNonReloadableChanges(t *testing.T) {
	var active config.Config
	active.Catalog.AllowedHosts = []string{"api.example"}
	active.Calls.SendTimeout = 60
	active.Database.MaxConn = 4
	active.Tasks.MaxAttempts = 3

	same := active
	require.Empty(t, nonReloadableChanges(active, same))

	reloadable := active
	reloadable.Database.MaxConn = 8
	reloadable.Tasks.MaxAttempts = 5
	reloadable.Outbox.BatchSize = 99
	require.Empty(t, nonReloadableChanges(active, reloadable), "pool, forwarder and task bounds are what a generation swap applies")

	hosts := active
	hosts.Catalog.AllowedHosts = []string{"api.example", "other.example"}
	require.Equal(t, []string{"catalog"}, nonReloadableChanges(active, hosts))

	several := hosts
	several.Calls.QualifiedRoutes = []config.QualifiedRoute{{Resource: "https://api.example/mcp", ProtocolVersion: "2025-11-25", Transport: "streamable-http", Route: "go-sdk"}}
	several.Control.Address = "control:9101"
	several.GRPC.Capacity = 128
	require.Equal(t, []string{"calls", "catalog", "control", "grpc"}, nonReloadableChanges(active, several))
}

// A generation's NATS Reloader is its own: built unstarted (a rejected
// candidate leaves no poller), polled from activation and stopped at
// retirement. Before, every candidate started one that never stopped.
func TestGenerationOwnsItsNATSIdentity(t *testing.T) {
	ca := identitytest.NewCA(t, "ca")
	dir := filepath.Join(t.TempDir(), "nats")
	files := mountIdentity(t, ca, dir)
	_, r, err := clientTLSConfig("outbox.nats.tls", mtlsSection(files), testInterval, quietLog())
	require.NoError(t, err)
	require.NotNil(t, r)
	// The pool never connects: pgxpool dials lazily and no test query runs.
	pool, err := pgxpool.New(context.Background(), "postgres://mcp@127.0.0.1:1/mcp")
	require.NoError(t, err)
	rt := &runtime{pool: pool, natsIdentity: r}

	unchanged(t, r, rotate(t, ca, dir, r), "no polling before activation")

	rt.startForwarder(quietLog(), nil)
	before := rotate(t, ca, dir, r)
	require.Eventually(t, func() bool { return r.Current().Digest != before }, 5*time.Second, testInterval, "polled while active")

	require.False(t, rt.retire(time.Second, quietLog()))
	unchanged(t, r, rotate(t, ca, dir, r), "no polling after retirement")
}
