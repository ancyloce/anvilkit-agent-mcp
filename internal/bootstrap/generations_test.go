package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/config"
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
