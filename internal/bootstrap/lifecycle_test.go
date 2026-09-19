package bootstrap_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	mcpv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/mcp/v1"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/bootstrap"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/testdb"
)

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	return ln.Addr().String()
}

func metric(t *testing.T, health, name string) string {
	t.Helper()
	resp, err := http.Get("http://" + health + "/metrics")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, name+" ") {
			return strings.TrimSpace(strings.TrimPrefix(line, name+" "))
		}
	}
	return ""
}

func readyStatus(health string) int {
	resp, err := http.Get("http://" + health + "/readyz")
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestLifecycleGenerationsAndShutdown starts the assembled service (forwarder
// disabled: NATS is the integration scenario's input) on a real database,
// rotates the database secret (the role's password changes and the mounted
// file follows), proves the new generation's pool serves while the old one
// drained, rejects a broken candidate without touching the active
// generation, and stops with the readiness withdrawn first and the drain
// recorded.
func TestLifecycleGenerationsAndShutdown(t *testing.T) {
	inst := testdb.Start(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "database-url")
	require.NoError(t, os.WriteFile(secret, []byte(inst.AppDSN), 0o600))
	cfgFile := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("outbox:\n  forwarder_enabled: false\nreload:\n  interval: 200ms\n  drain_limit: 5s\ntasks:\n  sweep_interval: 200ms\n"), 0o600))
	grpcAddr, healthAddr := freePort(t), freePort(t)
	t.Setenv("ANVILKIT_MCP_CONFIG", cfgFile)
	t.Setenv("ANVILKIT_MCP_DATABASE_URL_FILE", secret)
	t.Setenv("ANVILKIT_MCP_LISTEN", grpcAddr)
	t.Setenv("ANVILKIT_MCP_HEALTH_LISTEN", healthAddr)

	app := fx.New(bootstrap.Module(), fx.NopLogger)
	require.NoError(t, app.Err())
	require.NoError(t, app.Start(context.Background()))
	require.Equal(t, http.StatusOK, readyStatus(healthAddr))
	require.Equal(t, "1", metric(t, healthAddr, "anvilkit_mcp_config_generation"))

	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	hc := grpc_health_v1.NewHealthClient(conn)
	hr, err := hc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, hr.Status)
	tasks := mcpv1.NewBackgroundTaskServiceClient(conn)
	_, err = tasks.GetTask(context.Background(), &mcpv1.GetTaskRequest{TaskId: "missing"})
	require.Equal(t, codes.NotFound, status.Code(err))
	_, err = tasks.ClaimTask(context.Background(), &mcpv1.ClaimTaskRequest{TaskId: "x", Generation: "1", WorkerId: "w", LeaseSeconds: 0})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "protovalidate runs before the handler")

	// Secret rotation: the role's password changes, then the mounted file.
	// The old pool cannot authenticate new connections any more, so a served
	// call after the swap proves the new generation's pool is in use.
	admin, err := pgx.Connect(context.Background(), inst.AdminDSN)
	require.NoError(t, err)
	_, err = admin.Exec(context.Background(), "ALTER ROLE anvilkit_mcp_app PASSWORD 'rotated'")
	require.NoError(t, err)
	admin.Close(context.Background())
	rotated := strings.Replace(inst.AppDSN, ":app@", ":rotated@", 1)
	require.NoError(t, os.WriteFile(secret, []byte(rotated), 0o600))
	require.Eventually(t, func() bool { return metric(t, healthAddr, "anvilkit_mcp_config_generation") == "2" }, 10*time.Second, 100*time.Millisecond)
	require.Equal(t, "1", metric(t, healthAddr, "anvilkit_mcp_config_rotations_total"))
	for i := 0; i < 5; i++ {
		_, err = tasks.GetTask(context.Background(), &mcpv1.GetTaskRequest{TaskId: fmt.Sprintf("missing-%d", i)})
		require.Equal(t, codes.NotFound, status.Code(err), "served by the rotated generation")
	}

	// A broken candidate (a credential the database refuses) fails its probe
	// and is rejected; generation 2 stays and keeps serving.
	require.NoError(t, os.WriteFile(secret, []byte(strings.Replace(inst.AppDSN, ":app@", ":wrong@", 1)), 0o600))
	require.Eventually(t, func() bool {
		v := metric(t, healthAddr, "anvilkit_mcp_config_rejections_total")
		return v != "" && v != "0"
	}, 20*time.Second, 100*time.Millisecond)
	require.Equal(t, "2", metric(t, healthAddr, "anvilkit_mcp_config_generation"))
	_, err = tasks.GetTask(context.Background(), &mcpv1.GetTaskRequest{TaskId: "still"})
	require.Equal(t, codes.NotFound, status.Code(err))
	require.NoError(t, os.WriteFile(secret, []byte(rotated), 0o600))

	// Shutdown: readiness withdrawn, server drained, dependencies closed last.
	stopCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	require.NoError(t, app.Stop(stopCtx))
	require.Equal(t, 0, readyStatus(healthAddr), "health listener closed last")
	_, err = tasks.GetTask(context.Background(), &mcpv1.GetTaskRequest{TaskId: "after"})
	require.Error(t, err)
}

// TestStartupFailureUnwinds: an occupied gRPC port fails the start and
// leaves no health listener or loop behind.
func TestStartupFailureUnwinds(t *testing.T) {
	inst := testdb.Start(t)
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("outbox:\n  forwarder_enabled: false\n"), 0o600))
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer blocker.Close()
	healthAddr := freePort(t)
	t.Setenv("ANVILKIT_MCP_CONFIG", cfgFile)
	t.Setenv("ANVILKIT_MCP_DATABASE_URL", inst.AppDSN)
	t.Setenv("ANVILKIT_MCP_LISTEN", blocker.Addr().String())
	t.Setenv("ANVILKIT_MCP_HEALTH_LISTEN", healthAddr)
	app := fx.New(bootstrap.Module(), fx.NopLogger)
	require.NoError(t, app.Err())
	err = app.Start(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "listen")
	require.Equal(t, 0, readyStatus(healthAddr), "the health listener was unwound")
	ln, err := net.Listen("tcp", healthAddr)
	require.NoError(t, err, "the health port is free again")
	ln.Close()
}

func TestActiveSnapshotExpiryAndRenewal(t *testing.T) {
	inst := testdb.Start(t)
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	snapshot := filepath.Join(dir, "snapshot.json")
	require.NoError(t, os.WriteFile(cfgFile, []byte("apollo:\n  mode: snapshot\noutbox:\n  forwarder_enabled: false\nreload:\n  interval: 100ms\n  drain_limit: 2s\n"), 0600))
	document := func(expiry time.Time) []byte {
		return []byte(fmt.Sprintf(`{"schemaVersion":1,"appId":"anvilkit-agent-mcp","cluster":"default","namespace":"application","releaseKey":"20260918120000-0123456789ab","fetchedAt":%q,"expiresAt":%q,"configurations":{}}`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), expiry.UTC().Format(time.RFC3339Nano)))
	}
	require.NoError(t, os.WriteFile(snapshot, document(time.Now().Add(4*time.Second)), 0600))
	grpcAddr, healthAddr := freePort(t), freePort(t)
	t.Setenv("ANVILKIT_MCP_CONFIG", cfgFile)
	t.Setenv("ANVILKIT_MCP_DATABASE_URL", inst.AppDSN)
	t.Setenv("ANVILKIT_MCP_APOLLO_SNAPSHOT_FILE", snapshot)
	t.Setenv("ANVILKIT_MCP_LISTEN", grpcAddr)
	t.Setenv("ANVILKIT_MCP_HEALTH_LISTEN", healthAddr)
	app := fx.New(bootstrap.Module(), fx.NopLogger)
	require.NoError(t, app.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, app.Stop(context.Background())) })
	require.NoError(t, os.WriteFile(snapshot, []byte("invalid"), 0600))
	require.Eventually(t, func() bool { return metric(t, healthAddr, "anvilkit_mcp_config_rejections_total") != "0" }, 2*time.Second, 50*time.Millisecond)
	require.Equal(t, 200, readyStatus(healthAddr))
	require.Eventually(t, func() bool { return readyStatus(healthAddr) == 503 }, 6*time.Second, 50*time.Millisecond)
	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()
	_, err = mcpv1.NewBackgroundTaskServiceClient(conn).ClaimTask(context.Background(), &mcpv1.ClaimTaskRequest{TaskId: "expired", Generation: "1", WorkerId: "worker", LeaseSeconds: 10})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.NoError(t, os.WriteFile(snapshot, document(time.Now().Add(time.Minute)), 0600))
	require.Eventually(t, func() bool { return readyStatus(healthAddr) == 200 }, 5*time.Second, 50*time.Millisecond)
}
