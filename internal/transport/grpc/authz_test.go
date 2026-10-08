package grpc_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	mcpv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/mcp/v1"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
	grpctransport "github.com/ancyloce/anvilkit-agent-mcp/internal/transport/grpc"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity/identitytest"
)

const td = "anvilkit.local"

type noTasks struct{}

func (noTasks) Claim(context.Context, string, uint64, string, time.Duration) (domain.Task, []byte, error) {
	panic("unreachable")
}
func (noTasks) Heartbeat(context.Context, string, uint64, string) (domain.Task, error) {
	panic("unreachable")
}
func (noTasks) Submit(context.Context, string, uint64, domain.Submission) (domain.SubmitDecision, error) {
	panic("unreachable")
}
func (noTasks) Get(context.Context, string) (domain.Task, error) { panic("unreachable") }

func mount(t *testing.T, ca *identitytest.CA, cn string, uris []string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), cn)
	identitytest.Mount(t, dir, ca.Issue(t, cn, uris, cn), ca.PEM)
	return dir
}

func reloader(t *testing.T, dir string) *identity.Reloader {
	t.Helper()
	cert, key, caFile := identitytest.Files(dir)
	r, err := identity.New(identity.Files{CertFile: cert, KeyFile: key, CAFile: caFile}, 0, nil)
	require.NoError(t, err)
	return r
}

// TestPolicyCoversEveryRegisteredMethod (P0.1 AC2): the server refuses to
// construct under an mTLS identity unless every registered RPC has an
// allowlist entry; the entries of services this build does not register
// (Catalog, Grant, Call without their use cases) are not stale.
func TestPolicyCoversEveryRegisteredMethod(t *testing.T) {
	ca := identitytest.NewCA(t, "ca")
	r := reloader(t, mount(t, ca, "anvilkit-agent-mcp", []string{identitytest.SPIFFE(td, "anvilkit-apps", "anvilkit-agent-mcp")}))
	build := func(p identity.Policy, calls *application.Calls) error {
		_, err := grpctransport.NewServerWithIdentity("127.0.0.1:0", &grpctransport.Identity{Reloader: r, TrustDomain: td, Policy: p}, 4, noTasks{}, nil, nil, calls)
		return err
	}
	require.NoError(t, build(grpctransport.Policy(), nil), "the reviewed policy covers every registered method of the owner-only build")
	require.NoError(t, build(grpctransport.Policy(), &application.Calls{}), "and of a build with CallService")
	partial := grpctransport.Policy()
	delete(partial, "/anvilkit.mcp.v1.BackgroundTaskService/ClaimTask")
	require.ErrorContains(t, build(partial, nil), "/anvilkit.mcp.v1.BackgroundTaskService/ClaimTask")
	optional := grpctransport.Policy()
	delete(optional, "/anvilkit.mcp.v1.CallService/CreateCall")
	require.NoError(t, build(optional, nil), "a missing entry of an unregistered service is not detected in this build")
	require.ErrorContains(t, build(optional, &application.Calls{}), "/anvilkit.mcp.v1.CallService/CreateCall")
}

// TestWorkloadAuthorizationBeforeHandlers (P0.1 AC2) runs the real server
// under a throwaway CA: an allowed workload reaches validation, an
// unauthorized workload of the same CA is refused before protovalidate or
// the handler, a plaintext dial never completes a handshake.
func TestWorkloadAuthorizationBeforeHandlers(t *testing.T) {
	ca := identitytest.NewCA(t, "ca")
	r := reloader(t, mount(t, ca, "anvilkit-agent-mcp", []string{identitytest.SPIFFE(td, "anvilkit-apps", "anvilkit-agent-mcp")}))
	srv, err := grpctransport.NewServerWithIdentity("127.0.0.1:0", &grpctransport.Identity{Reloader: r, TrustDomain: td, Policy: grpctransport.Policy()}, 4, noTasks{}, nil, nil, nil)
	require.NoError(t, err)
	addr, err := srv.Listen()
	require.NoError(t, err)
	srv.Serve()
	t.Cleanup(func() { srv.Stop(time.Second) })
	dial := func(dir string) *grpc.ClientConn {
		creds, err := identity.NewClientCredentials(reloader(t, dir), "anvilkit-agent-mcp")
		require.NoError(t, err)
		conn, err := grpc.NewClient(addr.String(), grpc.WithTransportCredentials(creds))
		require.NoError(t, err)
		t.Cleanup(func() { conn.Close() })
		return conn
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	worker := mcpv1.NewBackgroundTaskServiceClient(dial(mount(t, ca, "anvilkit-agent-background-worker", []string{identitytest.SPIFFE(td, "anvilkit-apps", "anvilkit-agent-background-worker")})))
	_, err = worker.ClaimTask(ctx, &mcpv1.ClaimTaskRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "the worker passes authorization and reaches validation: %v", err)
	relay := mcpv1.NewBackgroundTaskServiceClient(dial(mount(t, ca, "anvilkit-agent-mcp", []string{identitytest.SPIFFE(td, "anvilkit-apps", "anvilkit-agent-mcp")})))
	_, err = relay.GetTask(ctx, &mcpv1.GetTaskRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "the relay container is admitted: %v", err)
	api := mcpv1.NewBackgroundTaskServiceClient(dial(mount(t, ca, "anvilkit-agent-api", []string{identitytest.SPIFFE(td, "anvilkit-apps", "anvilkit-agent-api")})))
	_, err = api.ClaimTask(ctx, &mcpv1.ClaimTaskRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "the API may not claim background tasks: %v", err)
	sidecar := mcpv1.NewBackgroundTaskServiceClient(dial(mount(t, ca, "anvilkit-job-access-sidecar", []string{identitytest.SPIFFE(td, "anvilkit-components", "anvilkit-job-access-sidecar")})))
	_, err = sidecar.GetTask(ctx, &mcpv1.GetTaskRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)
	foreign := mcpv1.NewBackgroundTaskServiceClient(dial(mount(t, ca, "anvilkit-agent-background-worker", []string{identitytest.SPIFFE("other.invalid", "anvilkit-apps", "anvilkit-agent-background-worker")})))
	_, err = foreign.ClaimTask(ctx, &mcpv1.ClaimTaskRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "wrong trust domain: %v", err)
	noID := mcpv1.NewBackgroundTaskServiceClient(dial(mount(t, ca, "anvilkit-agent-background-worker", nil)))
	_, err = noID.ClaimTask(ctx, &mcpv1.ClaimTaskRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err), "no URI SAN: %v", err)
	_, err = grpc_health_v1.NewHealthClient(dial(mount(t, ca, "anvilkit-agent-api", []string{identitytest.SPIFFE(td, "anvilkit-apps", "anvilkit-agent-api")}))).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err, "health is open to any authenticated workload")
	plain, err := grpc.NewClient(addr.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	_, err = grpc_health_v1.NewHealthClient(plain).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	require.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
}
