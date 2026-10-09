package grpc

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/peer"

	mcpv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/mcp/v1"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity"
)

// P0.3: a scope's roles are the user's verified roles only when the
// verified caller is the API workload.
func TestScopeRolesOnlyFromTheAPI(t *testing.T) {
	as := func(w identity.Workload) context.Context {
		p := identity.Principal{TrustDomain: "anvilkit.local", Namespace: w.Namespace, ServiceAccount: w.ServiceAccount}
		return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: identity.PeerInfo{Principal: p}})
	}
	s := &mcpv1.Scope{TenantId: "tenant_a", ProjectId: "proj_a", ActorId: "user_a", Roles: []string{"reviewer"}}
	require.Equal(t, []string{"reviewer"}, scopeOf(as(api), s).Roles)
	require.Empty(t, scopeOf(as(sidecar), s).Roles, "a Job's sidecar states no user roles")
	require.Empty(t, scopeOf(context.Background(), s).Roles, "an unverified connection states no user roles")
	require.Equal(t, "proj_a", scopeOf(as(sidecar), s).ProjectID)
}
