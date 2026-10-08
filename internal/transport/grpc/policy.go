package grpc

import (
	"strings"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity"
)

// The workloads that may call MCP (architecture.md communication matrix;
// docs/plans/0001 P0.1 allowlist). The namespace is part of the identity.
var (
	api              = identity.Workload{Namespace: "anvilkit-apps", ServiceAccount: "anvilkit-agent-api"}
	backgroundWorker = identity.Workload{Namespace: "anvilkit-apps", ServiceAccount: "anvilkit-agent-background-worker"}
	// mcp is the relay container of the MCP Pod (the Background Worker image
	// under the MCP ServiceAccount).
	mcp     = identity.Workload{Namespace: "anvilkit-apps", ServiceAccount: "anvilkit-agent-mcp"}
	sidecar = identity.Workload{Namespace: "anvilkit-components", ServiceAccount: "anvilkit-job-access-sidecar"}
)

// Policy is the method→principal allowlist of every RPC MCP can register.
// Catalog, Grant and Call services are registered only when their use
// cases exist; registeredOnly drops the entries of absent services so that
// the Authorizer's completeness check holds exactly for this build.
func Policy() identity.Policy {
	p := identity.Policy{}
	add := func(service string, methods []string, allowed ...identity.Workload) {
		for _, m := range methods {
			p["/anvilkit.mcp.v1."+service+"/"+m] = allowed
		}
	}
	add("CatalogService", []string{"ListCatalog", "GetDescriptor", "DiscoverServer", "ReviewDescriptor", "DisableDescriptor"}, api)
	add("GrantService", []string{"CreateGrant", "GetGrant", "ListGrants", "RevokeGrant", "GetRevocationProgress"}, api)
	add("CallService", []string{"CreateCall", "GetCall"}, api, sidecar)
	add("BackgroundTaskService", []string{"ClaimTask", "HeartbeatTask", "SubmitTaskResult", "GetTask"}, backgroundWorker, mcp)
	for _, m := range []string{"Check", "Watch", "List"} {
		p["/grpc.health.v1.Health/"+m] = []identity.Workload{identity.AnyAuthenticated}
	}
	return p
}

// registeredOnly keeps the entries whose service is registered.
func registeredOnly(p identity.Policy, services map[string]bool) identity.Policy {
	out := identity.Policy{}
	for method, allowed := range p {
		svc := strings.TrimPrefix(method, "/")
		svc = svc[:strings.Index(svc, "/")]
		if services[svc] {
			out[method] = allowed
		}
	}
	return out
}
