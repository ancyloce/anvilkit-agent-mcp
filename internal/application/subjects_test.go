package application

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// P0.3: a grant issued to a role subject lets exactly the callers whose
// verified roles name it send; a scope without that role (or a caller whose
// roles the transport did not trust) cannot.
func TestCallerMaySendRoleSubject(t *testing.T) {
	grant := domain.Grant{SubjectType: "role", SubjectID: "reviewer"}
	require.True(t, callerMaySend(Scope{TenantID: "tenant_a", ActorID: "u", Roles: []string{"author", "reviewer"}}, grant))
	require.False(t, callerMaySend(Scope{TenantID: "tenant_a", ActorID: "u", Roles: []string{"author"}}, grant))
	require.False(t, callerMaySend(Scope{TenantID: "tenant_a", ActorID: "reviewer"}, grant), "an actor named like the role is not the role")
	require.True(t, callerMaySend(Scope{TenantID: "tenant_a", ProjectID: "p", ActorID: "u"}, domain.Grant{SubjectType: "project", SubjectID: "p"}))
	require.False(t, callerMaySend(Scope{TenantID: "tenant_a", ActorID: "u"}, domain.Grant{SubjectType: "unknown", SubjectID: "u"}))
}
