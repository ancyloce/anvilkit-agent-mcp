package application

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

// Local marketplace authorization (A13, DD-08 §1): Casbin evaluates MCP's
// own rules only — which tenant role may discover, review, disable, read
// review-pending revisions, and create or revoke grants. Business
// authorization stays with Pagix and final effect admission with Control.
// The model and its policies are reviewed code; role bindings arrive from
// a mounted file (DEVELOPMENT_ONLY until the IdP's groups are the source,
// ENV-02). Reviewer and grant-manager roles are separated: one principal
// never holds both in a tenant, so the identity that approves a server's
// behavior never also hands out access to it.

// Actions checked by the transport before any use case runs.
const (
	ActCatalogDiscover    = "catalog.discover"
	ActCatalogReview      = "catalog.review"
	ActCatalogDisable     = "catalog.disable"
	ActCatalogReadPending = "catalog.read_pending"
	ActGrantCreate        = "grant.create"
	ActGrantRevoke        = "grant.revoke"
	ActGrantReadAll       = "grant.read_all"
)

// Roles a binding may name.
const (
	RoleCatalogManager  = "catalog_manager"
	RoleCatalogReviewer = "catalog_reviewer"
	RoleGrantManager    = "grant_manager"
)

const authzModel = `
[request_definition]
r = sub, dom, act

[policy_definition]
p = role, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.role, r.dom) && r.act == p.act
`

var authzPolicies = [][]string{
	{RoleCatalogManager, ActCatalogDiscover}, {RoleCatalogManager, ActCatalogDisable}, {RoleCatalogManager, ActCatalogReadPending},
	{RoleCatalogReviewer, ActCatalogReview}, {RoleCatalogReviewer, ActCatalogDisable}, {RoleCatalogReviewer, ActCatalogReadPending},
	{RoleGrantManager, ActGrantCreate}, {RoleGrantManager, ActGrantRevoke}, {RoleGrantManager, ActGrantReadAll},
}

// RoleBinding binds one actor of one tenant to one role.
type RoleBinding struct {
	TenantID string `json:"tenantId"`
	ActorID  string `json:"actorId"`
	Role     string `json:"role"`
}

// Authorizer answers whether an actor of a tenant may perform an action.
type Authorizer struct{ e *casbin.Enforcer }

// NewAuthorizer builds the enforcer from the reviewed model and policies
// and the bindings; an unknown role or a principal holding both the
// reviewer and the grant-manager role rejects the bindings.
func NewAuthorizer(bindings []RoleBinding) (*Authorizer, error) {
	m, err := model.NewModelFromString(authzModel)
	if err != nil {
		return nil, err
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, err
	}
	for _, p := range authzPolicies {
		if _, err := e.AddPolicy(p[0], p[1]); err != nil {
			return nil, err
		}
	}
	held := map[string][]string{}
	for _, b := range bindings {
		if b.TenantID == "" || b.ActorID == "" {
			return nil, fmt.Errorf("role binding without tenant or actor")
		}
		if !slices.Contains([]string{RoleCatalogManager, RoleCatalogReviewer, RoleGrantManager}, b.Role) {
			return nil, fmt.Errorf("role binding names an unknown role %q", b.Role)
		}
		key := b.TenantID + "\x00" + b.ActorID
		held[key] = append(held[key], b.Role)
		if slices.Contains(held[key], RoleCatalogReviewer) && slices.Contains(held[key], RoleGrantManager) {
			return nil, fmt.Errorf("actor %s of tenant %s would hold both %s and %s", b.ActorID, b.TenantID, RoleCatalogReviewer, RoleGrantManager)
		}
		if _, err := e.AddGroupingPolicy(b.ActorID, b.Role, b.TenantID); err != nil {
			return nil, err
		}
	}
	return &Authorizer{e: e}, nil
}

// LoadRoleBindings reads a JSON array of bindings; an empty path binds none.
func LoadRoleBindings(path string) ([]RoleBinding, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("role bindings: %w", err)
	}
	var out []RoleBinding
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("role bindings %s: %w", path, err)
	}
	return out, nil
}

// Allowed reports whether the actor of the tenant may perform the action.
func (a *Authorizer) Allowed(tenantID, actorID, action string) bool {
	if a == nil {
		return false
	}
	ok, err := a.e.Enforce(actorID, tenantID, action)
	return err == nil && ok
}

// Require is Allowed as an error (FORBIDDEN).
func (a *Authorizer) Require(tenantID, actorID, action string) error {
	if !a.Allowed(tenantID, actorID, action) {
		return fmt.Errorf("%w: %s may not %s in %s", ErrForbidden, actorID, action, tenantID)
	}
	return nil
}
