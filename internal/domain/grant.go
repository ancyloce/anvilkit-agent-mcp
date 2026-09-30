package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Grant rules (DD-08 §2): a grant revision binds tenant/subject, the
// canonical resource, issuer and audience, protocol/transport, the exact
// descriptor revision and digest, methods, resource/prompt selectors,
// purpose, data class, cost cap and expiry. The policy digest over all of
// them is what Control registers; the grant is executable only while it is
// ACTIVE, i.e. after Control's receipt and before its revocation commits.

// GrantState mirrors GrantState of anvilkit.mcp.v1 and the state column.
type GrantState string

const (
	GrantPending            GrantState = "pending"
	GrantActive             GrantState = "active"
	GrantRevoking           GrantState = "revoking"
	GrantRevoked            GrantState = "revoked"
	GrantExpired            GrantState = "expired"
	GrantRegistrationFailed GrantState = "registration_failed"
)

// Grant is one grant revision and its barrier state.
type Grant struct {
	GrantID            string
	Revision           uint64
	TenantID           string
	SubjectType        string
	SubjectID          string
	ServerID           string
	DescriptorRevision uint64
	DescriptorDigest   string
	CanonicalResource  string
	Transport          string
	ProtocolVersion    string
	Issuer             string
	Audience           string
	Methods            []string
	ResourceSelectors  []string
	PromptSelectors    []string
	Purpose            string
	DataClass          string
	CostCap            Money
	ExpiresAt          *time.Time
	PolicyDigest       string
	PolicyEpoch        uint64
	State              GrantState
	ControlReceiptID   string
	FailureCode        string
	RegistrationCmdID  string
	RevocationCmdID    string
	FencedAt           *time.Time
	InFlightCalls      uint64
	UnknownCalls       uint64
	ControlState       string // none | fenced | converging | converged
	RevokedAt          *time.Time
	CommandID          string
	RequestDigest      string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// GrantRequest is a CreateGrant command's content.
type GrantRequest struct {
	SubjectType       string
	SubjectID         string
	ServerID          string
	DescriptorRev     uint64
	DescriptorDigest  string
	Methods           []string
	ResourceSelectors []string
	PromptSelectors   []string
	Purpose           string
	DataClass         string
	CostCap           Money
	ExpiresAt         *time.Time
}

// NewGrant binds a request to an approved descriptor revision of the
// tenant's catalog. Every method, resource and prompt selector must exist
// in that exact revision; the data class may not exceed the descriptor's
// (empty takes the descriptor's); the expiry must lie in the future.
func NewGrant(tenantID, projectID string, req GrantRequest, d Descriptor, now time.Time) (Grant, error) {
	if d.TenantID != tenantID || d.ServerID != req.ServerID || d.Revision != req.DescriptorRev {
		return Grant{}, fmt.Errorf("%w: descriptor %s revision %d", ErrNotFound, req.ServerID, req.DescriptorRev)
	}
	if d.Digest != req.DescriptorDigest {
		return Grant{}, fmt.Errorf("%w: revision %d digests as %s", ErrDescriptorMismatch, d.Revision, d.Digest)
	}
	if d.State != CatalogApproved {
		return Grant{}, fmt.Errorf("%w: descriptor revision %d is %s", ErrForbidden, d.Revision, d.State)
	}
	switch req.SubjectType {
	case "tenant":
		if req.SubjectID != tenantID {
			return Grant{}, fmt.Errorf("%w: a tenant grant names the caller's tenant", ErrForbidden)
		}
	case "project":
		if projectID == "" || req.SubjectID != projectID {
			return Grant{}, fmt.Errorf("%w: a project grant names the caller's project", ErrForbidden)
		}
	case "actor", "role":
	default:
		return Grant{}, fmt.Errorf("%w: subject type %q", ErrInvalid, req.SubjectType)
	}
	methods := normalizeExact(req.Methods)
	if len(methods) == 0 || len(methods) != len(req.Methods) {
		return Grant{}, fmt.Errorf("%w: methods must be non-empty and unique", ErrInvalid)
	}
	for _, m := range methods {
		if _, ok := d.Method(m); !ok {
			return Grant{}, fmt.Errorf("%w: method %s is not in descriptor revision %d", ErrForbidden, m, d.Revision)
		}
	}
	names := func(xs []LiveNamed) []string {
		out := make([]string, 0, len(xs))
		for _, x := range xs {
			out = append(out, x.Name)
		}
		return out
	}
	resources, prompts := normalizeExact(req.ResourceSelectors), normalizeExact(req.PromptSelectors)
	for _, r := range resources {
		if !slices.Contains(names(d.Resources), r) {
			return Grant{}, fmt.Errorf("%w: resource %s is not in descriptor revision %d", ErrForbidden, r, d.Revision)
		}
	}
	for _, p := range prompts {
		if !slices.Contains(names(d.Prompts), p) {
			return Grant{}, fmt.Errorf("%w: prompt %s is not in descriptor revision %d", ErrForbidden, p, d.Revision)
		}
	}
	class := req.DataClass
	if class == "" {
		class = d.DataClass
	}
	if DataClassRank(class) < 0 || DataClassRank(class) > DataClassRank(d.DataClass) {
		return Grant{}, fmt.Errorf("%w: data class %q exceeds the descriptor's %s", ErrForbidden, class, d.DataClass)
	}
	if len(req.CostCap.Currency) != 3 || req.CostCap.Amount < 0 {
		return Grant{}, fmt.Errorf("%w: cost cap", ErrInvalid)
	}
	if req.ExpiresAt != nil {
		if !now.Before(*req.ExpiresAt) {
			return Grant{}, fmt.Errorf("%w: the grant would already be expired", ErrInvalid)
		}
		// The database keeps microseconds in UTC: the digest binds exactly
		// the instant that is stored and read back.
		exp := req.ExpiresAt.UTC().Truncate(time.Microsecond)
		req.ExpiresAt = &exp
	}
	if strings.TrimSpace(req.Purpose) == "" {
		return Grant{}, fmt.Errorf("%w: purpose", ErrInvalid)
	}
	g := Grant{
		Revision: 1, TenantID: tenantID, SubjectType: req.SubjectType, SubjectID: req.SubjectID, ServerID: d.ServerID, DescriptorRevision: d.Revision,
		DescriptorDigest: d.Digest, CanonicalResource: d.CanonicalResource, Transport: d.Transport, ProtocolVersion: d.ProtocolVersion, Issuer: d.Issuer,
		Audience: d.CanonicalResource, Methods: methods, ResourceSelectors: resources, PromptSelectors: prompts, Purpose: req.Purpose, DataClass: class,
		CostCap: req.CostCap, ExpiresAt: req.ExpiresAt, State: GrantPending, ControlState: "none",
	}
	return g, nil
}

// normalizeExact sorts and deduplicates; never nil (the columns are NOT NULL arrays).
func normalizeExact(xs []string) []string {
	out := append([]string{}, xs...)
	slices.Sort(out)
	return slices.Compact(out)
}

// dimensions are the security dimensions of a grant revision, in a fixed
// order: both the policy digest and the cache identity are built from them.
func (g Grant) dimensions() []string {
	exp := ""
	if g.ExpiresAt != nil {
		exp = g.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	return []string{
		"grant=" + g.GrantID, fmt.Sprintf("revision=%d", g.Revision), "tenant=" + g.TenantID, "subject=" + g.SubjectType + ":" + g.SubjectID,
		"server=" + g.ServerID, "resource=" + g.CanonicalResource, "issuer=" + g.Issuer, "audience=" + g.Audience,
		"protocol=" + g.ProtocolVersion, "transport=" + g.Transport, fmt.Sprintf("descriptor=%d@%s", g.DescriptorRevision, g.DescriptorDigest),
		"methods=" + strings.Join(g.Methods, ","), "resources=" + strings.Join(g.ResourceSelectors, ","), "prompts=" + strings.Join(g.PromptSelectors, ","),
		"purpose=" + g.Purpose, "dataClass=" + g.DataClass, fmt.Sprintf("costCap=%s:%d", g.CostCap.Currency, g.CostCap.Amount), "expires=" + exp,
	}
}

func digestLines(prefix string, lines []string) string {
	h := sha256.New()
	h.Write([]byte(prefix + "\n"))
	for _, l := range lines {
		// Length-prefixed so no value can shift a boundary.
		fmt.Fprintf(h, "%d:%s\n", len(l), l)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// PolicyDigest is the digest Control registers for this grant revision.
func (g Grant) ComputePolicyDigest() string {
	return digestLines("mcp-grant-policy-v1", g.dimensions())
}

// CacheKey is the identity of any credential or connection cached for this
// grant revision (DD-08 §2): every security dimension, never merely the URL
// or the tenant, so two grants that differ in any dimension never share an
// upstream token or connection.
func (g Grant) CacheKey() string { return digestLines("mcp-grant-cache-v1", g.dimensions()) }

// Executable reports whether new admission may use the grant at now: only an
// ACTIVE, unexpired revision with Control's receipt. PENDING (uncertain
// registration), REVOKING (the barrier has not converged), REVOKED,
// EXPIRED and REGISTRATION_FAILED never are.
func (g Grant) Executable(now time.Time) bool {
	return g.State == GrantActive && g.ControlReceiptID != "" && (g.ExpiresAt == nil || now.Before(*g.ExpiresAt))
}

// DigestBytes is the "sha256:<hex>" digest of bytes.
func DigestBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
