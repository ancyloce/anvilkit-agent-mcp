package grpc

import (
	"context"
	"fmt"
	"strconv"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	mcpv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/mcp/v1"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// catalogServer and grantServer adapt anvilkit.mcp.v1 CatalogService and
// GrantService (DD-08 §1/§2) to the catalog and grant use cases. Money
// crosses the wire as decimal strings of minor units; revisions as
// canonical unsigned decimals.
type catalogServer struct {
	mcpv1.UnimplementedCatalogServiceServer
	catalog *application.Catalog
}

type grantServer struct {
	mcpv1.UnimplementedGrantServiceServer
	grants *application.Grants
}

var catalogStateTo = map[domain.CatalogState]mcpv1.CatalogState{
	domain.CatalogDiscovered: mcpv1.CatalogState_CATALOG_STATE_DISCOVERED, domain.CatalogReviewPending: mcpv1.CatalogState_CATALOG_STATE_REVIEW_PENDING,
	domain.CatalogApproved: mcpv1.CatalogState_CATALOG_STATE_APPROVED, domain.CatalogRejected: mcpv1.CatalogState_CATALOG_STATE_REJECTED,
	domain.CatalogDisabled: mcpv1.CatalogState_CATALOG_STATE_DISABLED,
}

var grantStateTo = map[domain.GrantState]mcpv1.GrantState{
	domain.GrantPending: mcpv1.GrantState_GRANT_STATE_PENDING, domain.GrantActive: mcpv1.GrantState_GRANT_STATE_ACTIVE,
	domain.GrantRevoking: mcpv1.GrantState_GRANT_STATE_REVOKING, domain.GrantRevoked: mcpv1.GrantState_GRANT_STATE_REVOKED,
	domain.GrantExpired: mcpv1.GrantState_GRANT_STATE_EXPIRED, domain.GrantRegistrationFailed: mcpv1.GrantState_GRANT_STATE_REGISTRATION_FAILED,
}

func money(m domain.Money) *mcpv1.Money {
	return &mcpv1.Money{Currency: m.Currency, Amount: strconv.FormatInt(m.Amount, 10)}
}

func moneyOf(m *mcpv1.Money) (domain.Money, error) {
	if m == nil {
		return domain.Money{}, fmt.Errorf("%w: money is required", domain.ErrInvalid)
	}
	n, err := strconv.ParseInt(m.GetAmount(), 10, 64)
	if err != nil {
		return domain.Money{}, fmt.Errorf("%w: amount %q", domain.ErrInvalid, m.GetAmount())
	}
	return domain.Money{Currency: m.GetCurrency(), Amount: n}, nil
}

func revisionOf(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: revision %q", domain.ErrInvalid, s)
	}
	return n, nil
}

func cmdOf(c *mcpv1.CommandIdentity) application.Command {
	return application.Command{TenantID: c.GetTenantId(), CommandID: c.GetCommandId(), ActorID: c.GetActorId(), RequestDigest: c.GetRequestDigest()}
}

func scopeOf(s *mcpv1.Scope) application.Scope {
	return application.Scope{TenantID: s.GetTenantId(), ProjectID: s.GetProjectId(), ActorID: s.GetActorId()}
}

func toDescriptor(d domain.Descriptor) *mcpv1.Descriptor {
	out := &mcpv1.Descriptor{
		ServerId: d.ServerID, Revision: strconv.FormatUint(d.Revision, 10), CanonicalResource: d.CanonicalResource, Transport: d.Transport,
		ProtocolVersion: d.ProtocolVersion, Provenance: d.Provenance, DescriptorDigest: d.Digest, State: catalogStateTo[d.State],
		CreatedAt: timestamppb.New(d.CreatedAt), UpdatedAt: timestamppb.New(d.UpdatedAt), ServerName: d.ServerName, ServerVersion: d.ServerVersion,
		ResourcesDigest: d.ResourcesDigest, PromptsDigest: d.PromptsDigest, DataClass: d.DataClass, NetworkScope: d.NetworkScope, Licenses: d.Licenses,
		RevisionEvidence: d.RevisionEvidence, DiscoveredBy: d.DiscoveredBy,
	}
	if d.ReviewID != "" {
		out.ReviewId = proto.String(d.ReviewID)
	}
	if d.Reviewer != "" {
		out.Reviewer = proto.String(d.Reviewer)
	}
	for _, t := range d.Tools {
		out.Tools = append(out.Tools, &mcpv1.ToolSchema{Method: t.Method, InputSchemaDigest: t.InputSchemaDigest, OutputSchemaDigest: t.OutputSchemaDigest,
			SideEffecting: t.SideEffecting, UnitPrice: money(t.UnitPrice), Idempotent: t.Idempotent, QuerySupported: t.QuerySupported, AnnotationsDigest: t.AnnotationsDigest})
	}
	return out
}

func toGrant(g domain.Grant) *mcpv1.Grant {
	out := &mcpv1.Grant{
		GrantId: g.GrantID, Revision: strconv.FormatUint(g.Revision, 10), TenantId: g.TenantID, SubjectType: g.SubjectType, SubjectId: g.SubjectID,
		ServerId: g.ServerID, DescriptorRevision: strconv.FormatUint(g.DescriptorRevision, 10), DescriptorDigest: g.DescriptorDigest, Methods: g.Methods,
		Purpose: g.Purpose, CostCap: money(g.CostCap), State: grantStateTo[g.State], CreatedAt: timestamppb.New(g.CreatedAt), UpdatedAt: timestamppb.New(g.UpdatedAt),
		CanonicalResource: g.CanonicalResource, Transport: g.Transport, ProtocolVersion: g.ProtocolVersion, Issuer: g.Issuer, Audience: g.Audience,
		ResourceSelectors: g.ResourceSelectors, PromptSelectors: g.PromptSelectors, DataClass: g.DataClass, PolicyDigest: g.PolicyDigest,
	}
	if g.PolicyEpoch != 0 {
		out.PolicyEpoch = strconv.FormatUint(g.PolicyEpoch, 10)
	}
	if g.ControlReceiptID != "" {
		out.ControlReceiptId = proto.String(g.ControlReceiptID)
	}
	if g.ExpiresAt != nil {
		out.ExpiresAt = timestamppb.New(*g.ExpiresAt)
	}
	if g.FailureCode != "" {
		out.FailureCode = proto.String(g.FailureCode)
	}
	return out
}

var catalogStateOf = map[mcpv1.CatalogState]string{
	mcpv1.CatalogState_CATALOG_STATE_DISCOVERED: "discovered", mcpv1.CatalogState_CATALOG_STATE_REVIEW_PENDING: "review_pending",
	mcpv1.CatalogState_CATALOG_STATE_APPROVED: "approved", mcpv1.CatalogState_CATALOG_STATE_REJECTED: "rejected", mcpv1.CatalogState_CATALOG_STATE_DISABLED: "disabled",
}

func (s *catalogServer) ListCatalog(ctx context.Context, req *mcpv1.ListCatalogRequest) (*mcpv1.ListCatalogResponse, error) {
	ds, next, err := s.catalog.List(ctx, scopeOf(req.GetScope()), catalogStateOf[req.GetState()], req.GetCursor(), int(req.GetLimit()))
	if err != nil {
		return nil, toStatus(err)
	}
	out := &mcpv1.ListCatalogResponse{NextCursor: next}
	for _, d := range ds {
		out.Descriptors = append(out.Descriptors, toDescriptor(d))
	}
	return out, nil
}

func (s *catalogServer) GetDescriptor(ctx context.Context, req *mcpv1.GetDescriptorRequest) (*mcpv1.GetDescriptorResponse, error) {
	rev, err := revisionOf(req.GetRevision())
	if err != nil {
		return nil, toStatus(err)
	}
	d, err := s.catalog.Get(ctx, scopeOf(req.GetScope()), req.GetServerId(), rev)
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.GetDescriptorResponse{Descriptor_: toDescriptor(d)}, nil
}

func (s *catalogServer) DiscoverServer(ctx context.Context, req *mcpv1.DiscoverServerRequest) (*mcpv1.DiscoverServerResponse, error) {
	decl := domain.Declaration{
		CanonicalResource: req.GetCanonicalResource(), Transport: req.GetTransport(), ProtocolVersion: req.GetProtocolVersion(), Provenance: req.GetProvenance(),
		ExpectedDigest: req.GetDescriptorDigest(), DataClass: req.GetDataClass(), NetworkScope: req.GetNetworkScope(), Licenses: req.GetLicenses(),
	}
	for _, t := range req.GetTools() {
		price, err := moneyOf(t.GetUnitPrice())
		if err != nil {
			return nil, toStatus(err)
		}
		decl.Tools = append(decl.Tools, domain.ToolDeclaration{Method: t.GetMethod(), InputSchemaDigest: t.GetInputSchemaDigest(), OutputSchemaDigest: t.GetOutputSchemaDigest(),
			SideEffecting: t.GetSideEffecting(), UnitPrice: price, Idempotent: t.GetIdempotent(), QuerySupported: t.GetQuerySupported()})
	}
	d, existing, err := s.catalog.Discover(ctx, cmdOf(req.GetCommand()), scopeOf(req.GetScope()), decl)
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.DiscoverServerResponse{Descriptor_: toDescriptor(d), Existing: existing}, nil
}

func (s *catalogServer) ReviewDescriptor(ctx context.Context, req *mcpv1.ReviewDescriptorRequest) (*mcpv1.ReviewDescriptorResponse, error) {
	rev, err := revisionOf(req.GetRevision())
	if err != nil {
		return nil, toStatus(err)
	}
	decision := domain.ReviewApprove
	if req.GetDecision() == mcpv1.ReviewDecision_REVIEW_DECISION_REJECT {
		decision = domain.ReviewReject
	}
	d, existing, err := s.catalog.Review(ctx, cmdOf(req.GetCommand()), scopeOf(req.GetScope()), req.GetServerId(), rev, req.GetDescriptorDigest(), decision, req.GetReasonCode())
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.ReviewDescriptorResponse{Descriptor_: toDescriptor(d), Existing: existing}, nil
}

func (s *catalogServer) DisableDescriptor(ctx context.Context, req *mcpv1.DisableDescriptorRequest) (*mcpv1.DisableDescriptorResponse, error) {
	rev, err := revisionOf(req.GetRevision())
	if err != nil {
		return nil, toStatus(err)
	}
	d, existing, err := s.catalog.Disable(ctx, cmdOf(req.GetCommand()), scopeOf(req.GetScope()), req.GetServerId(), rev, req.GetReasonCode())
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.DisableDescriptorResponse{Descriptor_: toDescriptor(d), Existing: existing}, nil
}

func (s *grantServer) CreateGrant(ctx context.Context, req *mcpv1.CreateGrantRequest) (*mcpv1.CreateGrantResponse, error) {
	rev, err := revisionOf(req.GetDescriptorRevision())
	if err != nil {
		return nil, toStatus(err)
	}
	capMoney, err := moneyOf(req.GetCostCap())
	if err != nil {
		return nil, toStatus(err)
	}
	gr := domain.GrantRequest{SubjectType: req.GetSubjectType(), SubjectID: req.GetSubjectId(), ServerID: req.GetServerId(), DescriptorRev: rev,
		DescriptorDigest: req.GetDescriptorDigest(), Methods: req.GetMethods(), ResourceSelectors: req.GetResourceSelectors(), PromptSelectors: req.GetPromptSelectors(),
		Purpose: req.GetPurpose(), DataClass: req.GetDataClass(), CostCap: capMoney}
	if req.GetExpiresAt() != nil {
		at := req.GetExpiresAt().AsTime()
		gr.ExpiresAt = &at
	}
	g, existing, err := s.grants.Create(ctx, cmdOf(req.GetCommand()), scopeOf(req.GetScope()), gr)
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.CreateGrantResponse{Grant: toGrant(g), Existing: existing}, nil
}

func (s *grantServer) GetGrant(ctx context.Context, req *mcpv1.GetGrantRequest) (*mcpv1.GetGrantResponse, error) {
	g, err := s.grants.Get(ctx, scopeOf(req.GetScope()), req.GetGrantId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.GetGrantResponse{Grant: toGrant(g)}, nil
}

var grantStateOf = map[mcpv1.GrantState]string{
	mcpv1.GrantState_GRANT_STATE_PENDING: "pending", mcpv1.GrantState_GRANT_STATE_ACTIVE: "active", mcpv1.GrantState_GRANT_STATE_REVOKING: "revoking",
	mcpv1.GrantState_GRANT_STATE_REVOKED: "revoked", mcpv1.GrantState_GRANT_STATE_EXPIRED: "expired", mcpv1.GrantState_GRANT_STATE_REGISTRATION_FAILED: "registration_failed",
}

func (s *grantServer) ListGrants(ctx context.Context, req *mcpv1.ListGrantsRequest) (*mcpv1.ListGrantsResponse, error) {
	gs, next, err := s.grants.List(ctx, scopeOf(req.GetScope()), grantStateOf[req.GetState()], req.GetCursor(), int(req.GetLimit()))
	if err != nil {
		return nil, toStatus(err)
	}
	out := &mcpv1.ListGrantsResponse{NextCursor: next}
	for _, g := range gs {
		out.Grants = append(out.Grants, toGrant(g))
	}
	return out, nil
}

func (s *grantServer) RevokeGrant(ctx context.Context, req *mcpv1.RevokeGrantRequest) (*mcpv1.RevokeGrantResponse, error) {
	rev, err := revisionOf(req.GetExpectedRevision())
	if err != nil {
		return nil, toStatus(err)
	}
	g, existing, err := s.grants.Revoke(ctx, cmdOf(req.GetCommand()), scopeOf(req.GetScope()), req.GetGrantId(), rev, req.GetReasonCode())
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.RevokeGrantResponse{Grant: toGrant(g), Existing: existing}, nil
}

func (s *grantServer) GetRevocationProgress(ctx context.Context, req *mcpv1.GetRevocationProgressRequest) (*mcpv1.GetRevocationProgressResponse, error) {
	p, err := s.grants.Progress(ctx, scopeOf(req.GetScope()), req.GetGrantId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.GetRevocationProgressResponse{
		Grant: toGrant(p.Grant), NewAdmissionBlocked: p.NewAdmissionBlocked, SendersConverged: p.SendersConverged,
		InFlightCalls: strconv.FormatUint(p.Grant.InFlightCalls, 10), UnknownCalls: strconv.FormatUint(p.Grant.UnknownCalls, 10),
		ControlState: p.Grant.ControlState, OpenCalls: strconv.FormatUint(p.OpenCalls, 10),
	}, nil
}
