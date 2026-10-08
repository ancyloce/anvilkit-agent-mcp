package control

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/control/v1"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// PolicyClient is MCP's client of Control's GrantPolicyService (DD-08 §2):
// registration receipts and the revocation barrier. An answer Control
// decided (a refused, conflicting, invalid or unknown registration) is a
// definitive refusal; a transport failure, a timeout or an unavailable
// Control leaves the outcome unknown, and the caller reconciles under the
// same command identity.
type PolicyClient struct {
	conn    *grpc.ClientConn
	client  controlv1.GrantPolicyServiceClient
	timeout time.Duration
}

func DialPolicy(address string, timeout time.Duration, transport grpc.DialOption) (*PolicyClient, error) {
	conn, err := grpc.NewClient(address, grpc.WithStatsHandler(otelgrpc.NewClientHandler()), transport)
	if err != nil {
		return nil, fmt.Errorf("control %s: %w", address, err)
	}
	return &PolicyClient{conn: conn, client: controlv1.NewGrantPolicyServiceClient(conn), timeout: timeout}, nil
}

func (p *PolicyClient) Close() error { return p.conn.Close() }

func classify(err error) error {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Aborted, codes.InvalidArgument, codes.NotFound, codes.FailedPrecondition, codes.AlreadyExists:
		return fmt.Errorf("%w: %v", application.ErrRefused, err)
	}
	return err
}

func command(c application.ControlCommand) *controlv1.CommandIdentity {
	return &controlv1.CommandIdentity{TenantId: c.TenantID, CommandId: c.CommandID, ActorId: c.ActorID, RequestDigest: c.RequestDigest}
}

func (p *PolicyClient) Register(ctx context.Context, cmd application.ControlCommand, g domain.Grant) (string, uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req := &controlv1.RegisterPolicyRequest{
		Command: command(cmd), GrantId: g.GrantID, GrantRevision: strconv.FormatUint(g.Revision, 10), PolicyDigest: g.PolicyDigest,
		ServerId: g.ServerID, Methods: g.Methods, CostCap: &controlv1.Money{Currency: g.CostCap.Currency, Amount: strconv.FormatInt(g.CostCap.Amount, 10)},
	}
	if g.ExpiresAt != nil {
		req.ExpiresAt = timestamppb.New(*g.ExpiresAt)
	}
	resp, err := p.client.RegisterPolicy(ctx, req)
	if err != nil {
		return "", 0, classify(err)
	}
	epoch, err := strconv.ParseUint(resp.GetPolicyEpoch(), 10, 64)
	if err != nil || resp.GetReceiptId() == "" {
		return "", 0, fmt.Errorf("control answered a registration outside its contract")
	}
	return resp.GetReceiptId(), epoch, nil
}

func barrier(s *controlv1.RevocationStatus) (application.Barrier, error) {
	b := application.Barrier{}
	switch s.GetState() {
	case controlv1.RevocationState_REVOCATION_STATE_FENCED:
		b.State = "fenced"
	case controlv1.RevocationState_REVOCATION_STATE_CONVERGING:
		b.State = "converging"
	case controlv1.RevocationState_REVOCATION_STATE_CONVERGED:
		b.State = "converged"
	default:
		return b, fmt.Errorf("control answered revocation state %s", s.GetState())
	}
	var err error
	if b.InFlight, err = strconv.ParseUint(s.GetInFlightCalls(), 10, 64); err != nil {
		return b, fmt.Errorf("control answered in-flight calls %q", s.GetInFlightCalls())
	}
	if b.Unknown, err = strconv.ParseUint(s.GetUnknownCalls(), 10, 64); err != nil {
		return b, fmt.Errorf("control answered unknown calls %q", s.GetUnknownCalls())
	}
	if s.GetFencedAt() != nil {
		at := s.GetFencedAt().AsTime()
		b.FencedAt = &at
	}
	return b, nil
}

func (p *PolicyClient) BeginRevocation(ctx context.Context, cmd application.ControlCommand, grantID string, revision uint64) (application.Barrier, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	resp, err := p.client.BeginRevocation(ctx, &controlv1.BeginRevocationRequest{Command: command(cmd), GrantId: grantID, GrantRevision: strconv.FormatUint(revision, 10)})
	if err != nil {
		return application.Barrier{}, classify(err)
	}
	return barrier(resp.GetStatus())
}

func (p *PolicyClient) Revocation(ctx context.Context, grantID string, revision uint64) (application.Barrier, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	resp, err := p.client.GetRevocation(ctx, &controlv1.GetRevocationRequest{GrantId: grantID, GrantRevision: strconv.FormatUint(revision, 10)})
	if err != nil {
		return application.Barrier{}, classify(err)
	}
	return barrier(resp.GetStatus())
}
