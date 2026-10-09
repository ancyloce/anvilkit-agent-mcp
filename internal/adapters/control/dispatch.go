// Package control is the owner's client of Control's DispatchService for
// the original-dispatch query of an expired external-effect lease (DD-02
// §4, DD-09 §1). Only CONFIRMED_NOT_SENT or DENIED release the lease;
// every other state, answer or error leaves it unreleased.
package control

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"

	"google.golang.org/protobuf/types/known/timestamppb"

	controlv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/control/v1"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// Owner is the dispatch owner identity this service presents (the sender
// recorded on MCP tool dispatches; DD-08).
const Owner = "anvilkit-agent-mcp"

type DispatchQuery struct {
	conn    *grpc.ClientConn
	client  controlv1.DispatchServiceClient
	timeout time.Duration
}

// Dial connects to Control with the given transport (the rotating workload
// credential, or plaintext under the development guard) without blocking;
// failures surface per query.
func Dial(address string, timeout time.Duration, transport grpc.DialOption) (*DispatchQuery, error) {
	conn, err := grpc.NewClient(address, grpc.WithStatsHandler(otelgrpc.NewClientHandler()), transport)
	if err != nil {
		return nil, fmt.Errorf("control %s: %w", address, err)
	}
	return &DispatchQuery{conn: conn, client: controlv1.NewDispatchServiceClient(conn), timeout: timeout}, nil
}

func (d *DispatchQuery) Close() error { return d.conn.Close() }

func (d *DispatchQuery) Outcome(ctx context.Context, tenantID, dispatchID string) (domain.DispatchOutcome, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	resp, err := d.client.GetDispatch(ctx, &controlv1.GetDispatchRequest{DispatchId: dispatchID, Owner: Owner, TenantId: tenantID})
	if err != nil {
		return domain.DispatchUnknown, err
	}
	switch resp.GetDispatch().GetState() {
	case controlv1.DispatchState_DISPATCH_STATE_CONFIRMED_NOT_SENT, controlv1.DispatchState_DISPATCH_STATE_DENIED:
		return domain.DispatchNotSent, nil
	case controlv1.DispatchState_DISPATCH_STATE_OBSERVED:
		return domain.DispatchSent, nil
	default:
		return domain.DispatchUnknown, nil
	}
}

// AdmitTool asks Control for the single-use permission of a tool call
// under the call's own identity (a repeated request answers the recorded
// dispatch and never a second permission).
func (d *DispatchQuery) AdmitTool(ctx context.Context, r application.ToolAdmit) (application.ToolAdmission, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	resp, err := d.client.AdmitTool(ctx, &controlv1.AdmitToolRequest{
		Command: &controlv1.CommandIdentity{TenantId: r.Command.TenantID, CommandId: r.Command.CommandID, ActorId: r.Command.ActorID, RequestDigest: r.Command.RequestDigest},
		Binding: &controlv1.ExecutionBinding{OperationId: r.OperationID, AttemptId: r.AttemptID, InstanceId: r.InstanceID, ExecutionEpoch: strconv.FormatUint(r.ExecutionEpoch, 10)},
		CallId:  r.CallID, Owner: Owner, GrantId: r.GrantID, GrantRevision: strconv.FormatUint(r.GrantRevision, 10), ServerId: r.ServerID, Method: r.Method,
		ArgumentDigest: r.ArgumentDigest, SideEffecting: r.SideEffecting,
		MaxExposure: &controlv1.Money{Currency: r.MaxExposure.Currency, Amount: strconv.FormatInt(r.MaxExposure.Amount, 10)}, Deadline: timestamppb.New(r.Deadline),
	})
	if err != nil {
		return application.ToolAdmission{}, err
	}
	a := resp.GetAdmission()
	return application.ToolAdmission{DispatchID: a.GetDispatch().GetDispatchId(), Allowed: a.GetDispatchAllowed(), DenialCode: a.GetDenialCode(), State: stateName(a.GetDispatch().GetState())}, nil
}

func stateName(s controlv1.DispatchState) string {
	return strings.ToLower(strings.TrimPrefix(s.String(), "DISPATCH_STATE_"))
}

var outcomes = map[string]controlv1.DispatchOutcome{
	application.OutcomeSucceeded: controlv1.DispatchOutcome_DISPATCH_OUTCOME_SUCCEEDED,
	application.OutcomeFailed:    controlv1.DispatchOutcome_DISPATCH_OUTCOME_FAILED,
	application.OutcomeCanceled:  controlv1.DispatchOutcome_DISPATCH_OUTCOME_CANCELED,
	application.OutcomeUnknown:   controlv1.DispatchOutcome_DISPATCH_OUTCOME_UNKNOWN,
}

// ObserveTool reports a call's outcome; a tool call's usage is its count of
// calls (input units), every other category zero.
func (d *DispatchQuery) ObserveTool(ctx context.Context, dispatchID string, sequence uint64, outcome string, units *uint64, at time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	req := &controlv1.ObserveDispatchRequest{DispatchId: dispatchID, Source: Owner, Sequence: strconv.FormatUint(sequence, 10), Outcome: outcomes[outcome], ObservedAt: timestamppb.New(at)}
	if units != nil {
		req.CumulativeUsage = &controlv1.Usage{InputUnits: strconv.FormatUint(*units, 10), OutputUnits: "0", ReasoningUnits: "0", CachedInputUnits: "0"}
	}
	_, err := d.client.ObserveDispatch(ctx, req)
	return err
}

// GetTool reads Control's record of a dispatch.
func (d *DispatchQuery) GetTool(ctx context.Context, tenantID, dispatchID string) (application.DispatchView, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	resp, err := d.client.GetDispatch(ctx, &controlv1.GetDispatchRequest{DispatchId: dispatchID, Owner: Owner, TenantId: tenantID})
	if err != nil {
		return application.DispatchView{}, err
	}
	v := application.DispatchView{State: stateName(resp.GetDispatch().GetState())}
	if o := resp.GetDispatch().GetOutcome(); o != controlv1.DispatchOutcome_DISPATCH_OUTCOME_UNSPECIFIED {
		v.Outcome = strings.ToLower(strings.TrimPrefix(o.String(), "DISPATCH_OUTCOME_"))
	}
	return v, nil
}
