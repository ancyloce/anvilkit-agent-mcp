package grpc

import (
	"context"
	"strconv"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	mcpv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/mcp/v1"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// callServer adapts anvilkit.mcp.v1 CallService (DD-08 §3): CreateCall
// tracks the call and dispatches it once; GetCall only reads.
type callServer struct {
	mcpv1.UnimplementedCallServiceServer
	calls *application.Calls
}

var callStateTo = map[domain.CallState]mcpv1.CallState{
	domain.CallAccepted: mcpv1.CallState_CALL_STATE_ACCEPTED, domain.CallAdmitted: mcpv1.CallState_CALL_STATE_ADMITTED,
	domain.CallSent: mcpv1.CallState_CALL_STATE_SENT, domain.CallSucceeded: mcpv1.CallState_CALL_STATE_SUCCEEDED,
	domain.CallFailed: mcpv1.CallState_CALL_STATE_FAILED, domain.CallDenied: mcpv1.CallState_CALL_STATE_DENIED,
	domain.CallUnknown: mcpv1.CallState_CALL_STATE_UNKNOWN, domain.CallCanceled: mcpv1.CallState_CALL_STATE_CANCELED,
}

func toCall(c domain.Call) *mcpv1.ToolCall {
	out := &mcpv1.ToolCall{
		CallId: c.CallID, TenantId: c.TenantID, GrantId: c.GrantID, GrantRevision: strconv.FormatUint(c.GrantRevision, 10), ServerId: c.ServerID,
		Method: c.Method, ArgumentDigest: c.ArgumentDigest, State: callStateTo[c.State], CreatedAt: timestamppb.New(c.CreatedAt),
		UpdatedAt: timestamppb.New(c.UpdatedAt), Result: c.Result, DescriptorRevision: strconv.FormatUint(c.DescriptorRevision, 10),
		DescriptorDigest: c.DescriptorDigest, ProtocolVersion: c.ProtocolVersion,
	}
	if c.DispatchID != "" {
		out.ControlDispatchId = proto.String(c.DispatchID)
	}
	if c.ResultRef != "" {
		out.ResultRef, out.ResultDigest = proto.String(c.ResultRef), proto.String(c.ResultDigest)
	}
	if c.FailureCode != "" {
		out.FailureCode = proto.String(c.FailureCode)
	}
	return out
}

func (s *callServer) CreateCall(ctx context.Context, req *mcpv1.CreateCallRequest) (*mcpv1.CreateCallResponse, error) {
	rev, err := revisionOf(req.GetGrantRevision())
	if err != nil {
		return nil, toStatus(err)
	}
	epoch, err := revisionOf(req.GetExecutionEpoch())
	if err != nil {
		return nil, toStatus(err)
	}
	call, existing, err := s.calls.Create(ctx, cmdOf(req.GetCommand()), scopeOf(ctx, req.GetScope()), domain.CallRequest{
		GrantID: req.GetGrantId(), GrantRevision: rev, Method: req.GetMethod(), ArgumentRef: req.GetArgumentRef(), ArgumentDigest: req.GetArgumentDigest(),
		Arguments: req.GetArguments(), OperationID: req.GetOperationId(), AttemptID: req.GetAttemptId(), InstanceID: req.GetInstanceId(),
		ExecutionEpoch: epoch, Deadline: req.GetDeadline().AsTime(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.CreateCallResponse{Call: toCall(call), Existing: existing}, nil
}

func (s *callServer) GetCall(ctx context.Context, req *mcpv1.GetCallRequest) (*mcpv1.GetCallResponse, error) {
	call, err := s.calls.Get(ctx, scopeOf(ctx, req.GetScope()), req.GetCallId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.GetCallResponse{Call: toCall(call)}, nil
}
