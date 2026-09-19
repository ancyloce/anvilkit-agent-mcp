// Package grpc is MCP's grpc-go transport (A03) for the owner surfaces of
// P14: BackgroundTaskService. Requests are validated by protovalidate
// before any handler runs; domain errors map to the public codes of
// contracts.md §4. The listener is plaintext (DEVELOPMENT_ONLY; workload
// mTLS is ENV-03), like the other new services.
package grpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	mcpv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/mcp/v1"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// Tasks is the owner surface the transport needs.
type Tasks interface {
	Claim(ctx context.Context, taskID string, generation uint64, workerID string, lease time.Duration) (domain.Task, []byte, error)
	Heartbeat(ctx context.Context, taskID string, generation uint64, workerID string) (domain.Task, error)
	Submit(ctx context.Context, taskID string, generation uint64, sub domain.Submission) (domain.SubmitDecision, error)
	Get(ctx context.Context, taskID string) (domain.Task, error)
}

type Server struct {
	grpc   *grpc.Server
	health *health.Server
	listen string
	ln     net.Listener
}

func NewServer(listen string, capacity int, tasks Tasks) (*Server, error) {
	validator, err := protovalidate.New()
	if err != nil {
		return nil, err
	}
	slots := make(chan struct{}, capacity)
	s := grpc.NewServer(grpc.ChainUnaryInterceptor(bounded(slots), validateUnary(validator)))
	h := health.NewServer()
	grpc_health_v1.RegisterHealthServer(s, h)
	mcpv1.RegisterBackgroundTaskServiceServer(s, &backgroundServer{tasks: tasks})
	h.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	return &Server{grpc: s, health: h, listen: listen}, nil
}

// bounded is the explicit concurrency limit of the listener (A14): a call
// beyond capacity is refused with CAPACITY_EXHAUSTED instead of queueing.
func bounded(slots chan struct{}) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			return handler(ctx, req)
		default:
			return nil, status.Error(codes.ResourceExhausted, "CAPACITY_EXHAUSTED")
		}
	}
}

func validateUnary(v protovalidate.Validator) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if msg, ok := req.(proto.Message); ok {
			if err := v.Validate(msg); err != nil {
				return nil, status.Error(codes.InvalidArgument, "INVALID_ARGUMENT: "+err.Error())
			}
		}
		return handler(ctx, req)
	}
}

// Listen binds the listener without serving (startup unwinds a failed bind
// before anything else runs).
func (s *Server) Listen() (net.Addr, error) {
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", s.listen, err)
	}
	s.ln = ln
	return ln.Addr(), nil
}

// Serve starts serving on the bound listener; readiness turns SERVING.
func (s *Server) Serve() {
	go func() { _ = s.grpc.Serve(s.ln) }()
	s.health.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
}

// Withdraw turns readiness off without stopping in-flight calls.
func (s *Server) Withdraw() {
	s.health.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
}

// Stop drains in-flight calls within the timeout, then forces the stop
// (DD-09 §3); it reports whether force was needed.
func (s *Server) Stop(timeout time.Duration) (forced bool) {
	s.Withdraw()
	done := make(chan struct{})
	go func() { s.grpc.GracefulStop(); close(done) }()
	select {
	case <-done:
		return false
	case <-time.After(timeout):
		s.grpc.Stop()
		return true
	}
}

// Close releases a bound but never-served listener.
func (s *Server) Close() {
	if s.ln != nil {
		_ = s.ln.Close()
	}
}

type backgroundServer struct {
	mcpv1.UnimplementedBackgroundTaskServiceServer
	tasks Tasks
}

func toStatus(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, domain.ErrNotFound):
		return status.Error(codes.NotFound, "NOT_FOUND")
	case errors.Is(err, domain.ErrInvalid), errors.Is(err, domain.ErrInputTooLarge):
		return status.Error(codes.InvalidArgument, "INVALID_ARGUMENT: "+err.Error())
	case errors.Is(err, domain.ErrAlreadyClaimed), errors.Is(err, domain.ErrNotClaimable), errors.Is(err, domain.ErrDuplicateClaimID):
		return status.Error(codes.FailedPrecondition, "STALE_EXECUTION: "+err.Error())
	case errors.Is(err, domain.ErrStaleExecution):
		return status.Error(codes.FailedPrecondition, "STALE_EXECUTION: "+err.Error())
	case errors.Is(err, domain.ErrEffectUncertain):
		return status.Error(codes.FailedPrecondition, "EFFECT_UNCERTAIN: "+err.Error())
	case errors.Is(err, domain.ErrProfileUnknown):
		return status.Error(codes.FailedPrecondition, "PROFILE_UNQUALIFIED: "+err.Error())
	case errors.Is(err, application.ErrForbidden):
		return status.Error(codes.PermissionDenied, "FORBIDDEN: "+err.Error())
	case errors.Is(err, postgres.ErrDuplicateKey):
		return status.Error(codes.FailedPrecondition, "STALE_EXECUTION: concurrent claim")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	default:
		if _, ok := status.FromError(err); ok {
			return err
		}
		slog.Default().Error("unmapped mcp error", "error", err)
		return status.Error(codes.Unavailable, "DEPENDENCY_UNAVAILABLE")
	}
}

func parseGeneration(s string) (uint64, error) {
	var g uint64
	if _, err := fmt.Sscanf(s, "%d", &g); err != nil || g == 0 {
		return 0, fmt.Errorf("%w: generation %q", domain.ErrInvalid, s)
	}
	return g, nil
}

var stateOf = map[domain.TaskState]mcpv1.TaskState{
	domain.StatePending: mcpv1.TaskState_TASK_STATE_PENDING, domain.StateLeased: mcpv1.TaskState_TASK_STATE_LEASED,
	domain.StateResultSubmitted: mcpv1.TaskState_TASK_STATE_RESULT_SUBMITTED, domain.StateAccepted: mcpv1.TaskState_TASK_STATE_ACCEPTED,
	domain.StateRetryScheduled: mcpv1.TaskState_TASK_STATE_RETRY_SCHEDULED, domain.StateDead: mcpv1.TaskState_TASK_STATE_DEAD,
	domain.StateStale: mcpv1.TaskState_TASK_STATE_STALE, domain.StateCanceled: mcpv1.TaskState_TASK_STATE_CANCELED,
}

func toProto(t domain.Task) *mcpv1.BackgroundTask {
	p := &mcpv1.BackgroundTask{TaskId: t.TaskID, Generation: fmt.Sprintf("%d", t.Generation), TaskKind: t.Kind, InputDigest: t.InputDigest, State: stateOf[t.State], AttemptCount: fmt.Sprintf("%d", t.AttemptCount)}
	if t.WorkerID != "" {
		p.WorkerId = proto.String(t.WorkerID)
	}
	if t.State == domain.StateLeased && !t.LeaseUntil.IsZero() {
		p.LeaseUntil = timestamppb.New(t.LeaseUntil)
	}
	return p
}

func (b *backgroundServer) ClaimTask(ctx context.Context, req *mcpv1.ClaimTaskRequest) (*mcpv1.ClaimTaskResponse, error) {
	gen, err := parseGeneration(req.GetGeneration())
	if err != nil {
		return nil, toStatus(err)
	}
	task, input, err := b.tasks.Claim(ctx, req.GetTaskId(), gen, req.GetWorkerId(), time.Duration(req.GetLeaseSeconds())*time.Second)
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.ClaimTaskResponse{Task: toProto(task), Input: input}, nil
}

func (b *backgroundServer) HeartbeatTask(ctx context.Context, req *mcpv1.HeartbeatTaskRequest) (*mcpv1.HeartbeatTaskResponse, error) {
	gen, err := parseGeneration(req.GetGeneration())
	if err != nil {
		return nil, toStatus(err)
	}
	task, err := b.tasks.Heartbeat(ctx, req.GetTaskId(), gen, req.GetWorkerId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.HeartbeatTaskResponse{Task: toProto(task)}, nil
}

func (b *backgroundServer) SubmitTaskResult(ctx context.Context, req *mcpv1.SubmitTaskResultRequest) (*mcpv1.SubmitTaskResultResponse, error) {
	gen, err := parseGeneration(req.GetGeneration())
	if err != nil {
		return nil, toStatus(err)
	}
	d, err := b.tasks.Submit(ctx, req.GetTaskId(), gen, domain.Submission{
		WorkerID: req.GetWorkerId(), InputDigest: req.GetInputDigest(), Succeeded: req.GetSucceeded(), ResultRef: req.GetResultRef(), ResultDigest: req.GetResultDigest(), FailureCode: req.GetFailureCode(),
	})
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.SubmitTaskResultResponse{Task: toProto(d.Task), Accepted: d.Accepted, Existing: d.Existing}, nil
}

func (b *backgroundServer) GetTask(ctx context.Context, req *mcpv1.GetTaskRequest) (*mcpv1.GetTaskResponse, error) {
	task, err := b.tasks.Get(ctx, req.GetTaskId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &mcpv1.GetTaskResponse{Task: toProto(task)}, nil
}
