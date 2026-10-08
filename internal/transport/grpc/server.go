// Package grpc is MCP's grpc-go transport (A03) for the owner surfaces of
// P14: BackgroundTaskService. Requests are validated by protovalidate
// before any handler runs; domain errors map to the public codes of
// contracts.md §4. Under an Identity the listener is mTLS-only and every
// RPC is authorized by the peer's workload identity (P0.1); without one it
// is the DEVELOPMENT_ONLY plaintext listener that authorizes nothing.
package grpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"buf.build/go/protovalidate"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	mcpv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/mcp/v1"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/contextforge"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/transport/identity"
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

// Identity is the listener's transport: with a Reloader the server is
// mTLS-only (TLS 1.3, client certificates required and verified against the
// current bundle, every RPC authorized by the peer's workload identity
// under TrustDomain through Policy); nil is the DEVELOPMENT_ONLY plaintext
// listener the configuration loader admits only under development.enabled.
type Identity struct {
	Reloader         *identity.Reloader
	TrustDomain      string
	Policy           identity.Policy
	MaxConnectionAge time.Duration
}

// NewServer is the development (plaintext) listener.
func NewServer(listen string, capacity int, tasks Tasks, catalog *application.Catalog, grants *application.Grants, calls *application.Calls) (*Server, error) {
	return NewServerWithIdentity(listen, nil, capacity, tasks, catalog, grants, calls)
}

// NewServerWithIdentity is NewServer with the listener identity.
func NewServerWithIdentity(listen string, id *Identity, capacity int, tasks Tasks, catalog *application.Catalog, grants *application.Grants, calls *application.Calls) (*Server, error) {
	validator, err := protovalidate.New()
	if err != nil {
		return nil, err
	}
	slots := make(chan struct{}, capacity)
	unary := []grpc.UnaryServerInterceptor{bounded(slots), validateUnary(validator)}
	var stream []grpc.StreamServerInterceptor
	var authz *identity.Authorizer
	// Spans carry the gRPC semantic attributes only (service, method, status
	// code; no messages or metadata) and continue the callers' traces.
	opts := []grpc.ServerOption{grpc.StatsHandler(otelgrpc.NewServerHandler())}
	if id != nil {
		if id.Reloader == nil {
			return nil, errors.New("identity: mtls needs loaded material")
		}
		authz, err = identity.NewAuthorizer(id.TrustDomain, id.Policy)
		if err != nil {
			return nil, err
		}
		// Authorization runs first: an unauthorized caller never reaches the
		// capacity slots or validation.
		unary = append([]grpc.UnaryServerInterceptor{authz.Unary()}, unary...)
		stream = append(stream, authz.Stream())
		age := id.MaxConnectionAge
		if age <= 0 {
			age = time.Hour
		}
		opts = append(opts, grpc.Creds(identity.NewServerCredentials(id.Reloader)), grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: age, MaxConnectionAgeGrace: 30 * time.Second}))
	}
	opts = append(opts, grpc.ChainUnaryInterceptor(unary...))
	if len(stream) > 0 {
		opts = append(opts, grpc.ChainStreamInterceptor(stream...))
	}
	s := grpc.NewServer(opts...)
	h := health.NewServer()
	grpc_health_v1.RegisterHealthServer(s, h)
	mcpv1.RegisterBackgroundTaskServiceServer(s, &backgroundServer{tasks: tasks})
	if catalog != nil && grants != nil {
		mcpv1.RegisterCatalogServiceServer(s, &catalogServer{catalog: catalog})
		mcpv1.RegisterGrantServiceServer(s, &grantServer{grants: grants})
	}
	if calls != nil {
		mcpv1.RegisterCallServiceServer(s, &callServer{calls: calls})
	}
	h.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	if id != nil {
		registered := map[string]bool{}
		for name := range s.GetServiceInfo() {
			registered[name] = true
		}
		scoped, err := identity.NewAuthorizer(id.TrustDomain, registeredOnly(id.Policy, registered))
		if err != nil {
			return nil, err
		}
		if err := scoped.Check(s); err != nil {
			return nil, err
		}
	}
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
	case errors.Is(err, application.ErrForbidden), errors.Is(err, domain.ErrForbidden):
		return status.Error(codes.PermissionDenied, "FORBIDDEN: "+err.Error())
	case errors.Is(err, domain.ErrCommandConflict):
		return status.Error(codes.AlreadyExists, "COMMAND_CONFLICT: "+err.Error())
	case errors.Is(err, domain.ErrDescriptorMismatch), errors.Is(err, domain.ErrRevisionMismatch), errors.Is(err, domain.ErrInvalidTransition):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, contextforge.ErrUpstream):
		return status.Error(codes.FailedPrecondition, "UPSTREAM_UNREACHABLE: "+err.Error())
	case errors.Is(err, contextforge.ErrUnavailable):
		return status.Error(codes.Unavailable, "DEPENDENCY_UNAVAILABLE")
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
