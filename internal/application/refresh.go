package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres/sqlc"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// Catalog refresh (P2.5): the mcp-catalog-refresh background kind. On a
// schedule MCP requests one refresh per approved revision that an active
// grant can call, authorized by that grant. The Background Worker claims it
// and asks AdvanceRefresh; MCP itself re-reads the live server through its
// connection layer (the same route discovery took), rebuilds the descriptor
// from the reviewed declaration and records whether it still digests as the
// approved revision. The claimant submits exactly that record; acceptance
// of a drift disables the revision in the same transaction (its grants
// begin revocation), so a drifted server is withdrawn before a call meets
// the drift at the call-time lock.

// RefreshActor names the system actor of a refresh's disable decision.
const RefreshActor = "mcp-catalog-refresh"

// Failure codes a refresh claimant reports.
const (
	RefreshUnavailable = "REFRESH_UNAVAILABLE"
	RefreshNotApproved = "REFRESH_NOT_APPROVED"
)

// RefreshOutcome is AdvanceRefresh's answer.
type RefreshOutcome struct {
	Completed    bool
	ResultRef    string
	ResultDigest string
	FailureCode  string
}

type Refresh struct {
	store   *postgres.Store
	catalog *Catalog
	tasks   *Tasks
	clock   Clock
	log     *slog.Logger
}

// NewRefresh builds the use case and binds the refresh profile's
// acceptance to its recorded observations.
func NewRefresh(store *postgres.Store, catalog *Catalog, tasks *Tasks, clock Clock, log *slog.Logger) *Refresh {
	r := &Refresh{store: store, catalog: catalog, tasks: tasks, clock: clock, log: log}
	tasks.Bind(domain.CatalogRefreshProfile, r)
	return r
}

// Schedule requests the refresh of every callable approved revision for the
// current period (one task identity per revision and period: a repeated
// pass in the same period answers the existing request).
func (r *Refresh) Schedule(ctx context.Context, period time.Duration, max int32) (int, error) {
	if period <= 0 {
		return 0, nil
	}
	now := r.clock.Now()
	rows, err := r.store.Queries().ListRefreshTargets(ctx, sqlc.ListRefreshTargetsParams{Now: pgtype.Timestamptz{Time: now, Valid: true}, MaxTargets: max})
	if err != nil {
		return 0, err
	}
	bucket := now.Unix() / int64(period/time.Second)
	created := 0
	for _, row := range rows {
		input, err := json.Marshal(domain.CatalogRefreshInput{SchemaVersion: 1, ServerID: row.ServerID, Revision: uint64(row.Revision), DescriptorDigest: row.DescriptorDigest})
		if err != nil {
			return created, err
		}
		taskID := fmt.Sprintf("refresh-%s-r%d-%d", row.ServerID, row.Revision, bucket)
		_, existing, err := r.tasks.Request(ctx, RequestInput{
			TaskID: taskID, TenantID: row.TenantID, Kind: domain.KindCatalogRefresh, Profile: domain.CatalogRefreshProfile, Input: input,
			Effects: domain.EffectsReconstructible, AuthorizationRef: "grant:" + row.GrantID, CorrelationID: taskID,
		})
		if err != nil {
			// One revision's refusal (a grant revoked meanwhile) never stops the pass.
			r.log.Warn("catalog refresh not requested", "serverId", row.ServerID, "revision", row.Revision, "err", err)
			continue
		}
		if !existing {
			created++
		}
	}
	return created, nil
}

// Advance performs the live read of a claimed refresh once per generation
// and returns the recorded result. Only the current claimant with a valid
// lease and the frozen input digest is answered.
func (r *Refresh) Advance(ctx context.Context, taskID string, generation uint64, workerID, inputDigest string) (RefreshOutcome, error) {
	q := r.store.Queries()
	row, err := q.GetRequest(ctx, sqlc.GetRequestParams{TaskID: taskID, Generation: int64(generation)})
	if errors.Is(err, pgx.ErrNoRows) {
		return RefreshOutcome{}, fmt.Errorf("%w: %s generation %d", domain.ErrNotFound, taskID, generation)
	}
	if err != nil {
		return RefreshOutcome{}, err
	}
	task := postgres.TaskFromRow(row)
	switch {
	case task.Kind != domain.KindCatalogRefresh || task.ResultProfile != domain.CatalogRefreshProfile:
		return RefreshOutcome{}, fmt.Errorf("%w: %s is not a catalog refresh", domain.ErrInvalid, taskID)
	case task.State != domain.StateLeased || task.WorkerID != workerID:
		return RefreshOutcome{}, fmt.Errorf("%w: not the current claimant (state %s)", domain.ErrStaleExecution, task.State)
	case !task.LeaseUntil.After(r.clock.Now()):
		return RefreshOutcome{}, fmt.Errorf("%w: lease expired", domain.ErrStaleExecution)
	case task.InputDigest != inputDigest:
		return RefreshOutcome{}, fmt.Errorf("%w: input digest does not match the frozen input", domain.ErrInvalid)
	}
	if rec, err := q.GetRefresh(ctx, sqlc.GetRefreshParams{TaskID: taskID, Generation: int64(generation)}); err == nil {
		return RefreshOutcome{Completed: true, ResultRef: rec.ResultRef, ResultDigest: rec.ResultDigest}, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return RefreshOutcome{}, err
	}
	var in domain.CatalogRefreshInput
	if err := json.Unmarshal(task.Input, &in); err != nil {
		return RefreshOutcome{}, fmt.Errorf("%w: %v", domain.ErrInvalid, err)
	}
	dr, err := q.GetDescriptor(ctx, sqlc.GetDescriptorParams{ServerID: in.ServerID, Revision: int64(in.Revision)})
	if err != nil {
		return RefreshOutcome{}, err
	}
	srv, err := q.GetServer(ctx, in.ServerID)
	if err != nil {
		return RefreshOutcome{}, err
	}
	desc, err := postgres.DescriptorFromRow(dr, srv)
	if err != nil {
		return RefreshOutcome{}, err
	}
	if desc.TenantID != task.TenantID || desc.Digest != in.DescriptorDigest {
		return RefreshOutcome{}, fmt.Errorf("%w: the request does not name this tenant's revision", domain.ErrInvalid)
	}
	if desc.State != domain.CatalogApproved {
		return RefreshOutcome{FailureCode: RefreshNotApproved}, nil
	}
	live, err := r.catalog.readLive(ctx, desc.CanonicalResource, desc.ProtocolVersion)
	if err != nil {
		r.log.Warn("catalog refresh: live read failed", "serverId", desc.ServerID, "revision", desc.Revision, "err", err)
		return RefreshOutcome{FailureCode: RefreshUnavailable}, nil
	}
	liveDigest, reason := "", ""
	if rebuilt, err := domain.BuildDescriptor(DeclarationOf(desc), live); err != nil {
		reason = err.Error()
	} else {
		liveDigest = rebuilt.Digest
		reason = driftReason(desc, rebuilt)
	}
	drift := liveDigest != desc.Digest
	if !drift {
		reason = ""
	}
	ref, digest, err := domain.RefreshResult(taskID, generation, desc.ServerID, desc.Revision, desc.Digest, liveDigest, drift)
	if err != nil {
		return RefreshOutcome{}, err
	}
	if err := q.InsertRefresh(ctx, sqlc.InsertRefreshParams{
		TaskID: taskID, Generation: int64(generation), WorkerID: workerID, ServerID: desc.ServerID, Revision: int64(desc.Revision),
		ReviewedDigest: desc.Digest, LiveDigest: optional(liveDigest), Drift: drift, DriftReason: optional(bounded(reason, 1024)), ResultRef: ref, ResultDigest: digest,
	}); err != nil {
		return RefreshOutcome{}, err
	}
	// A concurrent call of the same generation may have recorded first: the record wins.
	rec, err := q.GetRefresh(ctx, sqlc.GetRefreshParams{TaskID: taskID, Generation: int64(generation)})
	if err != nil {
		return RefreshOutcome{}, err
	}
	if rec.Drift {
		r.log.Warn("catalog refresh found drift", "serverId", desc.ServerID, "revision", desc.Revision, "reason", deref(rec.DriftReason))
	}
	return RefreshOutcome{Completed: true, ResultRef: rec.ResultRef, ResultDigest: rec.ResultDigest}, nil
}

// Recorded is the refresh profile's expectation: the recorded observation.
func (r *Refresh) Recorded(ctx context.Context, tx postgres.Tx, t domain.Task) (*domain.RecordedResult, error) {
	rec, err := tx.Q.GetRefresh(ctx, sqlc.GetRefreshParams{TaskID: t.TaskID, Generation: int64(t.Generation)})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &domain.RecordedResult{Ref: rec.ResultRef, Digest: rec.ResultDigest}, nil
}

// Accepted disables a drifted revision in the acceptance transaction.
func (r *Refresh) Accepted(ctx context.Context, tx postgres.Tx, t domain.Task) error {
	rec, err := tx.Q.GetRefresh(ctx, sqlc.GetRefreshParams{TaskID: t.TaskID, Generation: int64(t.Generation)})
	if err != nil || !rec.Drift {
		return err
	}
	srv, err := tx.Q.GetServer(ctx, rec.ServerID)
	if err != nil {
		return err
	}
	dr, err := tx.Q.GetDescriptorForUpdate(ctx, sqlc.GetDescriptorForUpdateParams{ServerID: rec.ServerID, Revision: rec.Revision})
	if err != nil {
		return err
	}
	d, err := postgres.DescriptorFromRow(dr, srv)
	if err != nil || d.State != domain.CatalogApproved {
		return err
	}
	if err := r.catalog.disableLocked(ctx, tx, &d, RefreshActor, d.TenantID, fmt.Sprintf("refresh:%s:%d", t.TaskID, t.Generation), t.InputDigest, "REFRESH_DRIFT"); err != nil {
		return err
	}
	r.log.Warn("catalog refresh disabled a drifted revision", "serverId", d.ServerID, "revision", d.Revision, "taskId", t.TaskID)
	return nil
}

// DeclarationOf is the reviewed declaration a revision was approved under:
// what a live read is rebuilt against (no expected digests: the whole
// digest is compared).
func DeclarationOf(d domain.Descriptor) domain.Declaration {
	tools := make([]domain.ToolDeclaration, 0, len(d.Tools))
	for _, t := range d.Tools {
		tools = append(tools, domain.ToolDeclaration{Method: t.Method, SideEffecting: t.SideEffecting, UnitPrice: t.UnitPrice, Idempotent: t.Idempotent, QuerySupported: t.QuerySupported})
	}
	return domain.Declaration{CanonicalResource: d.CanonicalResource, Transport: d.Transport, ProtocolVersion: d.ProtocolVersion, Provenance: d.Provenance,
		Tools: tools, DataClass: d.DataClass, NetworkScope: d.NetworkScope, Licenses: d.Licenses}
}

// driftReason names what differs between the reviewed and the live revision.
func driftReason(reviewed, live domain.Descriptor) string {
	var parts []string
	if reviewed.ServerName != live.ServerName || reviewed.ServerVersion != live.ServerVersion {
		parts = append(parts, fmt.Sprintf("server %s %s -> %s %s", reviewed.ServerName, reviewed.ServerVersion, live.ServerName, live.ServerVersion))
	}
	for _, rt := range reviewed.Tools {
		lt, _ := live.Method(rt.Method)
		switch {
		case rt.InputSchemaDigest != lt.InputSchemaDigest:
			parts = append(parts, rt.Method+": input schema")
		case rt.OutputSchemaDigest != lt.OutputSchemaDigest:
			parts = append(parts, rt.Method+": output schema")
		case rt.AnnotationsDigest != lt.AnnotationsDigest:
			parts = append(parts, rt.Method+": annotations")
		}
	}
	if reviewed.ResourcesDigest != live.ResourcesDigest {
		parts = append(parts, "resources")
	}
	if reviewed.PromptsDigest != live.PromptsDigest {
		parts = append(parts, "prompts")
	}
	if reviewed.Issuer != live.Issuer {
		parts = append(parts, "issuer")
	}
	if len(parts) == 0 {
		return "descriptor digest"
	}
	return strings.Join(parts, "; ")
}

func bounded(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
