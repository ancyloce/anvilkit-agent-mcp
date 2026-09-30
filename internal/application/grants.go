package application

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/outbox"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres/sqlc"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// Grants owns grant management and MCP's side of the two-service barrier
// with Control (DD-08 §2). A grant is PENDING until Control's registration
// receipt, ACTIVE after it, REVOKING from the commit of its revocation (MCP
// admission denies it from that moment) until Control's barrier converged
// and MCP's own requests of the grant are terminal, then REVOKED. Every
// call to Control carries the command identity recorded before the call,
// so a crash or a lost answer at any boundary is reconciled under the
// original identity: an uncertain registration stays non-executable and an
// uncertain revocation stays restrictive until Control answers.

// Barrier is Control's revocation barrier as last read.
type Barrier struct {
	State    string // fenced | converging | converged
	InFlight uint64
	Unknown  uint64
	FencedAt *time.Time
}

// ControlCommand is the command identity a barrier call presents to Control.
type ControlCommand struct {
	TenantID, CommandID, ActorID, RequestDigest string
}

// PolicyRegistry is the port to Control's GrantPolicyService. ErrRefused
// wraps a definitive refusal; any other error leaves the outcome unknown.
type PolicyRegistry interface {
	Register(ctx context.Context, cmd ControlCommand, g domain.Grant) (receiptID string, epoch uint64, err error)
	BeginRevocation(ctx context.Context, cmd ControlCommand, grantID string, revision uint64) (Barrier, error)
	Revocation(ctx context.Context, grantID string, revision uint64) (Barrier, error)
}

// ErrRefused marks Control's definitive refusal (the call reached Control
// and was decided).
var ErrRefused = errors.New("CONTROL_REFUSED")

// Owner is the identity MCP presents to Control for barrier calls.
const Owner = "anvilkit-agent-mcp"

type Grants struct {
	store    *postgres.Store
	authz    *Authorizer
	registry PolicyRegistry
	clock    Clock
	log      *slog.Logger
	metrics  *Metrics
}

func NewGrants(store *postgres.Store, authz *Authorizer, registry PolicyRegistry, clock Clock, log *slog.Logger, metrics *Metrics) *Grants {
	return &Grants{store: store, authz: authz, registry: registry, clock: clock, log: log, metrics: metrics}
}

func (g *Grants) load(ctx context.Context, q *sqlc.Queries, grantID string) (domain.Grant, error) {
	r, err := q.GetGrant(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Grant{}, fmt.Errorf("%w: grant %s", domain.ErrNotFound, grantID)
	}
	if err != nil {
		return domain.Grant{}, err
	}
	return postgres.GrantFromRow(r), nil
}

func (g *Grants) lock(ctx context.Context, tx postgres.Tx, grantID string) (domain.Grant, error) {
	r, err := tx.Q.GetGrantForUpdate(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Grant{}, fmt.Errorf("%w: grant %s", domain.ErrNotFound, grantID)
	}
	if err != nil {
		return domain.Grant{}, err
	}
	return postgres.GrantFromRow(r), nil
}

// update writes the barrier columns under the state the transaction read.
func (g *Grants) update(ctx context.Context, tx postgres.Tx, next domain.Grant, read domain.GrantState) error {
	n, err := tx.Q.UpdateGrantBarrier(ctx, postgres.BarrierParams(next, read))
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("%w: grant %s changed under the lock", domain.ErrStaleExecution, next.GrantID)
	}
	return nil
}

func (g *Grants) decide(ctx context.Context, tx postgres.Tx, gr domain.Grant, decision, decider, reason, commandID, requestDigest string) error {
	return tx.Q.InsertGrantDecision(ctx, sqlc.InsertGrantDecisionParams{
		DecisionID: idOf("gd-", gr.GrantID, decision, commandID), GrantID: gr.GrantID, FromRevision: int64(gr.Revision), ToRevision: int64(gr.Revision),
		Decision: decision, Decider: decider, ReasonCode: optional(reason), CommandID: commandID, RequestDigest: requestDigest, TenantID: gr.TenantID,
	})
}

// Create records a PENDING grant bound to an approved descriptor revision
// and then registers it with Control. It needs the grant-manager role.
func (g *Grants) Create(ctx context.Context, cmd Command, scope Scope, req domain.GrantRequest) (domain.Grant, bool, error) {
	if err := checkCommand(cmd, scope); err != nil {
		return domain.Grant{}, false, err
	}
	if err := g.authz.Require(scope.TenantID, scope.ActorID, ActGrantCreate); err != nil {
		return domain.Grant{}, false, err
	}
	replay := func() (domain.Grant, bool, error) {
		r, err := g.store.Queries().GetGrantByCommand(ctx, sqlc.GetGrantByCommandParams{TenantID: cmd.TenantID, CommandID: cmd.CommandID})
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Grant{}, false, nil
		}
		if err != nil {
			return domain.Grant{}, false, err
		}
		if r.RequestDigest != cmd.RequestDigest {
			return domain.Grant{}, false, fmt.Errorf("%w: the command id was used with another request", domain.ErrCommandConflict)
		}
		gr := postgres.GrantFromRow(r)
		if gr.State == domain.GrantPending {
			// The retried command finishes what a crash or a lost answer left.
			gr, err = g.register(ctx, gr.GrantID)
		}
		return gr, true, err
	}
	if gr, found, err := replay(); err != nil || found {
		return gr, found, err
	}
	var created domain.Grant
	err := g.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		s, err := tx.Q.GetServer(ctx, req.ServerID)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && s.TenantID != scope.TenantID) {
			return fmt.Errorf("%w: server %s", domain.ErrNotFound, req.ServerID)
		}
		if err != nil {
			return err
		}
		// The descriptor row lock orders creation against a concurrent disable.
		row, err := tx.Q.GetDescriptorForUpdate(ctx, sqlc.GetDescriptorForUpdateParams{ServerID: req.ServerID, Revision: int64(req.DescriptorRev)})
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: descriptor %s revision %d", domain.ErrNotFound, req.ServerID, req.DescriptorRev)
		}
		if err != nil {
			return err
		}
		d, err := postgres.DescriptorFromRow(row, s)
		if err != nil {
			return err
		}
		gr, err := domain.NewGrant(scope.TenantID, scope.ProjectID, req, d, g.clock.Now())
		if err != nil {
			return err
		}
		gr.GrantID = idOf("grt-", cmd.TenantID, cmd.CommandID)
		gr.PolicyDigest = gr.ComputePolicyDigest()
		gr.RegistrationCmdID = fmt.Sprintf("register:%s:r%d", gr.GrantID, gr.Revision)
		gr.CommandID, gr.RequestDigest = cmd.CommandID, cmd.RequestDigest
		var exp *time.Time = gr.ExpiresAt
		if err := tx.Q.InsertGrant(ctx, sqlc.InsertGrantParams{
			GrantID: gr.GrantID, Revision: int64(gr.Revision), TenantID: gr.TenantID, SubjectType: gr.SubjectType, SubjectID: gr.SubjectID,
			ServerID: gr.ServerID, DescriptorRevision: int64(gr.DescriptorRevision), DescriptorDigest: gr.DescriptorDigest, Methods: gr.Methods,
			Purpose: gr.Purpose, CostCapCurrency: gr.CostCap.Currency, CostCapAmount: gr.CostCap.Amount, State: string(gr.State), ExpiresAt: tsOf(exp),
			CommandID: cmd.CommandID, RequestDigest: cmd.RequestDigest, CanonicalResource: gr.CanonicalResource, Transport: gr.Transport,
			ProtocolVersion: gr.ProtocolVersion, Issuer: gr.Issuer, Audience: gr.Audience, ResourceSelectors: gr.ResourceSelectors,
			PromptSelectors: gr.PromptSelectors, DataClass: gr.DataClass, PolicyDigest: gr.PolicyDigest, RegistrationCommandID: gr.RegistrationCmdID,
		}); err != nil {
			return err
		}
		created = gr
		return g.decide(ctx, tx, gr, "create", scope.ActorID, "", cmd.CommandID, cmd.RequestDigest)
	})
	if errors.Is(err, postgres.ErrDuplicateKey) {
		if gr, found, rerr := replay(); rerr == nil && found {
			return gr, true, nil
		}
	}
	if err != nil {
		return domain.Grant{}, false, err
	}
	g.metrics.GrantTransitions.WithLabelValues("pending").Inc()
	gr, err := g.register(ctx, created.GrantID)
	if err != nil {
		// The grant exists and stays PENDING (non-executable); reconciliation
		// completes the registration under the same command identity.
		g.log.Warn("grant registration not confirmed; the grant stays pending", "grantId", created.GrantID, "error", err)
		gr, err = g.load(ctx, g.store.Queries(), created.GrantID)
		return gr, false, err
	}
	return gr, false, nil
}

// register sends the registration of a PENDING grant under its recorded
// command identity and records the outcome: ACTIVE with the receipt,
// REGISTRATION_FAILED on a definitive refusal, still PENDING (with the
// failure code) when the outcome is unknown. A grant whose revocation
// committed meanwhile is never activated.
func (g *Grants) register(ctx context.Context, grantID string) (domain.Grant, error) {
	gr, err := g.load(ctx, g.store.Queries(), grantID)
	if err != nil || gr.State != domain.GrantPending {
		return gr, err
	}
	receipt, epoch, rerr := g.registry.Register(ctx, ControlCommand{TenantID: gr.TenantID, CommandID: gr.RegistrationCmdID, ActorID: Owner, RequestDigest: gr.PolicyDigest}, gr)
	var out domain.Grant
	err = g.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		cur, err := g.lock(ctx, tx, grantID)
		if err != nil {
			return err
		}
		out = cur
		if cur.State != domain.GrantPending {
			return nil
		}
		next := cur
		switch {
		case rerr == nil:
			next.State, next.ControlReceiptID, next.PolicyEpoch, next.FailureCode = domain.GrantActive, receipt, epoch, ""
			if err := g.decide(ctx, tx, next, "activate", Owner, "", cur.RegistrationCmdID, cur.PolicyDigest); err != nil {
				return err
			}
		case errors.Is(rerr, ErrRefused):
			next.State, next.FailureCode = domain.GrantRegistrationFailed, "REGISTRATION_REFUSED"
			if err := g.decide(ctx, tx, next, "registration_failed", Owner, "REGISTRATION_REFUSED", cur.RegistrationCmdID, cur.PolicyDigest); err != nil {
				return err
			}
		default:
			next.FailureCode = "REGISTRATION_UNCERTAIN"
		}
		if err := g.update(ctx, tx, next, cur.State); err != nil {
			return err
		}
		out = next
		return nil
	})
	if err != nil {
		return domain.Grant{}, err
	}
	if out.State != gr.State {
		g.metrics.GrantTransitions.WithLabelValues(string(out.State)).Inc()
		g.log.Info("grant registration settled", "grantId", grantID, "state", out.State)
	}
	if rerr != nil && !errors.Is(rerr, ErrRefused) {
		return out, rerr
	}
	return out, nil
}

// Revoke commits REVOKING (new MCP admission is denied from that commit)
// with its event and then installs Control's fence. It needs the
// grant-manager role; a repeated command answers the current grant.
func (g *Grants) Revoke(ctx context.Context, cmd Command, scope Scope, grantID string, expectedRevision uint64, reason string) (domain.Grant, bool, error) {
	if err := checkCommand(cmd, scope); err != nil {
		return domain.Grant{}, false, err
	}
	if err := g.authz.Require(scope.TenantID, scope.ActorID, ActGrantRevoke); err != nil {
		return domain.Grant{}, false, err
	}
	if d, err := g.store.Queries().GetGrantDecisionByCommand(ctx, sqlc.GetGrantDecisionByCommandParams{TenantID: cmd.TenantID, CommandID: cmd.CommandID, Decision: "revoke"}); err == nil {
		if d.GrantID != grantID || d.RequestDigest != cmd.RequestDigest {
			return domain.Grant{}, false, fmt.Errorf("%w: the command id was used with another request", domain.ErrCommandConflict)
		}
		gr, err := g.advance(ctx, grantID)
		if err != nil {
			// The revocation is committed; an unanswered barrier call leaves it
			// REVOKING for reconciliation, exactly as on the first call.
			g.log.Warn("revocation barrier not confirmed; the grant stays revoking", "grantId", grantID, "error", err)
			gr, err = g.load(ctx, g.store.Queries(), grantID)
		}
		return gr, true, err
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return domain.Grant{}, false, err
	}
	existing := false
	err := g.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		cur, err := g.lock(ctx, tx, grantID)
		if err != nil {
			return err
		}
		if cur.TenantID != scope.TenantID {
			return fmt.Errorf("%w: grant %s", domain.ErrNotFound, grantID)
		}
		if cur.Revision != expectedRevision {
			return fmt.Errorf("%w: grant revision is %d", domain.ErrRevisionMismatch, cur.Revision)
		}
		if cur.State == domain.GrantRevoking || cur.State == domain.GrantRevoked {
			existing = true
			return g.decide(ctx, tx, cur, "revoke", scope.ActorID, reason, cmd.CommandID, cmd.RequestDigest)
		}
		return g.revokeLocked(ctx, tx, cur, cmd.CommandID, cmd.RequestDigest, scope.ActorID, reason)
	})
	if err != nil {
		return domain.Grant{}, false, err
	}
	gr, err := g.advance(ctx, grantID)
	if err != nil {
		g.log.Warn("revocation barrier not confirmed; the grant stays revoking", "grantId", grantID, "error", err)
		gr, err = g.load(ctx, g.store.Queries(), grantID)
	}
	return gr, existing, err
}

// revokeIn begins the revocation of a grant inside the caller's
// transaction (a disabled descriptor revokes its grants).
func (g *Grants) revokeIn(ctx context.Context, tx postgres.Tx, grantID, commandID, requestLabel, decider, reason string) error {
	cur, err := g.lock(ctx, tx, grantID)
	if err != nil {
		return err
	}
	if cur.State == domain.GrantRevoking || cur.State == domain.GrantRevoked {
		return nil
	}
	return g.revokeLocked(ctx, tx, cur, fmt.Sprintf("%s:%s", commandID, grantID), domain.DigestBytes([]byte(requestLabel+"\x00"+grantID)), decider, reason)
}

func (g *Grants) revokeLocked(ctx context.Context, tx postgres.Tx, cur domain.Grant, commandID, requestDigest, decider, reason string) error {
	next := cur
	next.State, next.RevocationCmdID = domain.GrantRevoking, fmt.Sprintf("revoke:%s:r%d", cur.GrantID, cur.Revision)
	if reason != "" {
		next.FailureCode = reason
	}
	if err := g.update(ctx, tx, next, cur.State); err != nil {
		return err
	}
	if err := g.decide(ctx, tx, next, "revoke", decider, reason, commandID, requestDigest); err != nil {
		return err
	}
	env, err := domain.GrantRevokedEvent(next, commandID, g.clock.Now())
	if err != nil {
		return err
	}
	g.metrics.GrantTransitions.WithLabelValues("revoking").Inc()
	return outbox.Publish(ctx, tx.Tx, env)
}

// advance moves a REVOKING grant along the barrier: Control's fence
// (idempotent under the recorded revocation command), then its
// convergence; REVOKED only when Control converged and MCP's own requests
// of the grant are terminal. A PENDING grant is registered instead.
func (g *Grants) advance(ctx context.Context, grantID string) (domain.Grant, error) {
	gr, err := g.load(ctx, g.store.Queries(), grantID)
	if err != nil {
		return domain.Grant{}, err
	}
	switch gr.State {
	case domain.GrantPending:
		return g.register(ctx, grantID)
	case domain.GrantRevoking:
	default:
		return gr, nil
	}
	var b Barrier
	if gr.ControlState == "none" {
		b, err = g.registry.BeginRevocation(ctx, ControlCommand{TenantID: gr.TenantID, CommandID: gr.RevocationCmdID, ActorID: Owner, RequestDigest: gr.PolicyDigest}, gr.GrantID, gr.Revision)
	} else {
		b, err = g.registry.Revocation(ctx, gr.GrantID, gr.Revision)
	}
	if err != nil {
		return gr, err
	}
	if b.State != "converged" && gr.ControlState == "none" {
		// The fence is installed; read the barrier once more for convergence.
		if again, rerr := g.registry.Revocation(ctx, gr.GrantID, gr.Revision); rerr == nil {
			b = again
		}
	}
	open, err := g.store.Queries().CountOpenToolRequests(ctx, sqlc.CountOpenToolRequestsParams{GrantID: gr.GrantID, GrantRevision: int64(gr.Revision)})
	if err != nil {
		return gr, err
	}
	var out domain.Grant
	err = g.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		cur, err := g.lock(ctx, tx, grantID)
		if err != nil {
			return err
		}
		out = cur
		if cur.State != domain.GrantRevoking {
			return nil
		}
		next := cur
		next.ControlState, next.InFlightCalls, next.UnknownCalls = b.State, b.InFlight, b.Unknown
		if b.FencedAt != nil {
			next.FencedAt = b.FencedAt
		}
		if b.State == "converged" && open == 0 {
			now := g.clock.Now()
			next.State, next.RevokedAt = domain.GrantRevoked, &now
			if err := g.decide(ctx, tx, next, "converge", Owner, "", "converge:"+cur.RevocationCmdID, cur.PolicyDigest); err != nil {
				return err
			}
			env, err := domain.GrantRevokedEvent(next, cur.RevocationCmdID, now)
			if err != nil {
				return err
			}
			if err := outbox.Publish(ctx, tx.Tx, env); err != nil {
				return err
			}
		}
		if err := g.update(ctx, tx, next, cur.State); err != nil {
			return err
		}
		out = next
		return nil
	})
	if err == nil && out.State == domain.GrantRevoked {
		g.metrics.GrantTransitions.WithLabelValues("revoked").Inc()
		g.log.Info("grant revoked: the barrier converged", "grantId", grantID)
	}
	return out, err
}

// Progress is a grant's management outcome as the caller may see it.
type Progress struct {
	Grant               domain.Grant
	NewAdmissionBlocked bool
	SendersConverged    bool
	OpenCalls           uint64
}

func (g *Grants) visible(scope Scope, gr domain.Grant) bool {
	if gr.TenantID != scope.TenantID {
		return false
	}
	if g.authz.Allowed(scope.TenantID, scope.ActorID, ActGrantReadAll) {
		return true
	}
	switch gr.SubjectType {
	case "tenant":
		return true
	case "project":
		return gr.SubjectID == scope.ProjectID
	case "actor":
		return gr.SubjectID == scope.ActorID
	}
	return false
}

// Get answers a grant the caller may see.
func (g *Grants) Get(ctx context.Context, scope Scope, grantID string) (domain.Grant, error) {
	gr, err := g.load(ctx, g.store.Queries(), grantID)
	if err != nil {
		return domain.Grant{}, err
	}
	if !g.visible(scope, gr) {
		return domain.Grant{}, fmt.Errorf("%w: grant %s", domain.ErrNotFound, grantID)
	}
	return gr, nil
}

// Progress distinguishes blocked new admission (every state but ACTIVE)
// from all previous senders converged (Control's barrier converged and no
// request of the grant is open in MCP).
func (g *Grants) Progress(ctx context.Context, scope Scope, grantID string) (Progress, error) {
	gr, err := g.Get(ctx, scope, grantID)
	if err != nil {
		return Progress{}, err
	}
	open, err := g.store.Queries().CountOpenToolRequests(ctx, sqlc.CountOpenToolRequestsParams{GrantID: gr.GrantID, GrantRevision: int64(gr.Revision)})
	if err != nil {
		return Progress{}, err
	}
	return Progress{Grant: gr, NewAdmissionBlocked: !gr.Executable(g.clock.Now()), SendersConverged: gr.ControlState == "converged" && open == 0, OpenCalls: uint64(open)}, nil
}

// List answers a page of the grants the caller may see.
func (g *Grants) List(ctx context.Context, scope Scope, state, cursor string, limit int) ([]domain.Grant, string, error) {
	if limit <= 0 {
		limit = 50
	}
	after := ""
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return nil, "", fmt.Errorf("%w: cursor", domain.ErrInvalid)
		}
		after = string(raw)
	}
	rows, err := g.store.Queries().ListGrants(ctx, sqlc.ListGrantsParams{TenantID: scope.TenantID, State: state,
		ReadAll: g.authz.Allowed(scope.TenantID, scope.ActorID, ActGrantReadAll), ProjectID: scope.ProjectID, ActorID: scope.ActorID, AfterGrant: after, PageLimit: int32(limit + 1)})
	if err != nil {
		return nil, "", err
	}
	out := make([]domain.Grant, 0, len(rows))
	for _, r := range rows {
		out = append(out, postgres.GrantFromRow(r))
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = base64.RawURLEncoding.EncodeToString([]byte(out[limit-1].GrantID))
	}
	return out, next, nil
}

// Reconcile completes every open barrier older than the interval (uncertain
// registrations, unconfirmed fences, converging revocations) under the
// original command identities, and expires ACTIVE grants whose expiry passed.
func (g *Grants) Reconcile(ctx context.Context, olderThan time.Duration, limit int) (int, error) {
	// Database time: updated_at is written by the database.
	ids, err := g.store.Queries().ListOpenBarriers(ctx, sqlc.ListOpenBarriersParams{AgeSeconds: olderThan.Seconds(), PageLimit: int32(limit)})
	if err != nil {
		return 0, err
	}
	moved := 0
	for _, id := range ids {
		before, _ := g.load(ctx, g.store.Queries(), id)
		after, err := g.advance(ctx, id)
		if err != nil {
			g.log.Warn("grant barrier not advanced", "grantId", id, "error", err)
			continue
		}
		if after.State != before.State {
			moved++
		}
	}
	expired, err := g.store.Queries().ListExpiredGrants(ctx, sqlc.ListExpiredGrantsParams{ExpiresAt: tsOf(ptr(g.clock.Now())), Limit: int32(limit)})
	if err != nil {
		return moved, err
	}
	for _, id := range expired {
		err := g.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
			cur, err := g.lock(ctx, tx, id)
			if err != nil || cur.State != domain.GrantActive || cur.ExpiresAt == nil || g.clock.Now().Before(*cur.ExpiresAt) {
				return err
			}
			next := cur
			next.State = domain.GrantExpired
			if err := g.decide(ctx, tx, next, "expire", Owner, "EXPIRED", "expire:"+cur.GrantID, cur.PolicyDigest); err != nil {
				return err
			}
			return g.update(ctx, tx, next, cur.State)
		})
		if err != nil {
			g.log.Warn("grant expiry not recorded", "grantId", id, "error", err)
			continue
		}
		moved++
	}
	return moved, nil
}

func ptr[T any](v T) *T { return &v }

func tsOf(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}
