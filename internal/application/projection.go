package application

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// TokenCache is the replica's cache of upstream access tokens
// (upstream.Authority): entries of one grant's security dimensions, or of
// every grant and discovery credential of one canonical resource.
type TokenCache interface {
	EvictGrant(cacheKey string) int
	EvictResource(resource string) int
}

// RevisionGate admits each aggregate's events in strictly increasing
// aggregateRevision (contracts.md §6 "reject stale aggregate revisions";
// MCP-14): an event whose revision is not greater than the last one it
// admitted for the aggregate is stale. It holds at most limit aggregates;
// reaching the limit forgets them all, after which one replayed stale
// event can be admitted again, which a consumer whose effect is
// idempotent (an eviction) tolerates.
type RevisionGate struct {
	mu    sync.Mutex
	last  map[string]uint64
	limit int
}

func NewRevisionGate(limit int) *RevisionGate {
	return &RevisionGate{last: map[string]uint64{}, limit: limit}
}

// Admit reports whether the revision advances the aggregate and records it.
func (g *RevisionGate) Admit(aggregateType, aggregateID string, revision uint64) bool {
	key := aggregateType + "\x00" + aggregateID
	g.mu.Lock()
	defer g.mu.Unlock()
	if last, ok := g.last[key]; ok && revision <= last {
		return false
	}
	if len(g.last) >= g.limit {
		clear(g.last)
	}
	g.last[key] = revision
	return true
}

// CredentialProjection is the consumer of mcp.catalog-reviewed and
// mcp.grant-revoked (P2.8 event catalog): every MCP replica holds upstream
// access tokens in memory, and a committed revocation or a disabled or
// rejected descriptor evicts the tokens bound to that grant or server on
// every replica at once instead of at their expiry. It never authorizes
// anything: the call path re-reads the grant and the descriptor lock from
// the owner's records, so a lost or late event only leaves a token cached
// that no admitted call can use. Events are validated against this
// producer's catalog and rejected unless their aggregate revision
// increases; the grant or server is re-read from the owner's records and
// must belong to the event's tenant.
type CredentialProjection struct {
	store   *postgres.Store
	cache   TokenCache
	gate    *RevisionGate
	log     *slog.Logger
	metrics *Metrics
}

func NewCredentialProjection(store *postgres.Store, cache TokenCache, log *slog.Logger, metrics *Metrics) *CredentialProjection {
	return &CredentialProjection{store: store, cache: cache, gate: NewRevisionGate(100_000), log: log, metrics: metrics}
}

// ProjectionSubjects are the subjects the projection consumes.
var ProjectionSubjects = []string{domain.SubjectCatalogReviewed, domain.SubjectGrantRevoked}

// maxProjectionEnvelope bounds a message the projection decodes.
const maxProjectionEnvelope = 64 << 10

// Handle decodes and applies one message; outcomes are counted and
// logged, never returned (the consumer moves on).
func (p *CredentialProjection) Handle(ctx context.Context, data []byte) {
	if len(data) > maxProjectionEnvelope {
		p.count("rejected")
		p.log.Warn("credential projection dropped an oversized message", "bytes", len(data))
		return
	}
	var env domain.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		p.count("rejected")
		p.log.Warn("credential projection dropped a message that is not an envelope")
		return
	}
	applied, err := p.Apply(ctx, env)
	switch {
	case err != nil:
		p.count("rejected")
		p.log.Warn("credential projection rejected an event", "eventType", env.EventType, "aggregateId", env.AggregateID, "reason", err.Error())
	case !applied:
		p.count("stale")
		p.log.Debug("credential projection skipped a stale revision", "eventType", env.EventType, "aggregateId", env.AggregateID, "aggregateRevision", env.AggregateRevision)
	default:
		p.count("applied")
	}
}

func (p *CredentialProjection) count(outcome string) {
	if p.metrics != nil {
		p.metrics.EventProjections.WithLabelValues(outcome).Inc()
	}
}

type projectedPayload struct {
	Kind     string `json:"kind"`
	ServerID string `json:"serverId"`
	GrantID  string `json:"grantId"`
	Revision string `json:"revision"`
	State    string `json:"state"`
}

// Apply validates the envelope, admits it through the revision gate and
// evicts what it revokes. It answers false for a stale revision and an
// error for an envelope that is not one of this producer's catalog or
// grant events or that names another tenant's record.
func (p *CredentialProjection) Apply(ctx context.Context, env domain.Envelope) (bool, error) {
	if env.SchemaVersion != 1 || env.Producer != domain.Producer || env.TenantID == "" {
		return false, errors.New("not an event of this producer")
	}
	var pl projectedPayload
	if err := json.Unmarshal(env.Payload, &pl); err != nil || pl.Kind != env.EventType {
		return false, errors.New("payload does not match the event type")
	}
	rev, err := strconv.ParseUint(env.AggregateRevision, 10, 64)
	if err != nil {
		return false, errors.New("malformed aggregateRevision")
	}
	switch env.EventType {
	case "mcp.catalog-reviewed":
		if env.Subject != domain.SubjectCatalogReviewed || env.AggregateType != domain.AggregateDescriptor || pl.ServerID != env.AggregateID {
			return false, errors.New("catalog event bound to another subject or aggregate")
		}
		if !p.gate.Admit(env.AggregateType, env.AggregateID, rev) {
			return false, nil
		}
		if pl.State != string(domain.CatalogDisabled) && pl.State != string(domain.CatalogRejected) {
			return true, nil
		}
		s, err := p.store.Queries().GetServer(ctx, pl.ServerID)
		if errors.Is(err, pgx.ErrNoRows) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if s.TenantID != env.TenantID {
			return false, fmt.Errorf("server %s is not of the event's tenant", pl.ServerID)
		}
		n := p.cache.EvictResource(s.CanonicalResource)
		p.log.Info("credentials of a withdrawn server evicted", "serverId", pl.ServerID, "state", pl.State, "evicted", n)
		return true, nil
	case "mcp.grant-revoked":
		if env.Subject != domain.SubjectGrantRevoked || env.AggregateType != domain.AggregateGrant || pl.GrantID != env.AggregateID {
			return false, errors.New("grant event bound to another subject or aggregate")
		}
		if !p.gate.Admit(env.AggregateType, env.AggregateID, rev) {
			return false, nil
		}
		r, err := p.store.Queries().GetGrant(ctx, pl.GrantID)
		if errors.Is(err, pgx.ErrNoRows) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		g := postgres.GrantFromRow(r)
		if g.TenantID != env.TenantID {
			return false, fmt.Errorf("grant %s is not of the event's tenant", pl.GrantID)
		}
		n := p.cache.EvictGrant(g.CacheKey())
		p.log.Info("credentials of a revoked grant evicted", "grantId", pl.GrantID, "state", pl.State, "evicted", n)
		return true, nil
	}
	return false, fmt.Errorf("event type %q is not consumed here", env.EventType)
}
