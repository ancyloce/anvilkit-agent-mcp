package application_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

type recordingCache struct {
	mu        sync.Mutex
	grants    []string
	resources []string
}

func (c *recordingCache) EvictGrant(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.grants = append(c.grants, key)
	return 1
}

func (c *recordingCache) EvictResource(resource string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resources = append(c.resources, resource)
	return 1
}

// catalogAndGrantEvents reads the committed catalog and grant envelopes in
// commit order.
func catalogAndGrantEvents(t *testing.T, h *catalogHarness) []domain.Envelope {
	t.Helper()
	rows, err := h.inst.Pool(t).Query(context.Background(), `SELECT payload::text FROM outbox ORDER BY transaction_id, "offset"`)
	require.NoError(t, err)
	defer rows.Close()
	var out []domain.Envelope
	for rows.Next() {
		var raw string
		require.NoError(t, rows.Scan(&raw))
		var row struct {
			Payload string `json:"payload"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &row))
		body, err := base64.StdEncoding.DecodeString(row.Payload)
		require.NoError(t, err)
		var env domain.Envelope
		require.NoError(t, json.Unmarshal(body, &env))
		if env.EventType == "mcp.catalog-reviewed" || env.EventType == "mcp.grant-revoked" {
			out = append(out, env)
		}
	}
	require.NoError(t, rows.Err())
	return out
}

// eventsSchema resolves the contracts' envelope when the contracts
// checkout is reachable (the parent workspace or ANVILKIT_CONTRACTS_DIR).
func eventsSchema(t *testing.T) *jsonschema.Resolved {
	t.Helper()
	dir := os.Getenv("ANVILKIT_CONTRACTS_DIR")
	if dir == "" {
		wd, _ := os.Getwd()
		for d := wd; d != filepath.Dir(d); d = filepath.Dir(d) {
			if _, err := os.Stat(filepath.Join(d, "contracts", "events", "events.schema.json")); err == nil {
				dir = filepath.Join(d, "contracts")
				break
			}
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "events", "events.schema.json"))
	if dir == "" || err != nil {
		t.Logf("UNEXECUTED: the contracts' events schema is not reachable (set ANVILKIT_CONTRACTS_DIR)")
		return nil
	}
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	wrapper, err := json.Marshal(map[string]any{"$schema": doc["$schema"], "$defs": doc["$defs"], "$ref": "#/$defs/envelope"})
	require.NoError(t, err)
	var s jsonschema.Schema
	require.NoError(t, json.Unmarshal(wrapper, &s))
	r, err := s.Resolve(nil)
	require.NoError(t, err)
	return r
}

// TestCredentialProjectionReceivesEveryTransition (P2.8 AC4, MCP-14): a
// consumer that rejects non-increasing aggregate revisions receives
// DISABLED after APPROVED of the same descriptor revision and REVOKED
// after REVOKING of the same grant revision; each evicts the withdrawn
// credentials; a replay is stale; an event naming another tenant's record
// or bound to another aggregate is rejected.
func TestCredentialProjectionReceivesEveryTransition(t *testing.T) {
	h := newCatalogHarness(t)
	ctx := context.Background()
	d := h.approved(t)
	g, _, err := h.grants.Create(ctx, h.cmd(granter), granter, grantRequest(d))
	require.NoError(t, err)
	require.Equal(t, domain.GrantActive, g.State)
	_, _, err = h.catalog.Disable(ctx, h.cmd(reviewer), reviewer, d.ServerID, d.Revision, "incident")
	require.NoError(t, err)
	_, err = h.grants.Reconcile(ctx, 0, 50)
	require.NoError(t, err)
	revoked, err := h.grants.Get(ctx, granter, g.GrantID)
	require.NoError(t, err)
	require.Equal(t, domain.GrantRevoked, revoked.State)

	events := catalogAndGrantEvents(t, h)
	schema := eventsSchema(t)
	var states []string
	last := map[string]uint64{}
	for _, env := range events {
		var p struct{ State, Revision string }
		require.NoError(t, json.Unmarshal(env.Payload, &p))
		states = append(states, env.EventType+":"+p.State)
		rev, err := strconv.ParseUint(env.AggregateRevision, 10, 64)
		require.NoError(t, err)
		key := env.AggregateType + "/" + env.AggregateID
		require.Greater(t, rev, last[key], "aggregateRevision strictly increases per aggregate (%s)", key)
		last[key] = rev
		if schema != nil {
			var inst map[string]any
			raw, err := json.Marshal(env)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw, &inst))
			require.NoError(t, schema.Validate(inst), "the envelope satisfies contracts/events/events.schema.json")
		}
	}
	require.Equal(t, []string{"mcp.catalog-reviewed:approved", "mcp.catalog-reviewed:disabled", "mcp.grant-revoked:revoking", "mcp.grant-revoked:revoked"}, states)

	cache := &recordingCache{}
	projection := application.NewCredentialProjection(h.store, cache, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	for _, env := range events {
		applied, err := projection.Apply(ctx, env)
		require.NoError(t, err)
		require.True(t, applied, "%s %s revision %s is received", env.EventType, env.AggregateID, env.AggregateRevision)
	}
	require.Equal(t, []string{d.CanonicalResource}, cache.resources, "DISABLED evicts the server's credentials")
	require.Equal(t, []string{g.CacheKey(), g.CacheKey()}, cache.grants, "REVOKING and REVOKED evict the grant's tokens")

	// A replay (or the redelivery of an older event) is stale.
	for _, env := range events {
		applied, err := projection.Apply(ctx, env)
		require.NoError(t, err)
		require.False(t, applied)
	}
	require.Len(t, cache.grants, 2)

	// The shape MCP-14 removed: REVOKED under REVOKING's revision would be
	// rejected by the same gate.
	gate := application.NewRevisionGate(8)
	require.True(t, gate.Admit("grant", g.GrantID, 1))
	require.False(t, gate.Admit("grant", g.GrantID, 1), "a shared revision drops the second transition")
	require.True(t, gate.Admit("grant", g.GrantID, 2))

	// Another tenant's record, another aggregate, a mismatched payload and a
	// foreign producer are rejected.
	fresh := application.NewCredentialProjection(h.store, &recordingCache{}, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	revokedEv := events[3]
	foreign := revokedEv
	foreign.TenantID = "tenant_b"
	_, err = fresh.Apply(ctx, foreign)
	require.ErrorContains(t, err, "not of the event's tenant")
	wrong := revokedEv
	wrong.AggregateType = domain.AggregateDescriptor
	_, err = fresh.Apply(ctx, wrong)
	require.Error(t, err)
	mismatched := revokedEv
	mismatched.Payload = events[1].Payload
	_, err = fresh.Apply(ctx, mismatched)
	require.ErrorContains(t, err, "payload does not match")
	other := revokedEv
	other.Producer = "anvilkit-agent-knowledge"
	_, err = fresh.Apply(ctx, other)
	require.Error(t, err)
}
