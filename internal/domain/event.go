package domain

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Producer and subjects of this owner (architecture.md naming, event catalog).
const (
	Producer                   = "anvilkit-agent-mcp"
	SubjectBackgroundRequested = "anvilkit.mcp.background.requested"
	SubjectBackgroundCompleted = "anvilkit.mcp.background.completed"
	AggregateBackgroundRequest = "background_request"
)

// Envelope is the EventEnvelope of contracts/events/events.schema.json with
// a reviewed small payload. No input, result body, token or credential
// enters it; the payload carries identities, digests and states only.
type Envelope struct {
	EventID           string          `json:"eventId"`
	EventType         string          `json:"eventType"`
	SchemaVersion     int             `json:"schemaVersion"`
	Producer          string          `json:"producer"`
	Subject           string          `json:"subject"`
	TenantID          string          `json:"tenantId"`
	AggregateType     string          `json:"aggregateType"`
	AggregateID       string          `json:"aggregateId"`
	AggregateRevision string          `json:"aggregateRevision"`
	OccurredAt        string          `json:"occurredAt"`
	CorrelationID     string          `json:"correlationId"`
	Payload           json.RawMessage `json:"payload"`
}

type backgroundRequested struct {
	Kind        string `json:"kind"`
	TaskID      string `json:"taskId"`
	Generation  string `json:"generation"`
	TaskKind    string `json:"taskKind"`
	InputDigest string `json:"inputDigest"`
}

type backgroundCompleted struct {
	Kind         string `json:"kind"`
	TaskID       string `json:"taskId"`
	Generation   string `json:"generation"`
	State        string `json:"state"`
	ResultDigest string `json:"resultDigest,omitempty"`
}

func envelope(t Task, eventType, subject string, now time.Time, payload any) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		EventID: uuid.NewString(), EventType: eventType, SchemaVersion: 1, Producer: Producer, Subject: subject,
		TenantID: t.TenantID, AggregateType: AggregateBackgroundRequest, AggregateID: t.TaskID,
		AggregateRevision: fmt.Sprintf("%d", t.Revision), OccurredAt: now.UTC().Format("2006-01-02T15:04:05.000000Z"),
		CorrelationID: t.CorrelationID, Payload: raw,
	}, nil
}

// RequestedEvent is background.requested for a new generation.
func RequestedEvent(t Task, now time.Time) (Envelope, error) {
	return envelope(t, "background.requested", SubjectBackgroundRequested, now, backgroundRequested{
		Kind: "background.requested", TaskID: t.TaskID, Generation: fmt.Sprintf("%d", t.Generation), TaskKind: t.Kind, InputDigest: t.InputDigest,
	})
}

// CompletedEvent is background.completed for a generation that reached a
// terminal state (accepted, dead, stale, canceled); the payload names the
// state and, when accepted, the result digest.
func CompletedEvent(t Task, now time.Time) (Envelope, error) {
	if !t.State.Terminal() {
		return Envelope{}, fmt.Errorf("completed event of a non-terminal state %s", t.State)
	}
	p := backgroundCompleted{Kind: "background.completed", TaskID: t.TaskID, Generation: fmt.Sprintf("%d", t.Generation), State: string(t.State)}
	if t.State == StateAccepted {
		p.ResultDigest = t.ResultDigest
	}
	return envelope(t, "background.completed", SubjectBackgroundCompleted, now, p)
}

// Catalog and grant events (DD-08, event catalog of contracts.md): the
// subjects the event schema fixes for the mcp domain.
const (
	SubjectCatalogReviewed = "anvilkit.mcp.mcp.catalog-reviewed"
	SubjectGrantRevoked    = "anvilkit.mcp.mcp.grant-revoked"
	AggregateDescriptor    = "descriptor"
	AggregateGrant         = "grant"
)

type catalogReviewed struct {
	Kind     string `json:"kind"`
	ServerID string `json:"serverId"`
	Revision string `json:"revision"`
	State    string `json:"state"`
}

type grantRevoked struct {
	Kind     string `json:"kind"`
	GrantID  string `json:"grantId"`
	Revision string `json:"revision"`
	State    string `json:"state"`
}

func aggregateEnvelope(tenantID, eventType, subject, aggregateType, aggregateID string, revision uint64, correlationID string, now time.Time, payload any) (Envelope, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{
		EventID: uuid.NewString(), EventType: eventType, SchemaVersion: 1, Producer: Producer, Subject: subject, TenantID: tenantID,
		AggregateType: aggregateType, AggregateID: aggregateID, AggregateRevision: fmt.Sprintf("%d", revision),
		OccurredAt: now.UTC().Format("2006-01-02T15:04:05.000000Z"), CorrelationID: correlationID, Payload: raw,
	}, nil
}

// CatalogReviewedEvent is mcp.catalog-reviewed for an approved, rejected or
// disabled descriptor revision.
func CatalogReviewedEvent(d Descriptor, correlationID string, now time.Time) (Envelope, error) {
	return aggregateEnvelope(d.TenantID, "mcp.catalog-reviewed", SubjectCatalogReviewed, AggregateDescriptor, d.ServerID, d.Revision, correlationID, now,
		catalogReviewed{Kind: "mcp.catalog-reviewed", ServerID: d.ServerID, Revision: fmt.Sprintf("%d", d.Revision), State: string(d.State)})
}

// GrantRevokedEvent is mcp.grant-revoked when a revocation commits
// (revoking) and when its barrier converged (revoked).
func GrantRevokedEvent(g Grant, correlationID string, now time.Time) (Envelope, error) {
	return aggregateEnvelope(g.TenantID, "mcp.grant-revoked", SubjectGrantRevoked, AggregateGrant, g.GrantID, g.Revision, correlationID, now,
		grantRevoked{Kind: "mcp.grant-revoked", GrantID: g.GrantID, Revision: fmt.Sprintf("%d", g.Revision), State: string(g.State)})
}
