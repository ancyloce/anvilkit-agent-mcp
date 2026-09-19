// Package outbox binds the pinned watermill-sql PostgreSQL adapter to the
// owner's transactions (C07, DD-09 §2). The physical schema is migration
// 00002's outbox/outbox_offsets; nothing here initializes schema. Every
// event is published through the forwarder envelope so the forwarder
// module (and the Knowledge sidecar, which reads the identical schema)
// unwraps it and publishes to the destination subject.
package outbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-sql/v4/pkg/sql"
	"github.com/ThreeDotsLabs/watermill/components/forwarder"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/jackc/pgx/v5"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// The forwarder topic and the physical table names of the adapter.
const (
	ForwarderTopic = "outbox"
	MessagesTable  = `"outbox"`
	OffsetsTable   = `"outbox_offsets"`
)

// Metadata keys carried beside the envelope (they become NATS headers).
const (
	MetadataEventType = "anvilkit_event_type"
	MetadataTenantID  = "anvilkit_tenant_id"
	MetadataSchema    = "anvilkit_schema_version"
)

// Schema is the adapter's PostgreSQL schema with the owner's table names.
func Schema(batchSize int) sql.DefaultPostgreSQLSchema {
	return sql.DefaultPostgreSQLSchema{
		GenerateMessagesTableName: func(string) string { return MessagesTable },
		SubscribeBatchSize:        batchSize,
	}
}

// Offsets is the adapter's offsets schema with the owner's table name.
func Offsets() sql.DefaultPostgreSQLOffsetsAdapter {
	return sql.DefaultPostgreSQLOffsetsAdapter{GenerateMessagesOffsetsTableName: func(string) string { return OffsetsTable }}
}

// Publish inserts the envelope into the outbox of the given transaction:
// the same pgx.Tx the domain writes use, so both commit or roll back
// together. The watermill message UUID is the eventId (a standard UUID);
// the forwarder wrapper allocates its own row UUID.
func Publish(ctx context.Context, tx pgx.Tx, env domain.Envelope) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	pub, err := sql.NewPublisher(sql.TxFromPgx(tx), sql.PublisherConfig{SchemaAdapter: Schema(0), AutoInitializeSchema: false}, watermill.NopLogger{})
	if err != nil {
		return fmt.Errorf("outbox publisher: %w", err)
	}
	msg := message.NewMessage(env.EventID, raw)
	msg.Metadata.Set(MetadataEventType, env.EventType)
	msg.Metadata.Set(MetadataTenantID, env.TenantID)
	msg.Metadata.Set(MetadataSchema, "1")
	msg.SetContext(ctx)
	fp := forwarder.NewPublisher(pub, forwarder.PublisherConfig{ForwarderTopic: ForwarderTopic})
	if err := fp.Publish(env.Subject, msg); err != nil {
		return fmt.Errorf("outbox insert: %w", err)
	}
	return nil
}
