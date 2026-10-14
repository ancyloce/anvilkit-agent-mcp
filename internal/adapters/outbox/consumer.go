package outbox

import (
	"context"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Stream is the JetStream stream that captures MCP's subjects
// (anvilkit.mcp.>), a deployment input.
const Stream = "ANVILKIT_MCP"

// Consume reads the subjects through an ordered JetStream consumer of this
// replica from the newest message (P2.8: the credential projection) and
// passes every message to handle until ctx ends. The ordered consumer
// recreates itself after a gap or a lost connection; one that cannot be
// created (the stream is absent, the connection is down) is retried with
// backoff. Nothing is acknowledged: the consumer holds no durable state.
func Consume(ctx context.Context, nc *nats.Conn, subjects []string, handle func(context.Context, []byte), log *slog.Logger) {
	js, err := jetstream.New(nc)
	if err != nil {
		log.Error("event consumer unavailable", "error", err)
		return
	}
	const first = time.Second
	backoff := first
	for ctx.Err() == nil {
		cons, err := js.OrderedConsumer(ctx, Stream, jetstream.OrderedConsumerConfig{FilterSubjects: subjects, DeliverPolicy: jetstream.DeliverNewPolicy})
		if err == nil {
			var cc jetstream.ConsumeContext
			if cc, err = cons.Consume(func(m jetstream.Msg) { handle(ctx, m.Data()) }); err == nil {
				backoff = first
				select {
				case <-ctx.Done():
				case <-cc.Closed():
				}
				cc.Stop()
				continue
			}
		}
		if ctx.Err() != nil {
			return
		}
		log.Warn("event consumer unavailable; retrying", "error", err, "retryIn", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}
