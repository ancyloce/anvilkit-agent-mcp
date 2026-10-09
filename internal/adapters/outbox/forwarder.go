package outbox

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	wmjs "github.com/ThreeDotsLabs/watermill-nats/v2/pkg/jetstream"
	"github.com/ThreeDotsLabs/watermill-sql/v4/pkg/sql"
	"github.com/ThreeDotsLabs/watermill/components/forwarder"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus"
)

// ForwarderConfig are the reviewed bounds of the forwarder module.
type ForwarderConfig struct {
	ConsumerGroup  string
	PollInterval   time.Duration
	AckDeadline    time.Duration
	ResendInterval time.Duration
	BatchSize      int
	NATSURL        string
	NATSName       string
	PublishTimeout time.Duration
	CloseTimeout   time.Duration
	// NATSTLS is the verified transport (nil under the DEVELOPMENT_ONLY
	// plaintext foundation, admitted by the configuration guard only).
	NATSTLS *tls.Config
	// NATSCredsFile is the mounted client credential, a user .creds file or,
	// with NATSCredsNKey, a bare NKey user seed (classified by the
	// configuration); empty only under the DEVELOPMENT_ONLY foundation.
	NATSCredsFile string
	NATSCredsNKey bool
}

// Forwarder is the watermill forwarder (C07): the watermill-sql subscriber
// over outbox/outbox_offsets (its consumer group owns one offsets row; the
// FOR UPDATE of the adapter coordinates competing instances) publishing
// each unwrapped envelope to its destination subject on JetStream with
// Nats-Msg-Id = eventId (the stream's duplicate window absorbs a redelivery
// after a crash between publish and offset ack). Nothing here initializes
// schema or streams: both are deployment inputs.
type Forwarder struct {
	nc       *nats.Conn
	sub      *sql.Subscriber
	pub      *wmjs.Publisher
	fwd      *forwarder.Forwarder
	log      *slog.Logger
	closeTTL time.Duration
}

// NewForwarder builds the pieces and probes the NATS connection; nothing
// runs until Run.
func NewForwarder(pool *pgxpool.Pool, cfg ForwarderConfig, log *slog.Logger, forwarded, failures prometheus.Counter) (*Forwarder, error) {
	opts := []nats.Option{nats.Name(cfg.NATSName), nats.Timeout(cfg.PublishTimeout), nats.MaxReconnects(-1), nats.RetryOnFailedConnect(false)}
	if cfg.NATSTLS != nil {
		opts = append(opts, nats.Secure(cfg.NATSTLS))
	}
	creds, err := natsCredentials(cfg)
	if err != nil {
		return nil, err
	}
	if creds != nil {
		opts = append(opts, creds)
	}
	nc, err := nats.Connect(cfg.NATSURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	if _, err := jetstream.New(nc); err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream: %w", err)
	}
	wmLogger := watermill.NopLogger{}
	ack := cfg.AckDeadline
	sub, err := sql.NewSubscriber(sql.BeginnerFromPgx(pool), sql.SubscriberConfig{
		ConsumerGroup: cfg.ConsumerGroup, AckDeadline: &ack, PollInterval: cfg.PollInterval, ResendInterval: cfg.ResendInterval, RetryInterval: cfg.PollInterval,
		SchemaAdapter: Schema(cfg.BatchSize), OffsetsAdapter: Offsets(), InitializeSchema: false,
	}, wmLogger)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("outbox subscriber: %w", err)
	}
	pub, err := wmjs.NewPublisher(wmjs.PublisherConfig{
		Conn: nc, Logger: wmLogger, TrackMessageID: true,
		// The publisher only reads the stream name of this configurator as the
		// publish subject (watermill-nats v2.2.0); the destination topic of
		// the envelope is the subject, and the streams that capture it are
		// deployment inputs (ANVILKIT_MCP: anvilkit.mcp.>).
		ConfigureStream: func(topic string) jetstream.StreamConfig { return jetstream.StreamConfig{Name: topic} },
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream publisher: %w", err)
	}
	counted := &countingPublisher{Publisher: pub, forwarded: forwarded, failures: failures}
	fwd, err := forwarder.NewForwarder(sub, counted, wmLogger, forwarder.Config{ForwarderTopic: ForwarderTopic, HandlerName: "anvilkit-mcp-outbox-forwarder", CloseTimeout: cfg.CloseTimeout, AckWhenCannotUnwrap: false})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("forwarder: %w", err)
	}
	return &Forwarder{nc: nc, sub: sub, pub: pub, fwd: fwd, log: log, closeTTL: cfg.CloseTimeout}, nil
}

// natsCredentials is the authentication option of the connection (nil
// without a credential file). Both options read the mounted file when the
// connection authenticates, never at configuration time only: the .creds
// option re-reads the JWT and the seed on every (re)connect, so a rotated
// CSI file is presented on the next reconnect; the seed option derives the
// public key here and re-reads the seed to sign each nonce, so a seed
// rotated to a new key takes effect with the next configuration generation
// (the credential digest is part of its secret revision).
func natsCredentials(cfg ForwarderConfig) (nats.Option, error) {
	switch {
	case cfg.NATSCredsFile == "":
		return nil, nil
	case cfg.NATSCredsNKey:
		opt, err := nats.NkeyOptionFromSeed(cfg.NATSCredsFile)
		if err != nil {
			return nil, fmt.Errorf("nats credentials: %w", err)
		}
		return opt, nil
	default:
		return nats.UserCredentials(cfg.NATSCredsFile), nil
	}
}

// Run forwards until ctx ends or Close is called.
func (f *Forwarder) Run(ctx context.Context) error {
	return f.fwd.Run(ctx)
}

// Running is closed once the router consumes.
func (f *Forwarder) Running() chan struct{} { return f.fwd.Running() }

// Close stops the router (in-flight message handling ends within the close
// timeout), the subscriber and the NATS connection, in that order.
func (f *Forwarder) Close() error {
	err := f.fwd.Close()
	_ = f.sub.Close()
	f.nc.Close()
	return err
}

type countingPublisher struct {
	message.Publisher
	forwarded prometheus.Counter
	failures  prometheus.Counter
}

func (c *countingPublisher) Publish(topic string, msgs ...*message.Message) error {
	if err := c.Publisher.Publish(topic, msgs...); err != nil {
		c.failures.Inc()
		return err
	}
	c.forwarded.Add(float64(len(msgs)))
	return nil
}
