package application

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics are the lane's Prometheus signals (DD-09 §6): request counts by
// state, claim and submission outcomes, lease overruns, the oldest
// unforwarded outbox message, inbox duplicates seen by the owner's relay,
// forwarder counters, the configuration generation and the shutdown
// drain. Labels are controlled vocabularies; no identifier or body is a
// label value.
type Metrics struct {
	Requests         *prometheus.GaugeVec
	Claims           *prometheus.CounterVec
	Submissions      *prometheus.CounterVec
	LeaseOverruns    prometheus.Counter
	OverdueRetries   prometheus.Gauge
	OutboxOldest     prometheus.Gauge
	Forwarded        prometheus.Counter
	ForwardFailures  prometheus.Counter
	ConfigGeneration prometheus.Gauge
	ConfigRejections prometheus.Counter
	ConfigRotations  prometheus.Counter
	DrainSeconds     prometheus.Gauge
	ForcedStop       prometheus.Gauge
	PoolAcquired     prometheus.Gauge
	PoolTotal        prometheus.Gauge
	DispatchQueries  *prometheus.CounterVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Requests:         prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "anvilkit_mcp_background_requests", Help: "Durable background requests by state."}, []string{"state"}),
		Claims:           prometheus.NewCounterVec(prometheus.CounterOpts{Name: "anvilkit_mcp_background_claims_total", Help: "Claim decisions by outcome."}, []string{"outcome"}),
		Submissions:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "anvilkit_mcp_background_submissions_total", Help: "Result submissions by outcome."}, []string{"outcome"}),
		LeaseOverruns:    prometheus.NewCounter(prometheus.CounterOpts{Name: "anvilkit_mcp_background_lease_overruns_total", Help: "Leases that expired before a result was submitted."}),
		OverdueRetries:   prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_background_overdue_retries", Help: "retry_scheduled requests whose retry time has passed without a claim (durable-request versus queue difference)."}),
		OutboxOldest:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_outbox_oldest_unforwarded_seconds", Help: "Age of the oldest outbox message the forwarder has not acknowledged."}),
		Forwarded:        prometheus.NewCounter(prometheus.CounterOpts{Name: "anvilkit_mcp_outbox_forwarded_total", Help: "Outbox messages published to JetStream."}),
		ForwardFailures:  prometheus.NewCounter(prometheus.CounterOpts{Name: "anvilkit_mcp_outbox_forward_failures_total", Help: "Forwarder publish failures (the message is retried)."}),
		ConfigGeneration: prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_config_generation", Help: "Number of the active configuration generation."}),
		ConfigRejections: prometheus.NewCounter(prometheus.CounterOpts{Name: "anvilkit_mcp_config_rejections_total", Help: "Candidate configuration generations rejected by validation, construction or probe."}),
		ConfigRotations:  prometheus.NewCounter(prometheus.CounterOpts{Name: "anvilkit_mcp_config_rotations_total", Help: "Generations published after a secret or snapshot change."}),
		DrainSeconds:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_shutdown_drain_seconds", Help: "Seconds the last shutdown spent draining before dependencies closed."}),
		ForcedStop:       prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_shutdown_forced", Help: "1 when the last shutdown had to force-stop a server or loop."}),
		PoolAcquired:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_db_pool_acquired_connections", Help: "Connections of the active generation's pool currently acquired."}),
		PoolTotal:        prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_db_pool_total_connections", Help: "Connections of the active generation's pool."}),
		DispatchQueries:  prometheus.NewCounterVec(prometheus.CounterOpts{Name: "anvilkit_mcp_background_dispatch_queries_total", Help: "Original-dispatch queries for expired external-effect leases by answer."}, []string{"answer"}),
	}
	for _, c := range []prometheus.Collector{m.Requests, m.Claims, m.Submissions, m.LeaseOverruns, m.OverdueRetries, m.OutboxOldest, m.Forwarded, m.ForwardFailures, m.ConfigGeneration, m.ConfigRejections, m.ConfigRotations, m.DrainSeconds, m.ForcedStop, m.PoolAcquired, m.PoolTotal, m.DispatchQueries} {
		reg.MustRegister(c)
	}
	return m
}
