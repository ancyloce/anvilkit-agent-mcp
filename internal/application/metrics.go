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
	GrantTransitions *prometheus.CounterVec
	CallTransitions  *prometheus.CounterVec
	EventProjections *prometheus.CounterVec
	// P3.6: the UNKNOWN calls, the servers they restrict and the refusals.
	UnknownCalls       prometheus.Gauge
	RestrictedServers  prometheus.Gauge
	UnknownOldest      prometheus.Gauge
	RestrictedRefusals prometheus.Counter
	// P3.7: delivery rows deleted past their retention, by table.
	DeliveryPruned *prometheus.CounterVec
	// P3.6 (platform.md SLO row 3): the revocation barrier's milestones in
	// seconds from the revocation's commit, by stage (fenced, converged).
	RevocationSeconds *prometheus.HistogramVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Requests:           prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "anvilkit_mcp_background_requests", Help: "Durable background requests by state."}, []string{"state"}),
		Claims:             prometheus.NewCounterVec(prometheus.CounterOpts{Name: "anvilkit_mcp_background_claims_total", Help: "Claim decisions by outcome."}, []string{"outcome"}),
		Submissions:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "anvilkit_mcp_background_submissions_total", Help: "Result submissions by outcome."}, []string{"outcome"}),
		LeaseOverruns:      prometheus.NewCounter(prometheus.CounterOpts{Name: "anvilkit_mcp_background_lease_overruns_total", Help: "Leases that expired before a result was submitted."}),
		OverdueRetries:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_background_overdue_retries", Help: "retry_scheduled requests whose retry time has passed without a claim (durable-request versus queue difference)."}),
		OutboxOldest:       prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_outbox_oldest_unforwarded_seconds", Help: "Age of the oldest outbox message the forwarder has not acknowledged."}),
		Forwarded:          prometheus.NewCounter(prometheus.CounterOpts{Name: "anvilkit_mcp_outbox_forwarded_total", Help: "Outbox messages published to JetStream."}),
		ForwardFailures:    prometheus.NewCounter(prometheus.CounterOpts{Name: "anvilkit_mcp_outbox_forward_failures_total", Help: "Forwarder publish failures (the message is retried)."}),
		ConfigGeneration:   prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_config_generation", Help: "Number of the active configuration generation."}),
		ConfigRejections:   prometheus.NewCounter(prometheus.CounterOpts{Name: "anvilkit_mcp_config_rejections_total", Help: "Candidate configuration generations rejected by validation, construction or probe."}),
		ConfigRotations:    prometheus.NewCounter(prometheus.CounterOpts{Name: "anvilkit_mcp_config_rotations_total", Help: "Generations published after a secret or snapshot change."}),
		DrainSeconds:       prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_shutdown_drain_seconds", Help: "Seconds the last shutdown spent draining before dependencies closed."}),
		ForcedStop:         prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_shutdown_forced", Help: "1 when the last shutdown had to force-stop a server or loop."}),
		PoolAcquired:       prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_db_pool_acquired_connections", Help: "Connections of the active generation's pool currently acquired."}),
		PoolTotal:          prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_db_pool_total_connections", Help: "Connections of the active generation's pool."}),
		DispatchQueries:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "anvilkit_mcp_background_dispatch_queries_total", Help: "Original-dispatch queries for expired external-effect leases by answer."}, []string{"answer"}),
		GrantTransitions:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "anvilkit_mcp_grant_transitions_total", Help: "Grant state transitions by the state reached (pending, active, registration_failed, revoking, revoked)."}, []string{"state"}),
		CallTransitions:    prometheus.NewCounterVec(prometheus.CounterOpts{Name: "anvilkit_mcp_tool_call_transitions_total", Help: "Tool call state transitions by the state reached (accepted, admitted, sent, succeeded, failed, denied, unknown, canceled)."}, []string{"state"}),
		EventProjections:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "anvilkit_mcp_event_projections_total", Help: "Catalog and grant events the credential projection consumed by outcome (applied, stale, rejected)."}, []string{"outcome"}),
		UnknownCalls:       prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_tool_calls_unknown", Help: "Tool calls whose outcome is UNKNOWN (each restricts new calls to its server for its tenant)."}),
		RestrictedServers:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_recovery_restricted_servers", Help: "(tenant, server) pairs restricted by an UNKNOWN call (RECOVERY_RESTRICTED)."}),
		UnknownOldest:      prometheus.NewGauge(prometheus.GaugeOpts{Name: "anvilkit_mcp_tool_call_unknown_oldest_seconds", Help: "Age of the oldest UNKNOWN tool call since it last changed; 0 when there is none."}),
		RestrictedRefusals: prometheus.NewCounter(prometheus.CounterOpts{Name: "anvilkit_mcp_recovery_restricted_refusals_total", Help: "Tool calls refused with RECOVERY_RESTRICTED."}),
		DeliveryPruned:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "anvilkit_mcp_delivery_pruned_total", Help: "Delivery rows (acknowledged outbox, old inbox, terminal requests' attempts) deleted past their retention, by table."}, []string{"table"}),
		RevocationSeconds: prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "anvilkit_mcp_grant_revocation_seconds",
			Help:    "Seconds from a grant revocation's commit to Control's fence (stage fenced: no new tool admission) and to REVOKED (stage converged: every sender converged), observed once per revocation.",
			Buckets: prometheus.ExponentialBuckets(0.01, 2, 22)}, []string{"stage"}),
	}
	for _, c := range []prometheus.Collector{m.Requests, m.Claims, m.Submissions, m.LeaseOverruns, m.OverdueRetries, m.OutboxOldest, m.Forwarded, m.ForwardFailures, m.ConfigGeneration, m.ConfigRejections, m.ConfigRotations, m.DrainSeconds, m.ForcedStop, m.PoolAcquired, m.PoolTotal, m.DispatchQueries, m.GrantTransitions, m.CallTransitions, m.EventProjections, m.UnknownCalls, m.RestrictedServers, m.UnknownOldest, m.RestrictedRefusals, m.DeliveryPruned, m.RevocationSeconds} {
		reg.MustRegister(c)
	}
	return m
}
