// Package bootstrap assembles MCP with Fx (A08): the first configuration
// generation, logging, metrics, the generation-owned pool and forwarder,
// the owner use case, the gRPC transport, the lease sweeper and the
// generation watcher. Constructors only assemble; OnStart binds, probes and
// serves in dependency order and unwinds on failure; OnStop withdraws
// readiness, drains the server, stops the loops and closes dependencies
// last (DD-09 §3).
package bootstrap

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/control"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/config"
	grpctransport "github.com/ancyloce/anvilkit-agent-mcp/internal/transport/grpc"
)

// Module is the production assembly.
func Module() fx.Option {
	return fx.Options(
		fx.StopTimeout(6*time.Minute),
		fx.WithLogger(func(log *slog.Logger) fxevent.Logger { return &fxevent.SlogLogger{Logger: log} }),
		fx.Provide(
			config.Load,
			func() *slog.Logger {
				return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
			},
			func() application.Clock { return application.SystemClock{} },
			func() *prometheus.Registry {
				reg := prometheus.NewRegistry()
				reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
				return reg
			},
			func(reg *prometheus.Registry) *application.Metrics { return application.NewMetrics(reg) },
			// The first generation's runtime is built and probed before Fx
			// starts anything else: a rejected candidate never runs.
			func(gen config.Generation, metrics *application.Metrics, log *slog.Logger) (*runtime, error) {
				rt, err := buildRuntime(context.Background(), gen, metrics, log)
				if err != nil {
					metrics.ConfigRejections.Inc()
					return nil, fmt.Errorf("configuration generation %d rejected: %w", gen.Number, err)
				}
				return rt, nil
			},
			func(rt *runtime) *postgres.Store { return postgres.NewStore(rt.pool) },
			newDispatchQuery,
			func(gen config.Generation, store *postgres.Store, dispatch application.DispatchQuery, clock application.Clock, log *slog.Logger, metrics *application.Metrics) *application.Tasks {
				return application.NewTasks(store, dispatch, bounds(gen.Config), clock, log, metrics)
			},
			func(gen config.Generation, rt *runtime, store *postgres.Store, tasks *application.Tasks, metrics *application.Metrics, log *slog.Logger) *Generations {
				return newGenerations(configPath(), os.Environ(), gen, store, tasks, metrics, log)
			},
			func(gen config.Generation, tasks *application.Tasks) (*grpctransport.Server, error) {
				return grpctransport.NewServer(gen.Config.GRPC.Listen, gen.Config.GRPC.Capacity, tasks)
			},
			func(gen config.Generation, reg *prometheus.Registry) *Health {
				return NewHealth(gen.Config.Health.Listen, reg)
			},
		),
		fx.Invoke(run),
	)
}

func newDispatchQuery(lc fx.Lifecycle, gen config.Generation, log *slog.Logger) (application.DispatchQuery, error) {
	if gen.Config.Control.Address == "" {
		log.Warn("no Control placement: expired external-effect leases are never reassigned (control.address unset)")
		return application.NoDispatchQuery{}, nil
	}
	q, err := control.Dial(gen.Config.Control.Address, gen.Config.Control.Timeout)
	if err != nil {
		return nil, err
	}
	lc.Append(fx.Hook{OnStop: func(context.Context) error { return q.Close() }})
	return q, nil
}

// run orders the lifecycle: health listener, gRPC bind, generation
// activation (pool published, forwarder started), sweeper and watcher,
// then serving; stop in reverse with bounded drains and the generation's
// dependencies closed last.
func run(lc fx.Lifecycle, gen config.Generation, rt *runtime, gens *Generations, tasks *application.Tasks, srv *grpctransport.Server, health *Health, metrics *application.Metrics, log *slog.Logger) {
	cfg := gen.Config
	health.valid = tasks.Ready
	loops, cancelLoops := context.WithCancel(context.Background())
	sweeperDone := make(chan struct{})
	watcherDone := make(chan struct{})
	started := false
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) (err error) {
			// A failed start unwinds what this hook and the constructors
			// created: the health listener, the bound gRPC listener and the
			// generation's pool and forwarder; no listener or loop survives.
			defer func() {
				if err != nil {
					srv.Close()
					_ = health.Stop(context.Background())
					rt.retire(cfg.Reload.DrainLimit, log)
				}
			}()
			if _, err = health.Start(); err != nil {
				return fmt.Errorf("health listener: %w", err)
			}
			if _, err = srv.Listen(); err != nil {
				return err
			}
			gens.activate(rt)
			go func() {
				defer close(sweeperDone)
				t := time.NewTicker(cfg.Tasks.SweepInterval)
				defer t.Stop()
				for {
					select {
					case <-loops.Done():
						return
					case <-t.C:
						if _, err := tasks.SweepExpired(loops, 100); err != nil && loops.Err() == nil {
							log.Warn("lease sweep failed", "error", err)
						}
						tasks.Observe(loops, cfg.Outbox.ConsumerGroup)
					}
				}
			}()
			go func() { defer close(watcherDone); gens.Watch(loops, cfg.Reload.Interval) }()
			srv.Serve()
			health.SetReady(true)
			started = true
			log.Info("mcp serving", "listen", cfg.GRPC.Listen, "health", cfg.Health.Listen, "forwarder", cfg.Outbox.ForwarderEnabled, "generation", gen.Number)
			return nil
		},
		OnStop: func(ctx context.Context) error {
			begin := time.Now()
			forced := false
			health.SetReady(false)
			if started {
				forced = srv.Stop(cfg.GRPC.ShutdownTimeout) || forced
			} else {
				srv.Close()
			}
			cancelLoops()
			for _, done := range []chan struct{}{sweeperDone, watcherDone} {
				select {
				case <-done:
				case <-ctx.Done():
					forced = true
				}
			}
			forced = gens.Shutdown(cfg.Reload.DrainLimit) || forced
			metrics.DrainSeconds.Set(time.Since(begin).Seconds())
			if forced {
				metrics.ForcedStop.Set(1)
			}
			log.Info("mcp stopped", "drainSeconds", time.Since(begin).Seconds(), "forced", forced)
			return health.Stop(ctx)
		},
	})
}
