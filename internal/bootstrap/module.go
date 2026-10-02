// Package bootstrap assembles MCP with Fx (A08): the first configuration
// generation, logging, metrics, the generation-owned pool and forwarder,
// the owner use case, the gRPC transport, the lease sweeper and the
// generation watcher. Constructors only assemble; OnStart binds, probes and
// serves in dependency order and unwinds on failure; OnStop withdraws
// readiness, drains the server, stops the loops and closes dependencies
// last (DD-09 §3).
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/contextforge"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/control"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/upstream"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/config"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
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
			newAuthorizer,
			newPolicyRegistry,
			newConnectionLayer,
			func(store *postgres.Store, authz *application.Authorizer, registry application.PolicyRegistry, clock application.Clock, log *slog.Logger, metrics *application.Metrics) *application.Grants {
				return application.NewGrants(store, authz, registry, clock, log, metrics)
			},
			newEgress,
			func(gen config.Generation, store *postgres.Store, conn application.ConnectionLayer, authz *application.Authorizer, grants *application.Grants, eg *egress, clock application.Clock, log *slog.Logger) *application.Catalog {
				return application.NewCatalog(store, conn, authz, eg.guard.Policy, application.SystemResolver, grants, clock, log).WithIssuers(eg.authority)
			},
			newToolDispatcher,
			func(gen config.Generation, store *postgres.Store, dispatch application.ToolDispatcher, eg *egress, clock application.Clock, metrics *application.Metrics, log *slog.Logger) *application.Calls {
				c := gen.Config.Calls
				routes := make([]application.QualifiedRoute, 0, len(c.QualifiedRoutes))
				for _, r := range c.QualifiedRoutes {
					routes = append(routes, application.QualifiedRoute{Resource: r.Resource, ProtocolVersion: r.ProtocolVersion, Transport: r.Transport, Route: r.Route})
				}
				if len(routes) == 0 {
					log.Warn("no qualified tool routes: every tool call is refused (calls.qualified_routes empty)")
				}
				ups := map[string]application.Upstream{upstream.SDKRoute: upstream.NewRoute(eg.client, version)}
				return application.NewCalls(store, dispatch, ups, eg.authority, routes, application.CallOptions{
					SendTimeout: c.SendTimeout, Wait: c.Wait, ReconcileAge: c.ReconcileAge, ReconcileBatch: 50,
				}, clock, metrics, log)
			},
			func(gen config.Generation, tasks *application.Tasks, catalog *application.Catalog, grants *application.Grants, calls *application.Calls) (*grpctransport.Server, error) {
				return grpctransport.NewServer(gen.Config.GRPC.Listen, gen.Config.GRPC.Capacity, tasks, catalog, grants, calls)
			},
			func(gen config.Generation, reg *prometheus.Registry) *Health {
				return NewHealth(gen.Config.Health.Listen, reg)
			},
		),
		fx.Invoke(startTracing),
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

// newAuthorizer builds the local marketplace authorization from the mounted
// role bindings (DEVELOPMENT_ONLY source until IdP groups, ENV-02).
func newAuthorizer(gen config.Generation, log *slog.Logger) (*application.Authorizer, error) {
	bindings, err := application.LoadRoleBindings(gen.Config.Catalog.RolesFile)
	if err != nil {
		return nil, err
	}
	if len(bindings) == 0 {
		log.Warn("no role bindings: nobody may discover, review, disable or grant (catalog.roles_file unset or empty)")
	}
	return application.NewAuthorizer(bindings)
}

// noRegistry is the placement-less Control: every barrier call is an
// unknown outcome, so grants stay PENDING (never executable) and
// revocations stay REVOKING (restrictive) until a Control placement exists.
type noRegistry struct{}

var errNoControl = errors.New("no Control placement (control.address unset)")

func (noRegistry) Register(context.Context, application.ControlCommand, domain.Grant) (string, uint64, error) {
	return "", 0, errNoControl
}
func (noRegistry) BeginRevocation(context.Context, application.ControlCommand, string, uint64) (application.Barrier, error) {
	return application.Barrier{}, errNoControl
}
func (noRegistry) Revocation(context.Context, string, uint64) (application.Barrier, error) {
	return application.Barrier{}, errNoControl
}

func newPolicyRegistry(lc fx.Lifecycle, gen config.Generation, log *slog.Logger) (application.PolicyRegistry, error) {
	if gen.Config.Control.Address == "" {
		log.Warn("no Control placement: grants stay pending and revocations stay revoking (control.address unset)")
		return noRegistry{}, nil
	}
	p, err := control.DialPolicy(gen.Config.Control.Address, gen.Config.Control.Timeout)
	if err != nil {
		return nil, err
	}
	lc.Append(fx.Hook{OnStop: func(context.Context) error { return p.Close() }})
	return p, nil
}

// egress is MCP's own guarded egress: the network policy of the reviewed
// hosts applied at every connection, the bounded no-redirect client and
// the upstream authority (protected-resource metadata, resource-bound
// tokens from the mounted credential bindings).
type egress struct {
	guard     upstream.Guard
	client    *http.Client
	authority *upstream.Authority
}

// version is the implementation version MCP announces upstream.
const version = "0.1.0"

func newEgress(gen config.Generation, log *slog.Logger) (*egress, error) {
	guard := upstream.Guard{
		Policy:   application.NetworkPolicy{AllowedHosts: gen.Config.Catalog.AllowedHosts, PrivateHosts: gen.Config.Catalog.PrivateHosts},
		Resolver: application.SystemResolver,
	}
	client := guard.Client(gen.Config.Calls.MaxResponseBytes, gen.Config.Calls.SendTimeout)
	creds, err := loadCredentials(gen.Config.Calls.CredentialsFile)
	if err != nil {
		return nil, err
	}
	if len(gen.Config.Catalog.PrivateHosts) > 0 {
		log.Warn("DEVELOPMENT_ONLY private upstream hosts allowed (http and private addresses)", "hosts", gen.Config.Catalog.PrivateHosts)
	}
	return &egress{guard: guard, client: client, authority: upstream.NewAuthority(guard, client, creds, time.Now)}, nil
}

// loadCredentials reads the mounted upstream credential bindings: a JSON
// list of {resource, issuer, clientId, clientSecretFile, scopes}; the
// secrets themselves stay in their own mounted files.
func loadCredentials(path string) ([]upstream.Credential, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("upstream credentials: %w", err)
	}
	var in []struct {
		Resource         string   `json:"resource"`
		Issuer           string   `json:"issuer"`
		ClientID         string   `json:"clientId"`
		ClientSecretFile string   `json:"clientSecretFile"`
		Scopes           []string `json:"scopes"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("upstream credentials: %w", err)
	}
	out := make([]upstream.Credential, 0, len(in))
	for i, c := range in {
		if c.Resource == "" || c.Issuer == "" || c.ClientID == "" || c.ClientSecretFile == "" {
			return nil, fmt.Errorf("upstream credentials[%d]: resource, issuer, clientId and clientSecretFile are required", i)
		}
		out = append(out, upstream.Credential{Resource: c.Resource, Issuer: c.Issuer, ClientID: c.ClientID, ClientSecretFile: c.ClientSecretFile, Scopes: c.Scopes})
	}
	return out, nil
}

// noToolDispatch is the placement-less Control: AdmitTool never answers, so
// accepted calls stay accepted and nothing is ever sent.
type noToolDispatch struct{}

func (noToolDispatch) AdmitTool(context.Context, application.ToolAdmit) (application.ToolAdmission, error) {
	return application.ToolAdmission{}, errNoControl
}
func (noToolDispatch) ObserveTool(context.Context, string, uint64, string, *uint64, time.Time) error {
	return errNoControl
}
func (noToolDispatch) GetTool(context.Context, string) (application.DispatchView, error) {
	return application.DispatchView{}, errNoControl
}

func newToolDispatcher(lc fx.Lifecycle, gen config.Generation, log *slog.Logger) (application.ToolDispatcher, error) {
	if gen.Config.Control.Address == "" {
		log.Warn("no Control placement: tool calls are never admitted (control.address unset)")
		return noToolDispatch{}, nil
	}
	d, err := control.Dial(gen.Config.Control.Address, gen.Config.Control.Timeout)
	if err != nil {
		return nil, err
	}
	lc.Append(fx.Hook{OnStop: func(context.Context) error { return d.Close() }})
	return d, nil
}

// noConnectionLayer refuses discovery without a ContextForge placement.
type noConnectionLayer struct{}

func (noConnectionLayer) Discover(context.Context, string) (domain.LiveServer, error) {
	return domain.LiveServer{}, fmt.Errorf("%w: no ContextForge placement (catalog.contextforge.url unset)", contextforge.ErrUnavailable)
}

func newConnectionLayer(gen config.Generation, log *slog.Logger) application.ConnectionLayer {
	cf := gen.Config.Catalog.ContextForge
	if cf.URL == "" {
		log.Warn("no ContextForge placement: nothing is discovered (catalog.contextforge.url unset)")
		return noConnectionLayer{}
	}
	return contextforge.New(cf.URL, cf.TokenFile, cf.Timeout)
}

// run orders the lifecycle: health listener, gRPC bind, generation
// activation (pool published, forwarder started), sweeper and watcher,
// then serving; stop in reverse with bounded drains and the generation's
// dependencies closed last.
func run(lc fx.Lifecycle, gen config.Generation, rt *runtime, gens *Generations, tasks *application.Tasks, grants *application.Grants, calls *application.Calls, srv *grpctransport.Server, health *Health, metrics *application.Metrics, log *slog.Logger) {
	cfg := gen.Config
	health.valid = tasks.Ready
	loops, cancelLoops := context.WithCancel(context.Background())
	sweeperDone := make(chan struct{})
	watcherDone := make(chan struct{})
	barrierDone := make(chan struct{})
	callsDone := make(chan struct{})
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
			// Open grant barriers are advanced under their original command
			// identities (uncertain registrations, fences, convergence).
			go func() {
				defer close(barrierDone)
				t := time.NewTicker(cfg.Barrier.ReconcileInterval)
				defer t.Stop()
				for {
					select {
					case <-loops.Done():
						return
					case <-t.C:
						if _, err := grants.Reconcile(loops, cfg.Barrier.ReconcileAge, 50); err != nil && loops.Err() == nil {
							log.Warn("grant barrier reconciliation failed", "error", err)
						}
					}
				}
			}()
			// Open tool calls are advanced under their original identities
			// (uncertain admissions, abandoned senders, UNKNOWN outcomes).
			go func() {
				defer close(callsDone)
				t := time.NewTicker(cfg.Calls.ReconcileInterval)
				defer t.Stop()
				for {
					select {
					case <-loops.Done():
						return
					case <-t.C:
						if _, err := calls.Reconcile(loops); err != nil && loops.Err() == nil {
							log.Warn("tool call reconciliation failed", "error", err)
						}
					}
				}
			}()
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
			for _, done := range []chan struct{}{sweeperDone, watcherDone, barrierDone, callsDone} {
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
