package bootstrap

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Health is the plaintext probe and metrics listener: /healthz answers 200
// while the process runs, /readyz 200 only while the gRPC listener serves,
// the schema is at or above the binary's minimum and no shutdown has
// started, /metrics the Prometheus exposition. It is
// the first listener up and the last down so a scrape during the drain
// still sees the shutdown gauges.
type Health struct {
	srv   *http.Server
	ln    net.Listener
	ready atomic.Bool
	valid func() bool
	// schema is the reason readiness is withheld for the schema version
	// (P3.1 AC4); empty once the schema holds.
	schema atomic.Pointer[string]
}

func NewHealth(listen string, reg *prometheus.Registry) *Health {
	h := &Health{}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if reason := h.schema.Load(); reason != nil && *reason != "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("schema: " + *reason))
			return
		}
		if h.ready.Load() && (h.valid == nil || h.valid()) {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	h.srv = &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return h
}

func (h *Health) Start() (net.Addr, error) {
	ln, err := net.Listen("tcp", h.srv.Addr)
	if err != nil {
		return nil, err
	}
	h.ln = ln
	go func() { _ = h.srv.Serve(ln) }()
	return ln.Addr(), nil
}

func (h *Health) SetReady(ready bool) { h.ready.Store(ready) }

func (h *Health) setSchema(reason string) { h.schema.Store(&reason) }

func (h *Health) Stop(ctx context.Context) error {
	h.ready.Store(false)
	if h.ln == nil {
		return nil
	}
	return h.srv.Shutdown(ctx)
}
