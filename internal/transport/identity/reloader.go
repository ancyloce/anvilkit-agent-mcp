package identity

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Reloader keeps the current Material of one set of files and polls them
// for changes. A changed set is validated as a whole and published
// atomically; an invalid candidate (a missing file during a swap, a key
// that does not match, an expired leaf, an empty bundle) is logged and
// leaves the current material in force. There is no fallback: a Reloader
// without valid material never existed, because New refuses to construct
// one.
type Reloader struct {
	files    Files
	interval time.Duration
	log      *slog.Logger
	now      func() time.Time
	current  atomic.Pointer[Material]
	// failures counts rejected candidates since the last successful load;
	// it is the failure signal of an operator-visible metric or log.
	failures atomic.Int64
	mu       sync.Mutex
	onChange []func(previous, current *Material)
	cancel   context.CancelFunc
	done     chan struct{}
}

// New loads the files once (refusing invalid material) and starts no
// polling until Start.
func New(f Files, interval time.Duration, log *slog.Logger) (*Reloader, error) {
	if f.CertFile == "" || f.KeyFile == "" || f.CAFile == "" {
		return nil, fmt.Errorf("identity: cert_file, key_file and ca_file are required")
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	r := &Reloader{files: f, interval: interval, log: log, now: time.Now}
	m, err := Load(f, r.now())
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	r.current.Store(m)
	return r, nil
}

// Current is the material every new handshake uses.
func (r *Reloader) Current() *Material { return r.current.Load() }

// Failures is the number of rejected candidates since the last accepted one.
func (r *Reloader) Failures() int64 { return r.failures.Load() }

// OnChange registers a callback run after a new material is published.
func (r *Reloader) OnChange(fn func(previous, current *Material)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onChange = append(r.onChange, fn)
}

// Start polls until Stop.
func (r *Reloader) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		t := time.NewTicker(r.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				r.Reload()
			}
		}
	}()
}

// Stop ends polling.
func (r *Reloader) Stop() {
	r.mu.Lock()
	cancel, done := r.cancel, r.done
	r.cancel = nil
	r.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// Reload checks the files once; it returns whether a new material was
// published. Callers other than the poller are tests and operators.
func (r *Reloader) Reload() bool {
	cur := r.current.Load()
	digest, err := filesDigest(r.files)
	if err != nil {
		// A file is missing mid-swap or unreadable: keep the current material.
		r.failures.Add(1)
		r.log.Warn("identity reload rejected; current material kept", "error", err.Error())
		return false
	}
	if digest == cur.Digest {
		return false
	}
	m, err := Load(r.files, r.now())
	if err != nil {
		r.failures.Add(1)
		r.log.Warn("identity reload rejected; current material kept", "error", err.Error())
		return false
	}
	r.failures.Store(0)
	r.current.Store(m)
	r.mu.Lock()
	fns := append([]func(previous, current *Material){}, r.onChange...)
	r.mu.Unlock()
	for _, fn := range fns {
		fn(cur, m)
	}
	r.log.Info("identity material reloaded", "leafNotAfter", m.Leaf.NotAfter.UTC().Format(time.RFC3339), "trustedRoots", len(m.Roots), "retiredRoots", retired(cur, m))
	return true
}

// retired counts the roots trusted before and not after a reload.
func retired(previous, current *Material) int {
	n := 0
	for fp := range previous.Roots {
		if _, ok := current.Roots[fp]; !ok {
			n++
		}
	}
	return n
}

// RetiredRoots lists the previous roots a reload dropped.
func RetiredRoots(previous, current *Material) []*x509.Certificate {
	var out []*x509.Certificate
	for fp, c := range previous.Roots {
		if _, ok := current.Roots[fp]; !ok {
			out = append(out, c)
		}
	}
	return out
}
