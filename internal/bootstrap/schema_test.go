package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/testdb"
)

// P3.1 AC4 (MIG-02): a replica whose database is behind the binary's
// minimum schema stays not ready with the version pair in the readiness
// reason and the log; it becomes ready once the version is reached,
// without a restart; a schema ahead of the minimum is accepted.
func TestSchemaBehindTheMinimumWithholdsReadiness(t *testing.T) {
	require.EqualError(t, schemaVerdict(6, 7), "schema at version 6, the binary needs at least 7")
	require.NoError(t, schemaVerdict(7, 7))
	require.NoError(t, schemaVerdict(8, 7), "an expand migration of the next release does not stop this image")

	inst := testdb.Start(t)
	pool := inst.Pool(t)
	// The applied version as the migration Job left it, one behind the minimum.
	inst.Admin(t, fmt.Sprintf("DELETE FROM goose_db_version WHERE version_id = %d", MinimumSchemaVersion))

	h := NewHealth("127.0.0.1:0", prometheus.NewRegistry())
	addr, err := h.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = h.Stop(context.Background()) })
	h.SetReady(true)
	var logged bytes.Buffer
	var mu sync.Mutex
	log := slog.New(slog.NewTextHandler(writerFunc(func(p []byte) (int, error) { mu.Lock(); defer mu.Unlock(); return logged.Write(p) }), nil))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchSchema(ctx, h, func() *pgxpool.Pool { return pool }, MinimumSchemaVersion, 20*time.Millisecond, log)
	}()

	ready := func() (int, string) {
		resp, err := http.Get("http://" + addr.String() + "/readyz")
		if err != nil {
			return 0, ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	pair := fmt.Sprintf("schema at version %d, the binary needs at least %d", MinimumSchemaVersion-1, MinimumSchemaVersion)
	require.Eventually(t, func() bool { code, body := ready(); return code == 503 && body == "schema: "+pair }, 10*time.Second, 10*time.Millisecond)
	mu.Lock()
	require.Contains(t, logged.String(), pair, "the version pair is logged")
	mu.Unlock()

	inst.Admin(t, fmt.Sprintf("INSERT INTO goose_db_version (version_id, is_applied) VALUES (%d, true)", MinimumSchemaVersion))
	require.Eventually(t, func() bool { code, _ := ready(); return code == 200 }, 10*time.Second, 10*time.Millisecond, "the migrated schema makes the replica ready without a restart")
	<-done
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
