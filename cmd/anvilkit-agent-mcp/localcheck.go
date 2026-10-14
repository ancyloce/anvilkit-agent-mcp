//go:build localcheck

// The DEVELOPMENT_ONLY `local-check` subcommands (P14, behind the
// localcheck build tag since P2.5): the owner entry point that creates,
// cancels and reads requests of the fixture kind through the same
// application code and transactions the service uses. The production schema
// refuses the fixture kind; the development foundation's migration applies
// the fixture set that re-admits it.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/config"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

func init() { subcommands["local-check"] = localCheck }

func localCheck(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: local-check request|cancel|get [flags]")
	}
	fs := flag.NewFlagSet("local-check "+args[0], flag.ContinueOnError)
	taskID := fs.String("task-id", "", "task identity (default: a new UUID)")
	tenant := fs.String("tenant", "tenant_a", "tenant of the request")
	grant := fs.String("grant", "", "grant_id of the current authorization (grant:<id>)")
	payload := fs.String("bytes", "hello", "the bytes whose SHA-256 is the expected result")
	holdMs := fs.Int("hold-ms", 0, "make the handler hold this long (stall scenarios)")
	fail := fs.Bool("fail", false, "make the handler report a failure")
	wrong := fs.Bool("wrong-digest", false, "make the handler answer a wrong digest (profile mismatch)")
	effects := fs.String("effects", string(domain.EffectsReconstructible), "reconstructible or external")
	dispatch := fs.String("dispatch-id", "", "Control dispatch identity of an external-effect request")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	gen, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, gen.Config.Database.URL)
	if err != nil {
		return err
	}
	defer pool.Close()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	metrics := application.NewMetrics(prometheus.NewRegistry())
	c := gen.Config.Tasks
	tasks := application.NewTasks(postgres.NewStore(pool), application.NoDispatchQuery{}, domain.Bounds{MaxInputBytes: c.MaxInputBytes, MaxLease: c.MaxLease, RetryDelay: c.RetryDelay, MaxAttempts: c.MaxAttempts}, application.SystemClock{}, log, metrics)
	out := json.NewEncoder(os.Stdout)
	switch args[0] {
	case "request":
		if *taskID == "" {
			*taskID = "task_" + uuid.NewString()
		}
		if *grant == "" {
			return fmt.Errorf("-grant is required (the current authorization the request is bound to)")
		}
		input, err := json.Marshal(domain.LocalCheckInput{SchemaVersion: 1, Computation: domain.LocalCheckProfile, Bytes: base64.StdEncoding.EncodeToString([]byte(*payload)), HoldMs: *holdMs, Fail: *fail, WrongDigest: *wrong})
		if err != nil {
			return err
		}
		task, existing, err := tasks.Request(ctx, application.RequestInput{
			TaskID: *taskID, TenantID: *tenant, Kind: domain.KindLocalCheck, Profile: domain.LocalCheckProfile, Input: input,
			Effects: domain.Effects(*effects), DispatchID: *dispatch, AuthorizationRef: "grant:" + *grant, CorrelationID: "local-check-" + uuid.NewString(),
		})
		if err != nil {
			return err
		}
		ref, digest, _ := domain.ExpectedResult(task)
		return out.Encode(map[string]any{"taskId": task.TaskID, "generation": task.Generation, "inputDigest": task.InputDigest, "existing": existing, "expectedResultRef": ref, "expectedResultDigest": digest})
	case "cancel":
		task, changed, err := tasks.Cancel(ctx, *taskID)
		if err != nil {
			return err
		}
		return out.Encode(map[string]any{"taskId": task.TaskID, "generation": task.Generation, "state": task.State, "changed": changed})
	case "get":
		task, err := tasks.Get(ctx, *taskID)
		if err != nil {
			return err
		}
		return out.Encode(map[string]any{"taskId": task.TaskID, "generation": task.Generation, "state": task.State, "attemptCount": task.AttemptCount, "workerId": task.WorkerID, "resultDigest": task.ResultDigest, "failureCode": task.FailureCode, "revision": task.Revision})
	default:
		return fmt.Errorf("unknown local-check command %q", args[0])
	}
}
