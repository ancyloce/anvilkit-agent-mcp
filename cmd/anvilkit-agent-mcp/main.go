// anvilkit-agent-mcp: the MCP service (P14 scope: the BackgroundTaskService
// owner, the transactional outbox and its forwarder). Without arguments it
// runs the Fx application; `reconcile <callId>` is the operator path of
// P1.2. The DEVELOPMENT_ONLY `local-check` subcommands (the owner entry
// point of the fixture kind) exist only in a binary built with
// `-tags localcheck` (P2.5): the production build has no such entry and
// refuses any other argument.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/fx"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/bootstrap"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// subcommands are the entry points besides the service itself; a
// build-tagged file may add DEVELOPMENT_ONLY ones (localcheck.go).
var subcommands = map[string]func([]string) error{"reconcile": reconcile}

func main() {
	if len(os.Args) > 1 {
		run, ok := subcommands[os.Args[1]]
		if !ok {
			fmt.Fprintf(os.Stderr, "anvilkit-agent-mcp: unknown command %q\n", os.Args[1])
			os.Exit(2)
		}
		if err := run(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	app := fx.New(bootstrap.Module())
	if err := app.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "mcp:", err)
		os.Exit(1)
	}
	startCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	if err := app.Start(startCtx); err != nil {
		cancel()
		fmt.Fprintln(os.Stderr, "mcp start:", err)
		os.Exit(1)
	}
	cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	stopCtx, cancelStop := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancelStop()
	if err := app.Stop(stopCtx); err != nil {
		fmt.Fprintln(os.Stderr, "mcp stop:", err)
		os.Exit(1)
	}
}

// reconcile is the operator path of P1.2: `anvilkit-agent-mcp reconcile
// <callId>` advances one call now under its original identity from
// Control's record and prints the call's state. It runs with the service's
// configuration and workload identity and never sends anything upstream.
func reconcile(args []string) error {
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("usage: reconcile <callId>")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	call, err := bootstrap.ReconcileCall(ctx, args[0])
	if err != nil {
		return err
	}
	out := map[string]any{"callId": call.CallID, "state": call.State, "failureCode": call.FailureCode, "dispatchId": call.DispatchID, "serverId": call.ServerID, "observed": call.ObservedAt != nil}
	if call.State == domain.CallUnknown {
		out["note"] = "Control has not resolved the original identity; the server stays RECOVERY_RESTRICTED"
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}
