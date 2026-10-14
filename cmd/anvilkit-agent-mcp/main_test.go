package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalCheckIsAbsentFromTheProductionBinary (P2.5 AC6): the
// DEVELOPMENT_ONLY fixture entry point exists only under -tags localcheck;
// the production build has no localCheck symbol and refuses the command.
func TestLocalCheckIsAbsentFromTheProductionBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds two binaries")
	}
	dir := t.TempDir()
	build := func(name string, tags ...string) string {
		out := filepath.Join(dir, name)
		args := append([]string{"build"}, tags...)
		cmd := exec.Command("go", append(args, "-o", out, ".")...)
		if raw, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %v: %v\n%s", args, err, raw)
		}
		return out
	}
	symbols := func(bin string) string {
		raw, err := exec.Command("go", "tool", "nm", bin).CombinedOutput()
		if err != nil {
			t.Fatalf("go tool nm: %v\n%s", err, raw)
		}
		return string(raw)
	}
	prod := build("production")
	if strings.Contains(symbols(prod), "main.localCheck") {
		t.Fatal("the production binary carries the local-check entry point")
	}
	raw, err := exec.Command(prod, "local-check", "request", "-grant", "g").CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(raw), `unknown command "local-check"`) {
		t.Fatalf("production binary: want exit 2 unknown command, got %v: %s", err, raw)
	}
	dev := build("development", "-tags", "localcheck")
	if !strings.Contains(symbols(dev), "main.localCheck") {
		t.Fatal("the localcheck build lacks its entry point")
	}
}
