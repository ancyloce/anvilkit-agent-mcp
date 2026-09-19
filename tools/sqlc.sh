#!/bin/sh
# MCP's data-access generation (A06): sqlc 1.27.0 renders
# internal/adapters/postgres/sqlc from the reviewed queries
# (internal/adapters/postgres/queries) and the anvilkit_mcp schema. The
# schema is the migration source of the parent repository's migration Job
# (jobs/migration/internal/migrate/sql/mcp, found beside this repository or
# named by ANVILKIT_MCP_MIGRATIONS_DIR) until MCP owns its migrations; it is
# mirrored into a scratch "schema" directory next to sqlc.yaml for the run.
#
#   sh tools/sqlc.sh            # regenerate in place
#   sh tools/sqlc.sh --check    # regenerate into a scratch tree and fail on drift
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PIN=1.27.0
OUT=internal/adapters/postgres/sqlc
MIGRATIONS=${ANVILKIT_MCP_MIGRATIONS_DIR:-"$ROOT/../../../jobs/migration/internal/migrate/sql/mcp"}
if [ ! -f "$MIGRATIONS/00001_init.sql" ]; then
  echo "UNEXECUTED: anvilkit_mcp migrations not found at $MIGRATIONS (set ANVILKIT_MCP_MIGRATIONS_DIR)" >&2
  exit 2
fi
SQLC="$(go env GOPATH)/bin/sqlc"
if [ ! -x "$SQLC" ]; then
  SQLC=$(command -v sqlc 2>/dev/null || true)
fi
if [ -z "$SQLC" ]; then
  echo "FAIL: sqlc is not installed (go install github.com/sqlc-dev/sqlc/cmd/sqlc@v$PIN)" >&2
  exit 1
fi
VERSION=$("$SQLC" version 2>&1 | sed -n 's/.*v\([0-9][0-9.]*\).*/\1/p' | head -1)
if [ "$VERSION" != "$PIN" ]; then
  echo "FAIL: sqlc at $SQLC reports '$VERSION'; pinned $PIN" >&2
  exit 1
fi
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/internal/adapters/postgres" "$WORK/schema"
cp "$ROOT/sqlc.yaml" "$WORK/sqlc.yaml"
cp -R "$ROOT/internal/adapters/postgres/queries" "$WORK/internal/adapters/postgres/queries"
cp "$MIGRATIONS"/*.sql "$WORK/schema/"
(cd "$WORK" && "$SQLC" generate -f sqlc.yaml)
if [ "${1:-}" != "--check" ]; then
  rm -rf "$ROOT/$OUT"
  cp -R "$WORK/$OUT" "$ROOT/$OUT"
  echo "generated: $OUT"
  exit 0
fi
if diff -r "$WORK/$OUT" "$ROOT/$OUT" >"$WORK/diff.txt" 2>&1; then
  echo "sqlc check: 0 differences"
  exit 0
fi
echo "FAIL sqlc check: $OUT differs from the generated output" >&2
sed 's/^/  /' "$WORK/diff.txt" | head -50 >&2
exit 1
