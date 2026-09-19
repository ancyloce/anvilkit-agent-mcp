// Package testdb starts a disposable PostgreSQL 17 for MCP tests and
// installs anvilkit_mcp from the migration source with goose, exactly as
// the migration Job does. The migrations still live in the parent
// repository's migration Job (jobs/migration/internal/migrate/sql/mcp) until
// MCP owns them: the directory is found beside this repository or named by
// ANVILKIT_MCP_MIGRATIONS_DIR; tests skip when Docker or the directory is
// unavailable and never touch a shared database.
package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

const image = "postgres:17-alpine"

// Instance is one running database with the MCP schema installed.
type Instance struct {
	Container *postgres.PostgresContainer
	AppDSN    string
	AdminDSN  string
	RelayDSN  string
}

// MigrationsDir locates the anvilkit_mcp migration source.
func MigrationsDir() (string, error) {
	if dir := os.Getenv("ANVILKIT_MCP_MIGRATIONS_DIR"); dir != "" {
		return dir, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for d := wd; d != filepath.Dir(d); d = filepath.Dir(d) {
		candidate := filepath.Join(d, "jobs", "migration", "internal", "migrate", "sql", "mcp")
		if _, err := os.Stat(filepath.Join(candidate, "00001_init.sql")); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("anvilkit_mcp migrations not found (set ANVILKIT_MCP_MIGRATIONS_DIR)")
}

// Start provisions the container, roles, database and schema.
func Start(t *testing.T) *Instance {
	t.Helper()
	if os.Getenv("ANVILKIT_SKIP_DOCKER_TESTS") != "" {
		t.Skip("ANVILKIT_SKIP_DOCKER_TESTS set")
	}
	migrations, err := MigrationsDir()
	if err != nil {
		t.Skipf("UNEXECUTED: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	pg, err := postgres.Run(ctx, image,
		postgres.WithUsername("postgres"), postgres.WithPassword("postgres"), postgres.WithDatabase("postgres"),
		postgres.BasicWaitStrategies())
	if err != nil {
		t.Fatalf("start postgres: %v", err)
	}
	testcontainers.CleanupContainer(t, pg)
	adminDSN, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		"CREATE ROLE anvilkit_mcp_app LOGIN PASSWORD 'app'",
		"CREATE ROLE anvilkit_mcp_migrator LOGIN PASSWORD 'migrator'",
		"CREATE ROLE anvilkit_mcp_relay LOGIN PASSWORD 'relay'",
		"CREATE DATABASE anvilkit_mcp OWNER anvilkit_mcp_migrator",
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	admin.Close(ctx)
	host, _ := pg.Host(ctx)
	port, _ := pg.MappedPort(ctx, "5432/tcp")
	dsn := func(role, pw string) string {
		return fmt.Sprintf("postgres://%s:%s@%s:%s/anvilkit_mcp?sslmode=disable", role, pw, host, port.Port())
	}
	inst := &Instance{Container: pg, AdminDSN: adminDSN, AppDSN: dsn("anvilkit_mcp_app", "app"), RelayDSN: dsn("anvilkit_mcp_relay", "relay")}
	migratorDSN := dsn("anvilkit_mcp_migrator", "migrator")
	db, err := openMigrator(migratorDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	dbAdmin, err := pgx.Connect(ctx, migratorDSN)
	if err != nil {
		t.Fatal(err)
	}
	// As deploy/dev/postgres-init.sh: the app role cannot create objects.
	if _, err := dbAdmin.Exec(ctx, "REVOKE CREATE ON SCHEMA public FROM PUBLIC"); err != nil {
		t.Fatal(err)
	}
	dbAdmin.Close(ctx)
	provider, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS(migrations), goose.WithVerbose(false))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return inst
}

func openMigrator(dsn string) (*sql.DB, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	return stdlib.OpenDB(*cfg), nil
}

// Pool opens an app-role pool.
func (i *Instance) Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), i.AppDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// Admin runs statements as the database owner (test fixtures: grants,
// descriptors, servers; the P18 lifecycle will write them for real).
func (i *Instance) Admin(t *testing.T, statements ...string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, i.migratorDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for _, s := range statements {
		if _, err := conn.Exec(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func (i *Instance) migratorDSN() string {
	ctx := context.Background()
	host, _ := i.Container.Host(ctx)
	port, _ := i.Container.MappedPort(ctx, "5432/tcp")
	return fmt.Sprintf("postgres://anvilkit_mcp_migrator:migrator@%s:%s/anvilkit_mcp?sslmode=disable", host, port.Port())
}

// GrantFixture inserts the rows a grant:<id> authorization needs (server,
// descriptor, grant) in the given state.
func (i *Instance) GrantFixture(t *testing.T, tenant, grantID, state string) {
	t.Helper()
	i.Admin(t,
		fmt.Sprintf(`INSERT INTO servers (server_id, tenant_id, canonical_resource, transport) VALUES ('srv_%s', '%s', 'https://mcp.example/%s', 'streamable-http') ON CONFLICT DO NOTHING`, grantID, tenant, grantID),
		fmt.Sprintf(`INSERT INTO descriptors (server_id, revision, protocol_version, provenance, descriptor_digest, tools, state, command_id, request_digest) VALUES ('srv_%s', 1, '2025-06-18', 'test', 'sha256:%064d', '[]', 'approved', 'cmd_%s', 'sha256:%064d') ON CONFLICT DO NOTHING`, grantID, 1, grantID, 2),
		fmt.Sprintf(`INSERT INTO grants (grant_id, tenant_id, subject_type, subject_id, server_id, descriptor_revision, descriptor_digest, methods, purpose, cost_cap_currency, cost_cap_amount, state, expires_at, command_id, request_digest) VALUES ('%s', '%s', 'actor', 'user_a', 'srv_%s', 1, 'sha256:%064d', '{tools/call}', 'test', 'USD', 0, '%s', now() + interval '1 year', 'cmd_grant_%s', 'sha256:%064d')`, grantID, tenant, grantID, 1, state, grantID, 3),
	)
}

// SetGrantState changes a grant's state (revocation fixture).
func (i *Instance) SetGrantState(t *testing.T, grantID, state string) {
	t.Helper()
	i.Admin(t, fmt.Sprintf(`UPDATE grants SET state = '%s' WHERE grant_id = '%s'`, state, grantID))
}
