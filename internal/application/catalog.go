package application

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/outbox"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/adapters/postgres/sqlc"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// Catalog is the private MCP catalog (DD-08 §1): discovery through the
// connection layer, descriptor revisions, review, disabling and per-tenant
// visibility. Discovery never launches a package and never grants
// execution; network I/O (the host checks' DNS and the connection layer)
// runs before the transaction that records the revision.

// Command is a command identity of a management call.
type Command struct {
	TenantID      string
	CommandID     string
	ActorID       string
	RequestDigest string
}

// Scope is the caller's tenant, project and actor.
type Scope struct {
	TenantID  string
	ProjectID string
	ActorID   string
}

func checkCommand(cmd Command, scope Scope) error {
	if cmd.TenantID != scope.TenantID || cmd.ActorID != scope.ActorID {
		return fmt.Errorf("%w: command identity differs from the scope", ErrForbidden)
	}
	return nil
}

// ConnectionLayer is the port to ContextForge.
type ConnectionLayer interface {
	Discover(ctx context.Context, resource string) (domain.LiveServer, error)
}

// IssuerSource reads the authorization server a resource names in its
// protected-resource metadata, through MCP's guarded egress.
type IssuerSource interface {
	Issuer(ctx context.Context, resource string) (string, error)
}

// Resolver resolves a host for the network checks.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// NetworkPolicy is the reviewed allowlist of discovery targets: allowed
// hosts (exact, or a ".suffix"), and the DEVELOPMENT_ONLY private hosts that
// may use http and resolve to loopback or private addresses (a fixture on
// the development foundation). Everything else must resolve to public
// addresses only; metadata and link-local addresses are never allowed.
type NetworkPolicy struct {
	AllowedHosts []string
	PrivateHosts []string
}

func hostAllowed(host string, patterns []string) bool {
	for _, p := range patterns {
		p = strings.ToLower(p)
		if host == p || (strings.HasPrefix(p, ".") && strings.HasSuffix(host, p)) {
			return true
		}
	}
	return false
}

var metadataAddrs = []netip.Addr{netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("fd00:ec2::254")}

// CheckTarget applies the policy to a canonical resource at URL parsing
// and resolution; the connection layer applies its own SSRF rules again at
// connection time, and MCP's own egress checks every connected address.
func (p NetworkPolicy) CheckTarget(ctx context.Context, resolver Resolver, resource string) error {
	host, err := domain.CheckResource(resource, true)
	if err != nil {
		return err
	}
	private, err := p.CheckHost(host)
	if err != nil {
		return err
	}
	if !private {
		if _, err := domain.CheckResource(resource, false); err != nil {
			return err
		}
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		addrs = []netip.Addr{a}
	} else {
		addrs, err = resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("%w: host %s does not resolve", ErrForbidden, host)
		}
	}
	for _, a := range addrs {
		if err := CheckAddr(host, a, private); err != nil {
			return err
		}
	}
	return nil
}

// CheckHost reports whether a host is reviewed, and whether it is one of
// the DEVELOPMENT_ONLY private hosts (http and private addresses allowed).
func (p NetworkPolicy) CheckHost(host string) (private bool, err error) {
	host = strings.ToLower(strings.Trim(host, "[]"))
	private = hostAllowed(host, p.PrivateHosts)
	if !private && !hostAllowed(host, p.AllowedHosts) {
		return false, fmt.Errorf("%w: host %s is not in the reviewed allowlist", ErrForbidden, host)
	}
	return private, nil
}

// CheckAddr applies the address rules to one resolved or connected address
// (IPv4, IPv6 and IPv4-mapped IPv6 alike): metadata, link-local, multicast
// and unspecified addresses are never allowed; loopback and private
// addresses only for a private host.
func CheckAddr(host string, a netip.Addr, private bool) error {
	a = a.Unmap()
	if slices.Contains(metadataAddrs, a) || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return fmt.Errorf("%w: host %s resolves to a forbidden address %s", ErrForbidden, host, a)
	}
	if (a.IsLoopback() || a.IsPrivate()) && !private {
		return fmt.Errorf("%w: host %s resolves to a private address %s", ErrForbidden, host, a)
	}
	return nil
}

// SystemResolver is the process resolver.
var SystemResolver Resolver = net.DefaultResolver

type Catalog struct {
	issuers  IssuerSource
	store    *postgres.Store
	conn     ConnectionLayer
	authz    *Authorizer
	policy   NetworkPolicy
	resolver Resolver
	grants   *Grants
	clock    Clock
	log      *slog.Logger
}

func NewCatalog(store *postgres.Store, conn ConnectionLayer, authz *Authorizer, policy NetworkPolicy, resolver Resolver, grants *Grants, clock Clock, log *slog.Logger) *Catalog {
	return &Catalog{store: store, conn: conn, authz: authz, policy: policy, resolver: resolver, grants: grants, clock: clock, log: log}
}

// WithIssuers binds the issuer source discovery reads (MCP's guarded
// egress); without one, descriptors bind no issuer.
func (c *Catalog) WithIssuers(i IssuerSource) *Catalog {
	c.issuers = i
	return c
}

func idOf(prefix string, parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return prefix + hex.EncodeToString(h.Sum(nil))[:32]
}

// replayCommand answers a command already recorded: the same kind and
// request digest answer its descriptor, anything else conflicts.
func (c *Catalog) replayCommand(ctx context.Context, q *sqlc.Queries, cmd Command, kind string) (*domain.Descriptor, error) {
	rec, err := q.GetCatalogCommand(ctx, sqlc.GetCatalogCommandParams{TenantID: cmd.TenantID, CommandID: cmd.CommandID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if rec.CommandKind != kind || rec.RequestDigest != cmd.RequestDigest {
		return nil, fmt.Errorf("%w: the command id was used with another request", domain.ErrCommandConflict)
	}
	d, err := c.load(ctx, q, rec.ServerID, uint64(rec.Revision))
	return &d, err
}

func (c *Catalog) load(ctx context.Context, q *sqlc.Queries, serverID string, revision uint64) (domain.Descriptor, error) {
	s, err := q.GetServer(ctx, serverID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Descriptor{}, fmt.Errorf("%w: server %s", domain.ErrNotFound, serverID)
	}
	if err != nil {
		return domain.Descriptor{}, err
	}
	if revision == 0 {
		revision = uint64(s.CurrentRevision)
	}
	r, err := q.GetDescriptor(ctx, sqlc.GetDescriptorParams{ServerID: serverID, Revision: int64(revision)})
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Descriptor{}, fmt.Errorf("%w: descriptor %s revision %d", domain.ErrNotFound, serverID, revision)
	}
	if err != nil {
		return domain.Descriptor{}, err
	}
	return postgres.DescriptorFromRow(r, s)
}

// Discover records the live descriptor of a server as a new revision
// awaiting review (the same digest as an existing revision answers that
// revision). It needs the catalog-manager role.
func (c *Catalog) Discover(ctx context.Context, cmd Command, scope Scope, decl domain.Declaration) (domain.Descriptor, bool, error) {
	if err := checkCommand(cmd, scope); err != nil {
		return domain.Descriptor{}, false, err
	}
	if err := c.authz.Require(scope.TenantID, scope.ActorID, ActCatalogDiscover); err != nil {
		return domain.Descriptor{}, false, err
	}
	if prev, err := c.replayCommand(ctx, c.store.Queries(), cmd, "discover"); err != nil || prev != nil {
		if prev != nil {
			return *prev, true, nil
		}
		return domain.Descriptor{}, false, err
	}
	if decl.DataClass == "" {
		return domain.Descriptor{}, false, fmt.Errorf("%w: data class is required", domain.ErrInvalid)
	}
	if decl.Transport != "streamable-http" {
		return domain.Descriptor{}, false, fmt.Errorf("%w: only streamable-http servers are discovered (stdio servers run as qualified Jobs)", ErrForbidden)
	}
	if err := c.policy.CheckTarget(ctx, c.resolver, decl.CanonicalResource); err != nil {
		return domain.Descriptor{}, false, err
	}
	live, err := c.conn.Discover(ctx, decl.CanonicalResource)
	if err != nil {
		return domain.Descriptor{}, false, err
	}
	if c.issuers != nil {
		if live.Issuer, err = c.issuers.Issuer(ctx, decl.CanonicalResource); err != nil {
			return domain.Descriptor{}, false, fmt.Errorf("%w: %v", ErrForbidden, err)
		}
	}
	desc, err := domain.BuildDescriptor(decl, live)
	if err != nil {
		return domain.Descriptor{}, false, err
	}
	var out domain.Descriptor
	existing := false
	err = c.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		serverID := idOf("srv-", scope.TenantID, decl.CanonicalResource)
		s, err := tx.Q.GetServerByResourceForUpdate(ctx, sqlc.GetServerByResourceForUpdateParams{TenantID: scope.TenantID, CanonicalResource: decl.CanonicalResource})
		if errors.Is(err, pgx.ErrNoRows) {
			if err := tx.Q.InsertServer(ctx, sqlc.InsertServerParams{ServerID: serverID, TenantID: scope.TenantID, CanonicalResource: decl.CanonicalResource, Transport: decl.Transport}); err != nil {
				return err
			}
			s, err = tx.Q.GetServerByResourceForUpdate(ctx, sqlc.GetServerByResourceForUpdateParams{TenantID: scope.TenantID, CanonicalResource: decl.CanonicalResource})
		}
		if err != nil {
			return err
		}
		if same, err := tx.Q.GetDescriptorByDigest(ctx, sqlc.GetDescriptorByDigestParams{ServerID: s.ServerID, DescriptorDigest: desc.Digest}); err == nil {
			existing = true
			if out, err = postgres.DescriptorFromRow(same, s); err != nil {
				return err
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		} else {
			desc.ServerID, desc.TenantID, desc.Revision, desc.DiscoveredBy = s.ServerID, scope.TenantID, uint64(s.CurrentRevision)+1, scope.ActorID
			tools, _ := json.Marshal(desc.Tools)
			resources, _ := json.Marshal(desc.Resources)
			prompts, _ := json.Marshal(desc.Prompts)
			if err := tx.Q.InsertDescriptor(ctx, sqlc.InsertDescriptorParams{
				ServerID: desc.ServerID, Revision: int64(desc.Revision), ProtocolVersion: desc.ProtocolVersion, Provenance: desc.Provenance,
				DescriptorDigest: desc.Digest, Tools: tools, State: string(desc.State), CommandID: cmd.CommandID, RequestDigest: cmd.RequestDigest,
				ServerName: desc.ServerName, ServerVersion: desc.ServerVersion, Resources: resources, Prompts: prompts, ResourcesDigest: desc.ResourcesDigest,
				PromptsDigest: desc.PromptsDigest, DataClass: desc.DataClass, NetworkScope: desc.NetworkScope, Licenses: desc.Licenses, Issuer: desc.Issuer,
				RevisionEvidence: desc.RevisionEvidence, ConnectionRef: desc.ConnectionRef, DiscoveredBy: desc.DiscoveredBy,
			}); err != nil {
				return err
			}
			if err := tx.Q.SetServerRevision(ctx, sqlc.SetServerRevisionParams{ServerID: desc.ServerID, CurrentRevision: int64(desc.Revision)}); err != nil {
				return err
			}
			out = desc
		}
		return tx.Q.InsertCatalogCommand(ctx, sqlc.InsertCatalogCommandParams{TenantID: cmd.TenantID, CommandID: cmd.CommandID, CommandKind: "discover",
			RequestDigest: cmd.RequestDigest, ServerID: out.ServerID, Revision: int64(out.Revision)})
	})
	if errors.Is(err, postgres.ErrDuplicateKey) {
		// A concurrent identical command or a concurrent discovery of the
		// same server committed first: answer what is recorded now.
		if prev, rerr := c.replayCommand(ctx, c.store.Queries(), cmd, "discover"); rerr == nil && prev != nil {
			return *prev, true, nil
		}
	}
	if err != nil {
		return domain.Descriptor{}, false, err
	}
	if !existing {
		c.log.Info("descriptor revision discovered", "serverId", out.ServerID, "revision", out.Revision, "tools", len(out.Tools))
	}
	return out, existing, nil
}

// Review records a reviewer's decision on the exact digest of a revision
// awaiting review, with its event. It needs the catalog-reviewer role, and
// the discoverer never reviews its own revision.
func (c *Catalog) Review(ctx context.Context, cmd Command, scope Scope, serverID string, revision uint64, digest string, decision domain.ReviewDecision, reason string) (domain.Descriptor, bool, error) {
	if err := checkCommand(cmd, scope); err != nil {
		return domain.Descriptor{}, false, err
	}
	if err := c.authz.Require(scope.TenantID, scope.ActorID, ActCatalogReview); err != nil {
		return domain.Descriptor{}, false, err
	}
	if prev, err := c.replayCommand(ctx, c.store.Queries(), cmd, "review"); err != nil || prev != nil {
		if prev != nil {
			return *prev, true, nil
		}
		return domain.Descriptor{}, false, err
	}
	var out domain.Descriptor
	err := c.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		d, err := c.lockOwn(ctx, tx, scope, serverID, revision)
		if err != nil {
			return err
		}
		next, err := domain.CheckReview(d, scope.ActorID, digest, decision)
		if err != nil {
			return err
		}
		reviewID := idOf("rev-", cmd.TenantID, cmd.CommandID)
		if err := tx.Q.InsertReview(ctx, sqlc.InsertReviewParams{ReviewID: reviewID, ServerID: serverID, Revision: int64(revision), DescriptorDigest: d.Digest,
			Reviewer: scope.ActorID, Decision: string(decision), ReasonCode: optional(reason), CommandID: cmd.CommandID, RequestDigest: cmd.RequestDigest, TenantID: cmd.TenantID}); err != nil {
			return err
		}
		if err := tx.Q.UpdateDescriptorState(ctx, sqlc.UpdateDescriptorStateParams{ServerID: serverID, Revision: int64(revision), State: string(next),
			Reviewer: &scope.ActorID, ReviewID: &reviewID}); err != nil {
			return err
		}
		d.State, d.Reviewer, d.ReviewID = next, scope.ActorID, reviewID
		if err := c.publish(ctx, tx, d, cmd.CommandID); err != nil {
			return err
		}
		out = d
		return tx.Q.InsertCatalogCommand(ctx, sqlc.InsertCatalogCommandParams{TenantID: cmd.TenantID, CommandID: cmd.CommandID, CommandKind: "review",
			RequestDigest: cmd.RequestDigest, ServerID: serverID, Revision: int64(revision)})
	})
	if err != nil {
		return domain.Descriptor{}, false, err
	}
	c.log.Info("descriptor revision reviewed", "serverId", serverID, "revision", revision, "state", out.State)
	return out, false, nil
}

// Disable withdraws a revision from new grants and new calls: its active
// and pending grants begin their revocation in the same transaction (the
// barrier with Control follows). Effects already sent are unaffected.
func (c *Catalog) Disable(ctx context.Context, cmd Command, scope Scope, serverID string, revision uint64, reason string) (domain.Descriptor, bool, error) {
	if err := checkCommand(cmd, scope); err != nil {
		return domain.Descriptor{}, false, err
	}
	if err := c.authz.Require(scope.TenantID, scope.ActorID, ActCatalogDisable); err != nil {
		return domain.Descriptor{}, false, err
	}
	if prev, err := c.replayCommand(ctx, c.store.Queries(), cmd, "disable"); err != nil || prev != nil {
		if prev != nil {
			return *prev, true, nil
		}
		return domain.Descriptor{}, false, err
	}
	var out domain.Descriptor
	existing := false
	err := c.store.InTx(ctx, func(ctx context.Context, tx postgres.Tx) error {
		d, err := c.lockOwn(ctx, tx, scope, serverID, revision)
		if err != nil {
			return err
		}
		if d.State == domain.CatalogDisabled {
			existing, out = true, d
		} else {
			reviewID := idOf("rev-", cmd.TenantID, cmd.CommandID)
			if err := tx.Q.InsertReview(ctx, sqlc.InsertReviewParams{ReviewID: reviewID, ServerID: serverID, Revision: int64(revision), DescriptorDigest: d.Digest,
				Reviewer: scope.ActorID, Decision: "disable", ReasonCode: optional(reason), CommandID: cmd.CommandID, RequestDigest: cmd.RequestDigest, TenantID: cmd.TenantID}); err != nil {
				return err
			}
			if err := tx.Q.UpdateDescriptorState(ctx, sqlc.UpdateDescriptorStateParams{ServerID: serverID, Revision: int64(revision), State: string(domain.CatalogDisabled)}); err != nil {
				return err
			}
			d.State = domain.CatalogDisabled
			if err := c.publish(ctx, tx, d, cmd.CommandID); err != nil {
				return err
			}
			ids, err := tx.Q.ListGrantsOfDescriptor(ctx, sqlc.ListGrantsOfDescriptorParams{ServerID: serverID, DescriptorRevision: int64(revision)})
			if err != nil {
				return err
			}
			for _, id := range ids {
				if err := c.grants.revokeIn(ctx, tx, id, "disable:"+cmd.CommandID, "descriptor-disabled", scope.ActorID, "DESCRIPTOR_DISABLED"); err != nil {
					return err
				}
			}
			out = d
		}
		return tx.Q.InsertCatalogCommand(ctx, sqlc.InsertCatalogCommandParams{TenantID: cmd.TenantID, CommandID: cmd.CommandID, CommandKind: "disable",
			RequestDigest: cmd.RequestDigest, ServerID: serverID, Revision: int64(revision)})
	})
	if err != nil {
		return domain.Descriptor{}, false, err
	}
	return out, existing, nil
}

func (c *Catalog) lockOwn(ctx context.Context, tx postgres.Tx, scope Scope, serverID string, revision uint64) (domain.Descriptor, error) {
	s, err := tx.Q.GetServer(ctx, serverID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && s.TenantID != scope.TenantID) {
		return domain.Descriptor{}, fmt.Errorf("%w: server %s", domain.ErrNotFound, serverID)
	}
	if err != nil {
		return domain.Descriptor{}, err
	}
	r, err := tx.Q.GetDescriptorForUpdate(ctx, sqlc.GetDescriptorForUpdateParams{ServerID: serverID, Revision: int64(revision)})
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Descriptor{}, fmt.Errorf("%w: descriptor %s revision %d", domain.ErrNotFound, serverID, revision)
	}
	if err != nil {
		return domain.Descriptor{}, err
	}
	return postgres.DescriptorFromRow(r, s)
}

func (c *Catalog) publish(ctx context.Context, tx postgres.Tx, d domain.Descriptor, correlation string) error {
	env, err := domain.CatalogReviewedEvent(d, correlation, c.clock.Now())
	if err != nil {
		return err
	}
	return outbox.Publish(ctx, tx.Tx, env)
}

// visible: members see approved and disabled revisions of their tenant's
// catalog; revisions awaiting review or rejected are visible to the
// catalog roles only. Another tenant's server is indistinguishable from a
// missing one.
func (c *Catalog) visible(scope Scope, d domain.Descriptor) bool {
	if d.TenantID != scope.TenantID {
		return false
	}
	if d.State == domain.CatalogApproved || d.State == domain.CatalogDisabled {
		return true
	}
	return c.authz.Allowed(scope.TenantID, scope.ActorID, ActCatalogReadPending)
}

// Get answers one revision (0: the current one) the caller may see.
func (c *Catalog) Get(ctx context.Context, scope Scope, serverID string, revision uint64) (domain.Descriptor, error) {
	d, err := c.load(ctx, c.store.Queries(), serverID, revision)
	if err != nil {
		return domain.Descriptor{}, err
	}
	if !c.visible(scope, d) {
		return domain.Descriptor{}, fmt.Errorf("%w: server %s", domain.ErrNotFound, serverID)
	}
	return d, nil
}

// List answers a page of the tenant's catalog the caller may see.
func (c *Catalog) List(ctx context.Context, scope Scope, state, cursor string, limit int) ([]domain.Descriptor, string, error) {
	if limit <= 0 {
		limit = 50
	}
	afterServer, afterRevision := "", int64(0)
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return nil, "", fmt.Errorf("%w: cursor", domain.ErrInvalid)
		}
		if _, err := fmt.Sscanf(string(raw), "%s %d", &afterServer, &afterRevision); err != nil {
			return nil, "", fmt.Errorf("%w: cursor", domain.ErrInvalid)
		}
	}
	q := c.store.Queries()
	rows, err := q.ListDescriptors(ctx, sqlc.ListDescriptorsParams{TenantID: scope.TenantID, State: state,
		IncludePending: c.authz.Allowed(scope.TenantID, scope.ActorID, ActCatalogReadPending), AfterServer: afterServer, AfterRevision: afterRevision, PageLimit: int32(limit + 1)})
	if err != nil {
		return nil, "", err
	}
	var out []domain.Descriptor
	for _, r := range rows {
		s, err := q.GetServer(ctx, r.ServerID)
		if err != nil {
			return nil, "", err
		}
		d, err := postgres.DescriptorFromRow(r, s)
		if err != nil {
			return nil, "", err
		}
		out = append(out, d)
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[limit-1]
		next = base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s %d", last.ServerID, last.Revision)))
	}
	return out, next, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
