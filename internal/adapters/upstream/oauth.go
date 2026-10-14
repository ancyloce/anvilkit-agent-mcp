package upstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/ancyloce/anvilkit-agent-mcp/internal/application"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// ErrAuthority: the resource's authorization metadata is missing, changed
// or points outside the network policy (a substituted protected-resource,
// authorization-server or JWKS/token endpoint); no token is requested and
// nothing is sent to the resource.
var ErrAuthority = errors.New("AUTHORIZATION_SUBSTITUTED")

// Credential is one reviewed client registration of MCP at an
// authorization server for one canonical resource. The secret is read from
// its mounted file for every token request (the secret platform's file
// injection; DEVELOPMENT_ONLY binding list, ENV-02).
type Credential struct {
	Resource         string
	Issuer           string
	ClientID         string
	ClientSecretFile string
	Scopes           []string
}

// Authority reads protected-resource metadata (RFC 9728) and obtains
// resource-bound access tokens (client credentials, RFC 8707 resource
// indicator) through the guarded client. Tokens are cached per grant
// security dimensions (the grant's cache key), never per URL or tenant.
type Authority struct {
	guard       Guard
	client      *http.Client
	credentials []Credential
	now         func() time.Time

	mu    sync.Mutex
	cache map[string]cachedToken
}

// cachedToken is one cached access token with what evicts it: the cache
// key it was obtained under and the canonical resource it is bound to.
type cachedToken struct {
	token    *oauth2.Token
	key      string
	resource string
}

func NewAuthority(guard Guard, client *http.Client, credentials []Credential, now func() time.Time) *Authority {
	return &Authority{guard: guard, client: client, credentials: credentials, now: now, cache: map[string]cachedToken{}}
}

type resourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

func metadataURLs(resource string) []string {
	u, err := url.Parse(resource)
	if err != nil {
		return nil
	}
	base := u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource"
	if p := strings.Trim(u.Path, "/"); p != "" {
		return []string{base + "/" + p, base}
	}
	return []string{base}
}

// ProtectedResource returns the authorization servers the resource names,
// or none when it publishes no metadata (an unprotected server). A document
// naming another resource is a substitution.
func (a *Authority) ProtectedResource(ctx context.Context, resource string) ([]string, error) {
	for _, mu := range metadataURLs(resource) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, mu, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := a.client.Do(req)
		if err != nil {
			return nil, err
		}
		raw, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if rerr != nil {
			return nil, rerr
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("protected resource metadata %s answered %d", mu, resp.StatusCode)
		}
		var md resourceMetadata
		if err := json.Unmarshal(raw, &md); err != nil {
			return nil, fmt.Errorf("%w: protected resource metadata: %v", ErrAuthority, err)
		}
		if md.Resource != resource {
			return nil, fmt.Errorf("%w: metadata names resource %q, not %q", ErrAuthority, md.Resource, resource)
		}
		for _, s := range md.AuthorizationServers {
			if err := a.checkURL(ctx, s); err != nil {
				return nil, err
			}
		}
		return md.AuthorizationServers, nil
	}
	return nil, nil
}

// Issuer is what discovery binds into the descriptor: the resource's first
// authorization server, or empty for an unprotected server.
func (a *Authority) Issuer(ctx context.Context, resource string) (string, error) {
	servers, err := a.ProtectedResource(ctx, resource)
	if err != nil || len(servers) == 0 {
		return "", err
	}
	return servers[0], nil
}

// checkURL applies the network policy to a URL named by metadata before
// anything contacts it: reviewed host, https (http only for a private
// host), resolvable to allowed addresses only.
func (a *Authority) checkURL(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("%w: URL %q", ErrAuthority, raw)
	}
	private, err := a.guard.Policy.CheckHost(u.Hostname())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthority, err)
	}
	if u.Scheme != "https" && !(private && u.Scheme == "http") {
		return fmt.Errorf("%w: scheme of %q", ErrAuthority, raw)
	}
	host := u.Hostname()
	var addrs []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{ip}
	} else if addrs, err = a.guard.Resolver.LookupNetIP(ctx, "ip", host); err != nil || len(addrs) == 0 {
		return fmt.Errorf("%w: host %s does not resolve", ErrAuthority, host)
	}
	for _, ip := range addrs {
		if err := application.CheckAddr(host, ip, private); err != nil {
			return fmt.Errorf("%w: %v", ErrAuthority, err)
		}
	}
	return nil
}

// Token returns the access token for a call under grant g, or "" when the
// grant binds no issuer (an unprotected server). Every call re-reads the
// resource's metadata: it must still name the grant's resource and issuer,
// and the issuer's metadata must still identify that issuer with token and
// JWKS endpoints inside the policy.
func (a *Authority) Token(ctx context.Context, g domain.Grant) (string, error) {
	if g.Issuer == "" {
		return "", nil
	}
	return a.token(ctx, g.CanonicalResource, g.Issuer, g.CacheKey())
}

// HasCredential reports whether a reviewed credential binds the resource.
func (a *Authority) HasCredential(resource string) bool {
	for _, c := range a.credentials {
		if c.Resource == resource {
			return true
		}
	}
	return false
}

// DiscoveryToken is the token discovery presents to a protected resource
// (P2.5): the resource's first authorization server and a token from the
// reviewed credential bound to exactly that resource and issuer, cached
// apart from every grant's. An unprotected resource needs none ("", "").
func (a *Authority) DiscoveryToken(ctx context.Context, resource string) (token, issuer string, err error) {
	if issuer, err = a.Issuer(ctx, resource); err != nil || issuer == "" {
		return "", "", err
	}
	token, err = a.token(ctx, resource, issuer, "discovery\x00"+resource+"\x00"+issuer)
	return token, issuer, err
}

func (a *Authority) token(ctx context.Context, resource, issuer, cacheKey string) (string, error) {
	servers, err := a.ProtectedResource(ctx, resource)
	if err != nil {
		return "", err
	}
	if !slices.Contains(servers, issuer) {
		return "", fmt.Errorf("%w: resource no longer names issuer %s", ErrAuthority, issuer)
	}
	var cred *Credential
	for i := range a.credentials {
		if a.credentials[i].Resource == resource && a.credentials[i].Issuer == issuer {
			cred = &a.credentials[i]
		}
	}
	if cred == nil {
		return "", fmt.Errorf("%w: no reviewed credential for %s at %s", ErrAuthority, resource, issuer)
	}
	key := cacheKey + "\x00" + cred.ClientID
	a.mu.Lock()
	cached := a.cache[key].token
	a.mu.Unlock()
	if cached != nil && cached.Expiry.After(a.now().Add(30*time.Second)) {
		return cached.AccessToken, nil
	}
	asm, err := auth.GetAuthServerMetadata(ctx, issuer, a.client)
	if err != nil {
		return "", fmt.Errorf("%w: authorization server metadata: %v", ErrAuthority, err)
	}
	if asm == nil {
		return "", fmt.Errorf("%w: issuer %s publishes no metadata", ErrAuthority, issuer)
	}
	for _, u := range []string{asm.TokenEndpoint, asm.JWKSURI} {
		if u == "" {
			continue
		}
		if err := a.checkURL(ctx, u); err != nil {
			return "", err
		}
	}
	secret, err := os.ReadFile(cred.ClientSecretFile)
	if err != nil {
		return "", fmt.Errorf("%w: client secret: %v", ErrAuthority, err)
	}
	cc := clientcredentials.Config{
		ClientID: cred.ClientID, ClientSecret: strings.TrimSpace(string(secret)), TokenURL: asm.TokenEndpoint, Scopes: cred.Scopes,
		EndpointParams: url.Values{"resource": {resource}}, AuthStyle: oauth2.AuthStyleInHeader,
	}
	tok, err := cc.Token(context.WithValue(ctx, oauth2.HTTPClient, a.client))
	if err != nil {
		return "", fmt.Errorf("%w: token: %v", ErrAuthority, err)
	}
	a.mu.Lock()
	a.cache[key] = cachedToken{token: tok, key: cacheKey, resource: resource}
	a.mu.Unlock()
	return tok.AccessToken, nil
}

// EvictGrant drops the tokens cached under a grant's cache key (P2.8: a
// committed revocation, consumed from mcp.grant-revoked) and answers how
// many it dropped.
func (a *Authority) EvictGrant(cacheKey string) int {
	return a.evict(func(c cachedToken) bool { return c.key == cacheKey })
}

// EvictResource drops every token cached for a canonical resource, grant
// and discovery tokens alike (P2.8: a disabled or rejected descriptor,
// consumed from mcp.catalog-reviewed).
func (a *Authority) EvictResource(resource string) int {
	return a.evict(func(c cachedToken) bool { return c.resource == resource })
}

func (a *Authority) evict(match func(cachedToken) bool) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for k, c := range a.cache {
		if match(c) {
			delete(a.cache, k)
			n++
		}
	}
	return n
}
