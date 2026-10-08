// Package identity is the workload identity of the internal gRPC transport
// (P0.1, security.md SEC-01): rotating TLS 1.3 server and client
// credentials loaded from mounted certificate files, the strict SPIFFE URI
// SAN of a peer and the method→principal authorization that runs ahead of
// every handler. A workload certificate identifies a service; it never
// establishes a user, tenant, role or approver.
package identity

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Principal is the parsed form of spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>.
type Principal struct {
	TrustDomain    string
	Namespace      string
	ServiceAccount string
}

func (p Principal) String() string {
	return "spiffe://" + p.TrustDomain + "/ns/" + p.Namespace + "/sa/" + p.ServiceAccount
}

// Workload names the identity of a service by namespace and ServiceAccount
// under the server's trust domain.
type Workload struct {
	Namespace      string
	ServiceAccount string
}

var (
	label       = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	trustDomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`)
)

// ValidTrustDomain reports whether s is a lowercase DNS-shaped trust domain.
func ValidTrustDomain(s string) bool { return trustDomain.MatchString(s) }

// ParseSPIFFE parses the complete URI strictly: scheme spiffe, a DNS-shaped
// trust domain without port or userinfo, the exact path /ns/<ns>/sa/<sa>
// with DNS-label segments, no query and no fragment.
func ParseSPIFFE(u *url.URL) (Principal, error) {
	if u == nil {
		return Principal{}, errors.New("no uri")
	}
	if u.Scheme != "spiffe" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return Principal{}, fmt.Errorf("uri %q is not a workload identity", u.String())
	}
	if !ValidTrustDomain(u.Host) {
		return Principal{}, fmt.Errorf("uri %q has no valid trust domain", u.String())
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "ns" || parts[3] != "sa" || !label.MatchString(parts[2]) || !label.MatchString(parts[4]) {
		return Principal{}, fmt.Errorf("uri %q path is not /ns/<namespace>/sa/<service-account>", u.String())
	}
	return Principal{TrustDomain: u.Host, Namespace: parts[2], ServiceAccount: parts[4]}, nil
}

// PeerPrincipal reads the single URI SAN of a verified leaf certificate.
// A certificate without a URI SAN, with several, or with one that does not
// parse carries no workload identity.
func PeerPrincipal(leaf *x509.Certificate) (Principal, error) {
	if leaf == nil {
		return Principal{}, errors.New("no peer certificate")
	}
	if len(leaf.URIs) != 1 {
		return Principal{}, fmt.Errorf("peer certificate carries %d URI SANs, exactly one workload identity is required", len(leaf.URIs))
	}
	return ParseSPIFFE(leaf.URIs[0])
}
