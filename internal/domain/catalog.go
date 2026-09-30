package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Catalog rules (DD-08 §1): a descriptor revision binds what discovery read
// from the live server through the connection layer and what the listing
// declared; its digest covers both. Registry entries and caller claims are
// never the descriptor: every declared method must exist live and every
// live method must be declared. A changed descriptor is a new revision;
// only an authorized reviewer other than the discoverer approves the exact
// digest; approval, rejection and disabling are the only decisions.

// CatalogState mirrors CatalogState of anvilkit.mcp.v1 and the state column.
type CatalogState string

const (
	CatalogDiscovered    CatalogState = "discovered"
	CatalogReviewPending CatalogState = "review_pending"
	CatalogApproved      CatalogState = "approved"
	CatalogRejected      CatalogState = "rejected"
	CatalogDisabled      CatalogState = "disabled"
)

var (
	ErrDescriptorMismatch = errors.New("DESCRIPTOR_MISMATCH")
	ErrForbidden          = errors.New("FORBIDDEN")
	ErrCommandConflict    = errors.New("COMMAND_CONFLICT")
	ErrRevisionMismatch   = errors.New("REVISION_MISMATCH")
	ErrInvalidTransition  = errors.New("INVALID_TRANSITION")
)

// DataClass orders the classes a descriptor or grant may carry.
var dataClasses = []string{"public", "internal", "confidential", "restricted"}

// DataClassRank is the order of a data class, -1 when unknown.
func DataClassRank(c string) int { return slices.Index(dataClasses, c) }

// Money is a currency and an integer amount in minor units.
type Money struct {
	Currency string `json:"currency"`
	Amount   int64  `json:"amount"`
}

// ToolDeclaration is the listing's statement about one method.
type ToolDeclaration struct {
	Method             string
	InputSchemaDigest  string // optional expectation
	OutputSchemaDigest string // optional expectation
	SideEffecting      bool
	UnitPrice          Money
	Idempotent         bool
	QuerySupported     bool
}

// Declaration is a discovery request: the canonical resource, transport and
// protocol version to connect to, provenance (a registry reference or the
// operator's source), the per-method declarations and the review inputs.
type Declaration struct {
	CanonicalResource string
	Transport         string
	ProtocolVersion   string
	Provenance        string
	ExpectedDigest    string
	Tools             []ToolDeclaration
	DataClass         string
	NetworkScope      []string
	Licenses          []string
}

// LiveTool, LiveNamed and LiveServer are what the connection layer read.
type LiveTool struct {
	Name         string
	InputSchema  json.RawMessage
	OutputSchema json.RawMessage
	Annotations  json.RawMessage
}

type LiveNamed struct {
	Name string `json:"name"`
	URI  string `json:"uri,omitempty"`
}

type LiveServer struct {
	Name            string
	Version         string
	ProtocolVersion string
	Tools           []LiveTool
	Resources       []LiveNamed
	Prompts         []LiveNamed
	// Evidence names the retrieval (connection identity and time); hosted
	// servers expose no binary hash to pin.
	Evidence      string
	ConnectionRef string
	// Issuer is the authorization server the resource's protected-resource
	// metadata names (empty: an unprotected server), read by MCP's own
	// guarded egress.
	Issuer string
}

// Tool is one method of a descriptor revision.
type Tool struct {
	Method             string `json:"method"`
	InputSchemaDigest  string `json:"inputSchemaDigest"`
	OutputSchemaDigest string `json:"outputSchemaDigest"`
	AnnotationsDigest  string `json:"annotationsDigest"`
	SideEffecting      bool   `json:"sideEffecting"`
	UnitPrice          Money  `json:"unitPrice"`
	Idempotent         bool   `json:"idempotent"`
	QuerySupported     bool   `json:"querySupported"`
}

// Descriptor is one revision of a server.
type Descriptor struct {
	ServerID          string
	TenantID          string
	Revision          uint64
	CanonicalResource string
	Transport         string
	ProtocolVersion   string
	Provenance        string
	Digest            string
	Tools             []Tool
	Resources         []LiveNamed
	Prompts           []LiveNamed
	ResourcesDigest   string
	PromptsDigest     string
	ServerName        string
	ServerVersion     string
	DataClass         string
	NetworkScope      []string
	Licenses          []string
	Issuer            string
	RevisionEvidence  string
	ConnectionRef     string
	State             CatalogState
	DiscoveredBy      string
	Reviewer          string
	ReviewID          string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Method returns the descriptor's method, when it has it.
func (d Descriptor) Method(name string) (Tool, bool) {
	for _, t := range d.Tools {
		if t.Method == name {
			return t, true
		}
	}
	return Tool{}, false
}

// CanonicalDigest is the SHA-256 of the canonical JSON of a value: a JSON
// document re-encoded with sorted object keys and no insignificant space;
// an absent document digests as null.
func CanonicalDigest(raw json.RawMessage) (string, error) {
	var v any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &v); err != nil {
			return "", fmt.Errorf("%w: schema is not JSON", ErrInvalid)
		}
	}
	return digestJSON(v)
}

func digestJSON(v any) (string, error) {
	b, err := json.Marshal(v) // encoding/json sorts map keys
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// CheckResource validates the canonical resource of a streamable-http
// server: an absolute https URL (http only for DEVELOPMENT_ONLY hosts the
// caller allows), no userinfo, no fragment. The host is returned for the
// network checks of the connection layer.
func CheckResource(raw string, allowHTTP bool) (host string, err error) {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "" {
		return "", fmt.Errorf("%w: canonical resource %q is not an absolute URL", ErrInvalid, raw)
	}
	if u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return "", fmt.Errorf("%w: canonical resource carries userinfo, a query or a fragment", ErrInvalid)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return "", fmt.Errorf("%w: canonical resource must use https", ErrForbidden)
		}
	default:
		return "", fmt.Errorf("%w: scheme %q", ErrInvalid, u.Scheme)
	}
	return strings.ToLower(u.Hostname()), nil
}

// BuildDescriptor binds the live retrieval to the declaration. It refuses a
// transport the baseline does not qualify (discovery never launches a stdio
// package), a protocol version other than the declared one, a method set
// that differs, schema digests that differ from the declared expectations,
// a network scope that omits the resource's own host, and a digest other
// than the expected one.
func BuildDescriptor(d Declaration, live LiveServer) (Descriptor, error) {
	if d.Transport != "streamable-http" {
		return Descriptor{}, fmt.Errorf("%w: transport %s is not discoverable (stdio servers run only as qualified Jobs)", ErrForbidden, d.Transport)
	}
	if DataClassRank(d.DataClass) < 0 {
		return Descriptor{}, fmt.Errorf("%w: data class %q", ErrInvalid, d.DataClass)
	}
	host, err := CheckResource(d.CanonicalResource, true)
	if err != nil {
		return Descriptor{}, err
	}
	scope := normalizeSet(d.NetworkScope)
	if !slices.Contains(scope, host) {
		scope = normalizeSet(append(scope, host))
	}
	if live.ProtocolVersion != d.ProtocolVersion {
		return Descriptor{}, fmt.Errorf("%w: the server speaks protocol %s, the listing declares %s", ErrDescriptorMismatch, live.ProtocolVersion, d.ProtocolVersion)
	}
	declared := map[string]ToolDeclaration{}
	for _, t := range d.Tools {
		if _, dup := declared[t.Method]; dup || t.Method == "" {
			return Descriptor{}, fmt.Errorf("%w: method %q declared twice or empty", ErrInvalid, t.Method)
		}
		if t.UnitPrice.Amount < 0 || len(t.UnitPrice.Currency) != 3 {
			return Descriptor{}, fmt.Errorf("%w: price of %s", ErrInvalid, t.Method)
		}
		declared[t.Method] = t
	}
	var tools []Tool
	for _, lt := range live.Tools {
		decl, ok := declared[lt.Name]
		if !ok {
			return Descriptor{}, fmt.Errorf("%w: live method %s is not declared", ErrDescriptorMismatch, lt.Name)
		}
		delete(declared, lt.Name)
		in, err := CanonicalDigest(lt.InputSchema)
		if err != nil {
			return Descriptor{}, err
		}
		out, err := CanonicalDigest(lt.OutputSchema)
		if err != nil {
			return Descriptor{}, err
		}
		ann, err := CanonicalDigest(lt.Annotations)
		if err != nil {
			return Descriptor{}, err
		}
		if (decl.InputSchemaDigest != "" && decl.InputSchemaDigest != in) || (decl.OutputSchemaDigest != "" && decl.OutputSchemaDigest != out) {
			return Descriptor{}, fmt.Errorf("%w: schema of %s differs from the listing", ErrDescriptorMismatch, lt.Name)
		}
		tools = append(tools, Tool{Method: lt.Name, InputSchemaDigest: in, OutputSchemaDigest: out, AnnotationsDigest: ann, SideEffecting: decl.SideEffecting,
			UnitPrice: decl.UnitPrice, Idempotent: decl.Idempotent, QuerySupported: decl.QuerySupported})
	}
	if len(declared) > 0 {
		missing := make([]string, 0, len(declared))
		for m := range declared {
			missing = append(missing, m)
		}
		slices.Sort(missing)
		return Descriptor{}, fmt.Errorf("%w: declared methods absent from the server: %s", ErrDescriptorMismatch, strings.Join(missing, ", "))
	}
	slices.SortFunc(tools, func(a, b Tool) int { return strings.Compare(a.Method, b.Method) })
	resources, prompts := sortNamed(live.Resources), sortNamed(live.Prompts)
	rd, err := digestJSON(resources)
	if err != nil {
		return Descriptor{}, err
	}
	pd, err := digestJSON(prompts)
	if err != nil {
		return Descriptor{}, err
	}
	desc := Descriptor{
		CanonicalResource: d.CanonicalResource, Transport: d.Transport, ProtocolVersion: d.ProtocolVersion, Provenance: d.Provenance,
		Tools: tools, Resources: resources, Prompts: prompts, ResourcesDigest: rd, PromptsDigest: pd, ServerName: live.Name, ServerVersion: live.Version,
		DataClass: d.DataClass, NetworkScope: scope, Licenses: normalizeSet(d.Licenses), RevisionEvidence: live.Evidence, ConnectionRef: live.ConnectionRef, Issuer: live.Issuer,
		State: CatalogReviewPending,
	}
	desc.Digest, err = DescriptorDigest(desc)
	if err != nil {
		return Descriptor{}, err
	}
	if d.ExpectedDigest != "" && d.ExpectedDigest != desc.Digest {
		return Descriptor{}, fmt.Errorf("%w: the live descriptor digests as %s, the listing expects %s", ErrDescriptorMismatch, desc.Digest, d.ExpectedDigest)
	}
	return desc, nil
}

// DescriptorDigest covers everything a reviewer approves: resource,
// transport, protocol, server identity, every method's schemas,
// annotations and declarations, resources, prompts, data class, network
// scope and licenses. Provenance and the retrieval evidence are recorded
// but do not change what executes.
func DescriptorDigest(d Descriptor) (string, error) {
	return digestJSON(map[string]any{
		"schema": "mcp-descriptor-v1", "canonicalResource": d.CanonicalResource, "transport": d.Transport, "protocolVersion": d.ProtocolVersion,
		"serverName": d.ServerName, "serverVersion": d.ServerVersion, "tools": d.Tools, "resourcesDigest": d.ResourcesDigest, "promptsDigest": d.PromptsDigest,
		"dataClass": d.DataClass, "networkScope": d.NetworkScope, "licenses": d.Licenses, "issuer": d.Issuer,
	})
}

func normalizeSet(xs []string) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if x = strings.ToLower(strings.TrimSpace(x)); x != "" {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func sortNamed(xs []LiveNamed) []LiveNamed {
	out := slices.Clone(xs)
	if out == nil {
		out = []LiveNamed{}
	}
	slices.SortFunc(out, func(a, b LiveNamed) int { return strings.Compare(a.Name+"\x00"+a.URI, b.Name+"\x00"+b.URI) })
	return out
}

// ReviewDecision is approve or reject.
type ReviewDecision string

const (
	ReviewApprove ReviewDecision = "approve"
	ReviewReject  ReviewDecision = "reject"
)

// CheckReview admits a reviewer's decision on the exact digest of a
// revision awaiting review; the discoverer never reviews its own revision.
func CheckReview(d Descriptor, reviewer, digest string, decision ReviewDecision) (CatalogState, error) {
	if d.Digest != digest {
		return "", fmt.Errorf("%w: revision %d digests as %s", ErrDescriptorMismatch, d.Revision, d.Digest)
	}
	if reviewer == d.DiscoveredBy {
		return "", fmt.Errorf("%w: the discoverer never reviews its own revision", ErrForbidden)
	}
	if d.State != CatalogReviewPending {
		return "", fmt.Errorf("%w: a %s revision is not reviewed", ErrInvalidTransition, d.State)
	}
	switch decision {
	case ReviewApprove:
		return CatalogApproved, nil
	case ReviewReject:
		return CatalogRejected, nil
	}
	return "", fmt.Errorf("%w: decision %q", ErrInvalid, decision)
}
