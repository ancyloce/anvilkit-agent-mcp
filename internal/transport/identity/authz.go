package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// AnyAuthenticated is the policy entry of a method every verified workload
// may call (the gRPC health service).
var AnyAuthenticated = Workload{Namespace: "*", ServiceAccount: "*"}

// Policy maps a fully qualified method (/package.Service/Method) to the
// workloads allowed to call it. Methods absent from the policy are denied;
// Authorizer.Check reports every registered method without an entry so a
// newly registered RPC cannot slip through.
type Policy map[string][]Workload

// Authorizer enforces a Policy under one trust domain.
type Authorizer struct {
	trustDomain string
	policy      Policy
}

// NewAuthorizer validates the trust domain and the policy's shape.
func NewAuthorizer(trustDomain string, policy Policy) (*Authorizer, error) {
	if !ValidTrustDomain(trustDomain) {
		return nil, fmt.Errorf("identity: trust domain %q is not a lowercase DNS name", trustDomain)
	}
	for method, allowed := range policy {
		if !strings.HasPrefix(method, "/") || strings.Count(method, "/") != 2 {
			return nil, fmt.Errorf("identity: policy method %q is not /package.Service/Method", method)
		}
		if len(allowed) == 0 {
			return nil, fmt.Errorf("identity: policy method %q allows nobody; remove it instead", method)
		}
		for _, w := range allowed {
			if w == AnyAuthenticated {
				continue
			}
			if !label.MatchString(w.Namespace) || !label.MatchString(w.ServiceAccount) {
				return nil, fmt.Errorf("identity: policy method %q names an invalid workload %s/%s", method, w.Namespace, w.ServiceAccount)
			}
		}
	}
	return &Authorizer{trustDomain: trustDomain, policy: policy}, nil
}

// Check lists the registered methods of srv that have no policy entry and
// the policy entries that name no registered method; both are
// configuration errors.
func (a *Authorizer) Check(srv *grpc.Server) error {
	var missing, stale []string
	registered := map[string]bool{}
	for name, info := range srv.GetServiceInfo() {
		for _, m := range info.Methods {
			full := "/" + name + "/" + m.Name
			registered[full] = true
			if _, ok := a.policy[full]; !ok {
				missing = append(missing, full)
			}
		}
	}
	for m := range a.policy {
		if !registered[m] {
			stale = append(stale, m)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 || len(stale) > 0 {
		return fmt.Errorf("identity: policy incomplete: methods without entry %v; entries without method %v", missing, stale)
	}
	return nil
}

// Allowed reports whether the principal may call the method.
func (a *Authorizer) Allowed(method string, p Principal) bool {
	if p.TrustDomain != a.trustDomain {
		return false
	}
	for _, w := range a.policy[method] {
		if w == AnyAuthenticated || (w.Namespace == p.Namespace && w.ServiceAccount == p.ServiceAccount) {
			return true
		}
	}
	return false
}

// Authorize is the decision for one call: UNAUTHENTICATED when the
// connection carries no usable workload identity, PERMISSION_DENIED when
// the identity is not allowed for the method.
func (a *Authorizer) Authorize(ctx context.Context, method string) error {
	pr, ok := peer.FromContext(ctx)
	if !ok || pr.AuthInfo == nil {
		return status.Error(codes.Unauthenticated, "UNAUTHENTICATED: no transport identity")
	}
	info, ok := pr.AuthInfo.(PeerInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "UNAUTHENTICATED: no workload identity on this connection")
	}
	if info.Err != nil {
		return status.Error(codes.Unauthenticated, "UNAUTHENTICATED: "+info.Err.Error())
	}
	if !a.Allowed(method, info.Principal) {
		return status.Errorf(codes.PermissionDenied, "PERMISSION_DENIED: %s may not call %s", info.Principal, method)
	}
	return nil
}

// Unary runs ahead of every unary handler.
func (a *Authorizer) Unary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := a.Authorize(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream runs ahead of every streaming handler.
func (a *Authorizer) Stream() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := a.Authorize(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// Caller is the verified workload of a call, for handlers that bind rows to
// the identity (P0.2); absent on development connections.
func Caller(ctx context.Context) (Principal, bool) {
	pr, ok := peer.FromContext(ctx)
	if !ok || pr.AuthInfo == nil {
		return Principal{}, false
	}
	info, ok := pr.AuthInfo.(PeerInfo)
	if !ok || info.Err != nil {
		return Principal{}, false
	}
	return info.Principal, true
}
