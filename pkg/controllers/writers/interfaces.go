package writers

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const IstioControllerName = "istio.io/gateway-controller"

// Permission represents a single Kubernetes RBAC permission required by a writer.
type Permission struct {
	Group    string
	Resource string
	Verb     string
}

// PermissionProvider is an optional interface a writer can implement to declare
// the RBAC permissions it needs. checkRBAC in main.go uses this for preflight checks.
type PermissionProvider interface {
	RequiredPermissions() []Permission
}

// L4PolicyWriter creates gateway-level (L4) allow policies.
type L4PolicyWriter interface {
	Apply(ctx context.Context, scheme *runtime.Scheme, gateway *gatewayApiv1.Gateway, ips []string) error
	Delete(ctx context.Context, gateway *gatewayApiv1.Gateway) error
}

// L7PolicyWriter creates route-level (L7) allow policies.
type L7PolicyWriter interface {
	Apply(ctx context.Context, scheme *runtime.Scheme, route *gatewayApiv1.HTTPRoute, gateway *gatewayApiv1.Gateway, ips, hosts, paths []string) error
	ListManaged(ctx context.Context, managedBy string) ([]client.Object, error)
	IsOrphaned(obj client.Object, allRoutes []gatewayApiv1.HTTPRoute) bool
	Delete(ctx context.Context, obj client.Object) error
	// DeleteForRoute deletes all policies owned by the given route, identified by owner labels.
	// Called when the allowlist annotation is removed so that existing APs are cleaned up
	// immediately rather than waiting for the next startup cleanup.
	DeleteForRoute(ctx context.Context, managedBy, routeNamespace, routeName string) error
}

// MergeableL7PolicyWriter is an optional extension of L7PolicyWriter for writers that support
// merging IPs and hosts from multiple HTTPRoutes into a single shared policy identified by a merge key.
// Writers that don't support this concept simply don't implement this interface.
type MergeableL7PolicyWriter interface {
	L7PolicyWriter
	ApplyMerged(ctx context.Context, gateway *gatewayApiv1.Gateway, siblings []*gatewayApiv1.HTTPRoute, mergeKey string) error
	// DeleteMerged removes the merged policy for the given merge key in the gateway's namespace.
	// Called when a confirmed-empty sibling list means the merge group no longer exists.
	DeleteMerged(ctx context.Context, namespace, mergeKey string) error
}

// PathTranslator is an optional interface a writer can implement to control how HTTPRoute path
// matches are translated into the enforcement-layer path strings passed to Apply.
// Writers that don't implement this receive raw path values from match.Path.Value.
type PathTranslator interface {
	TranslatePaths(matches []gatewayApiv1.HTTPRouteMatch) []string
}

// L4WriterRegistry maps GatewayClass controllerName to an L4PolicyWriter.
type L4WriterRegistry map[string]L4PolicyWriter

// L7WriterRegistry maps GatewayClass controllerName to an L7PolicyWriter.
type L7WriterRegistry map[string]L7PolicyWriter
