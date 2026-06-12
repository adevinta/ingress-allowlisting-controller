package writers

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const IstioControllerName = "istio.io/gateway-controller"

// L4PolicyWriter creates gateway-level (L4) allow policies.
type L4PolicyWriter interface {
	Apply(ctx context.Context, gateway *gatewayApiv1.Gateway, ips []string) error
	Delete(ctx context.Context, gateway *gatewayApiv1.Gateway) error
}

// L7PolicyWriter creates route-level (L7) allow policies.
type L7PolicyWriter interface {
	Apply(ctx context.Context, scheme *runtime.Scheme, route *gatewayApiv1.HTTPRoute, gateway *gatewayApiv1.Gateway, ips, hosts, paths []string, index int) error
	ListManaged(ctx context.Context, managedBy string) ([]client.Object, error)
	IsOrphaned(obj client.Object, allRoutes []gatewayApiv1.HTTPRoute) bool
	Delete(ctx context.Context, obj client.Object) error
}

// MergeableL7PolicyWriter is an optional extension of L7PolicyWriter for writers that support
// merging IPs and hosts from multiple HTTPRoutes into a single shared policy identified by a merge key.
// Writers that don't support this concept simply don't implement this interface.
type MergeableL7PolicyWriter interface {
	L7PolicyWriter
	ApplyMerged(ctx context.Context, gateway *gatewayApiv1.Gateway, siblings []*gatewayApiv1.HTTPRoute, mergeKey string, index int) error
}

// L4WriterRegistry maps GatewayClass controllerName to an L4PolicyWriter.
type L4WriterRegistry map[string]L4PolicyWriter

// L7WriterRegistry maps GatewayClass controllerName to an L7PolicyWriter.
type L7WriterRegistry map[string]L7PolicyWriter
