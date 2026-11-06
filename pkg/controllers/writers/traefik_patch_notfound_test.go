package writers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// routePatchFails makes every patch of an HTTPRoute fail with err, as when the route is deleted
// after the writer read it from the cache: the read still finds it, the API server doesn't.
func routePatchFails(err error) interceptor.Funcs {
	return interceptor.Funcs{Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
		if _, ok := obj.(*gatewayApiv1.HTTPRoute); ok {
			return err
		}
		return c.Patch(ctx, obj, patch, opts...)
	}}
}

// TestTraefikRouteGoneBeforeThePatch verifies that a route deleted between the read and the patch
// of its filters is no error, when the filter is added (Apply) and when it is removed
// (DeleteForRoute): the route's reconcile cleans up. Before, the patch's NotFound was returned, and
// the reconcile logged an error and was retried. Other patch errors are still returned.
func TestTraefikRouteGoneBeforeThePatch(t *testing.T) {
	ctx := context.Background()
	gw := testGateway("my-gw", "gw-ns")
	gone := apierrors.NewNotFound(schema.GroupResource{Group: gatewayApiv1.GroupName, Resource: "httproutes"}, "my-route")
	forbidden := apierrors.NewForbidden(schema.GroupResource{Group: gatewayApiv1.GroupName, Resource: "httproutes"}, "my-route", nil)

	t.Run("adding the filter", func(t *testing.T) {
		route := testTraefikRouteWithRules("my-route", "gw-ns", "/")
		c := interceptor.NewClient(fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route.DeepCopy()).Build(), routePatchFails(gone))
		assert.NoError(t, newTraefikWriter(c).Apply(ctx, traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, nil))
	})

	t.Run("removing the filter", func(t *testing.T) {
		route := testTraefikRouteWithRules("my-route", "gw-ns", "/")
		base := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route.DeepCopy()).Build()
		require.NoError(t, newTraefikWriter(base).Apply(ctx, traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, nil), "precondition: the filter is there")
		c := interceptor.NewClient(base, routePatchFails(gone))
		assert.NoError(t, newTraefikWriter(c).DeleteForRoute(ctx, "ingress-allowlisting-controller", "gw-ns", "my-route"))
	})

	t.Run("other errors are returned", func(t *testing.T) {
		route := testTraefikRouteWithRules("my-route", "gw-ns", "/")
		c := interceptor.NewClient(fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route.DeepCopy()).Build(), routePatchFails(forbidden))
		err := newTraefikWriter(c).Apply(ctx, traefikScheme, route, gw, []string{"10.0.0.0/8"}, nil, nil)
		assert.True(t, apierrors.IsForbidden(err), "got %v", err)
	})
}
