package writers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
)

// countingAPUpdates builds a fake client that counts Updates of AuthorizationPolicies.
func countingAPUpdates(t *testing.T, objs ...client.Object) (client.Client, *int) {
	t.Helper()
	updates := 0
	c := fake.NewClientBuilder().WithScheme(istioL7Scheme).WithObjects(objs...).WithInterceptorFuncs(interceptor.Funcs{
		Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if _, ok := obj.(*istiosecurityv1.AuthorizationPolicy); ok {
				updates++
			}
			return c.Update(ctx, obj, opts...)
		},
	}).Build()
	return c, &updates
}

// TestIstioWritersDontUpdateUnchangedPolicies verifies that applying the same allowlist again sends
// no Update. The spec is a protobuf message: a freshly built one is never DeepEqual to the one read
// back (internal fields differ), so CreateOrUpdate used to update every policy on every reconcile.
func TestIstioWritersDontUpdateUnchangedPolicies(t *testing.T) {
	ctx := context.Background()

	t.Run("Gateway (L4)", func(t *testing.T) {
		gw := testL4Gateway("my-gateway", "mynamespace")
		c, updates := countingAPUpdates(t, gw)
		w := NewIstioL4Writer(c, "ingress-allowlisting-controller", "ipam.adevinta.com")

		require.NoError(t, w.Apply(ctx, istioL7Scheme, gw, []string{"10.0.0.0/8"}))
		require.NoError(t, w.Apply(ctx, istioL7Scheme, gw, []string{"10.0.0.0/8"}))
		assert.Equal(t, 0, *updates, "the same allowlist again: no Update")

		require.NoError(t, w.Apply(ctx, istioL7Scheme, gw, []string{"192.0.2.0/24"}))
		assert.Equal(t, 1, *updates, "a real change: one Update")
	})

	t.Run("HTTPRoute (L7, per route)", func(t *testing.T) {
		gw := testGateway("my-gw", "mynamespace")
		route := testRoute("my-route", "mynamespace", "app.example.com")
		c, updates := countingAPUpdates(t, gw, route)
		w := newIstioL7Writer(c)
		hosts := []string{"app.example.com"}

		require.NoError(t, w.Apply(ctx, istioL7Scheme, route, gw, []string{"10.0.0.0/8"}, hosts, nil))
		require.NoError(t, w.Apply(ctx, istioL7Scheme, route, gw, []string{"10.0.0.0/8"}, hosts, nil))
		assert.Equal(t, 0, *updates, "the same allowlist again: no Update")

		require.NoError(t, w.Apply(ctx, istioL7Scheme, route, gw, []string{"192.0.2.0/24"}, hosts, nil))
		assert.Equal(t, 1, *updates, "a real change: one Update")
	})

	t.Run("HTTPRoute (L7, merged)", func(t *testing.T) {
		cidrs := testCIDRs("allowlist", "ns-a", "1.2.3.4/32")
		route := testRoute("svc-a", "ns-a", "svc-a.example.com")
		route.Annotations["ipam.adevinta.com/allowlist-group"] = "allowlist"
		gw := testGateway("my-gw", "gw-ns")
		c, updates := countingAPUpdates(t, cidrs, route, gw)
		w := newIstioL7Writer(c)
		routes := []*gatewayApiv1.HTTPRoute{route}

		require.NoError(t, w.ApplyMerged(ctx, gw, routes, "shared-service"))
		require.NoError(t, w.ApplyMerged(ctx, gw, routes, "shared-service"))
		assert.Equal(t, 0, *updates, "the same allowlist again: no Update")

		cidrs.Status.CIDRs = []string{"5.6.7.8/32"}
		require.NoError(t, c.Update(ctx, cidrs)) // no status subresource in this fake client: Update writes the status
		require.NoError(t, w.ApplyMerged(ctx, gw, routes, "shared-service"))
		assert.Equal(t, 1, *updates, "a real change: one Update")
	})
}
