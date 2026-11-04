package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// otherFinalizer is what another controller adds while we write: on EKS the VPC CNI adds
// networking.k8s.aws/resources to every new NetworkPolicy right after it is created.
const otherFinalizer = "example.com/other-controller"

// racingClient returns a fake client on which another controller changes the object (adds
// otherFinalizer) right before the controller's first write of it is applied, so that write is
// based on an outdated resourceVersion. writes counts the controller's writes.
func racingClient(objs ...client.Object) (c client.Client, writes *int) {
	writes = new(int)
	race := func(ctx context.Context, store client.WithWatch, obj client.Object) error {
		*writes++
		if *writes > 1 {
			return nil
		}
		current := obj.DeepCopyObject().(client.Object)
		if err := store.Get(ctx, client.ObjectKeyFromObject(obj), current); err != nil {
			return err
		}
		controllerutil.AddFinalizer(current, otherFinalizer)
		return store.Update(ctx, current)
	}
	c = fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(objs...).WithInterceptorFuncs(interceptor.Funcs{
		Update: func(ctx context.Context, store client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
			if err := race(ctx, store, obj); err != nil {
				return err
			}
			return store.Update(ctx, obj, opts...)
		},
		Patch: func(ctx context.Context, store client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := race(ctx, store, obj); err != nil {
				return err
			}
			return store.Patch(ctx, obj, patch, opts...)
		},
	}).Build()
	return c, writes
}

// TestWritesDontConflictWithOtherControllers verifies that the NetworkPolicy, Ingress and Service
// controllers write their allowlist even when another controller changed the object since they
// read it, and keep that controller's change: they patch only the field they manage. With a full
// Update the write failed ("the object has been modified"), was logged as a reconcile error and
// retried. A second reconcile, with nothing changed, writes nothing.
func TestWritesDontConflictWithOtherControllers(t *testing.T) {
	ctx := context.Background()
	annotations := func() map[string]string {
		return map[string]string{"ipam.adevinta.com/allowlist-group": "office"}
	}
	cidrs := func() *ipamv1alpha1.CIDRs {
		return &ipamv1alpha1.CIDRs{
			ObjectMeta: metav1.ObjectMeta{Name: "office", Namespace: "team-a"},
			Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.0.2.0/24"}},
		}
	}
	resolver := func(c client.Client) resolvers.CidrResolver {
		return resolvers.CidrResolver{Client: c, AnnotationPrefix: resolvers.DefaultPrefix}
	}

	cases := map[string]struct {
		obj       client.Object
		reconcile func(c client.Client, req reconcile.Request) error
		allowlist func(t *testing.T, obj client.Object) []string
	}{
		"NetworkPolicy": {
			obj: &netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a", Annotations: annotations()}},
			reconcile: func(c client.Client, req reconcile.Request) error {
				_, err := (&NetworkPolicyReconciler{Client: c, CidrResolver: resolver(c)}).Reconcile(ctx, req)
				return err
			},
			allowlist: func(t *testing.T, obj client.Object) []string {
				np := obj.(*netv1.NetworkPolicy)
				require.Len(t, np.Spec.Egress, 1)
				return peerCIDRs(np.Spec.Egress[0].To)
			},
		},
		"Ingress": {
			obj: &netv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a", Annotations: annotations()}},
			reconcile: func(c client.Client, req reconcile.Request) error {
				_, err := (&IngressReconciler{Client: c, CidrResolver: resolver(c)}).Reconcile(ctx, req)
				return err
			},
			allowlist: func(_ *testing.T, obj client.Object) []string {
				return []string{obj.GetAnnotations()["nginx.ingress.kubernetes.io/whitelist-source-range"]}
			},
		},
		"Service": {
			obj: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team-a", Annotations: annotations()},
				Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
			},
			reconcile: func(c client.Client, req reconcile.Request) error {
				_, err := (&ServiceReconciler{Client: c, CidrResolver: resolver(c)}).Reconcile(ctx, req)
				return err
			},
			allowlist: func(_ *testing.T, obj client.Object) []string {
				return obj.(*corev1.Service).Spec.LoadBalancerSourceRanges
			},
		},
	}
	for kind, tc := range cases {
		t.Run(kind, func(t *testing.T) {
			c, writes := racingClient(cidrs(), tc.obj)
			req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(tc.obj)}

			require.NoError(t, tc.reconcile(c, req), "another controller's change must not make the write fail")
			got := tc.obj.DeepCopyObject().(client.Object)
			require.NoError(t, c.Get(ctx, req.NamespacedName, got))
			assert.Equal(t, []string{"192.0.2.0/24"}, tc.allowlist(t, got), "the allowlist is written")
			assert.Contains(t, got.GetFinalizers(), otherFinalizer, "the other controller's change stays")
			assert.Equal(t, 1, *writes)

			require.NoError(t, tc.reconcile(c, req))
			assert.Equal(t, 1, *writes, "unchanged: nothing written")
		})
	}
}

// peerCIDRs returns the ipBlock CIDRs of NetworkPolicy peers.
func peerCIDRs(peers []netv1.NetworkPolicyPeer) []string {
	var cidrs []string
	for _, p := range peers {
		if p.IPBlock != nil {
			cidrs = append(cidrs, p.IPBlock.CIDR)
		}
	}
	return cidrs
}
