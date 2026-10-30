package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// missingGroupSeries counts the missing-group series of one namespace in the controller's registry.
func missingGroupSeries(t *testing.T, namespace string) int {
	t.Helper()
	families, err := metrics.Registry.Gather()
	require.NoError(t, err)
	n := 0
	for _, f := range families {
		if f.GetName() != "namespace_ingress_IpAllowlistingGroup_missing" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "namespace" && l.GetValue() == namespace {
					n++
				}
			}
		}
	}
	return n
}

// TestReconcileDeletedObjectForgetsMetrics verifies that once an allowlisted object is deleted, its
// missing-group series is removed instead of staying (e.g. as an alert that never clears).
func TestReconcileDeletedObjectForgetsMetrics(t *testing.T) {
	const ns = "metrics-deleted-object"
	ctx := context.Background()
	ingress := &netv1.Ingress{ObjectMeta: v1.ObjectMeta{Name: "web", Namespace: ns, Annotations: map[string]string{
		"ipam.adevinta.com/allowlist-group": "missing",
	}}}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(ingress).Build()
	reconciler := newIngressReconciler(t, k8sClient)
	req := reconcile.Request{NamespacedName: client.ObjectKeyFromObject(ingress)}

	_, err := reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	require.Equal(t, 1, missingGroupSeries(t, ns), "precondition: the missing group is reported")

	require.NoError(t, k8sClient.Delete(ctx, ingress))
	_, err = reconciler.Reconcile(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, 0, missingGroupSeries(t, ns), "a deleted object keeps no series")
}
