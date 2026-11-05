package resolvers

import (
	"context"
	"testing"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var cacheMetricsTestScheme *runtime.Scheme

func init() {
	cacheMetricsTestScheme = runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(cacheMetricsTestScheme); err != nil {
		panic(err)
	}
	if err := ipamv1alpha1.AddToScheme(cacheMetricsTestScheme); err != nil {
		panic(err)
	}
}

// TestGetCidrsFromObjectWithCache_MetricsEmittedOnCacheHit verifies that missingCIDRs is set
// for every object even when its CIDR lookup is a cache hit.
//
// Regression: the previous cache in ApplyMerged returned cached IPs directly for subsequent
// siblings, skipping getIpsFromAnnotation entirely. This left those routes' missing-group gauges
// stale — a missing CIDR on sibling B would show as healthy (gauge = 0) while sibling A
// correctly showed unhealthy (gauge = 1).
func TestGetCidrsFromObjectWithCache_MetricsEmittedOnCacheHit(t *testing.T) {
	missingCIDRs.Reset()
	t.Cleanup(func() { missingCIDRs.Reset() })

	// No ClusterCIDRs object created — "missing-vpn" is intentionally absent.
	c := fake.NewClientBuilder().WithScheme(cacheMetricsTestScheme).Build()
	resolver := CidrResolver{Client: c, AnnotationPrefix: DefaultPrefix}
	cache := NewResolutionCache()

	ann := map[string]string{"ipam.adevinta.com/cluster-allowlist-group": "missing-vpn"}
	objA := &netv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "svc-a", Namespace: "ns-a", Annotations: ann}}
	objB := &netv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "svc-b", Namespace: "ns-b", Annotations: ann}}

	_, err := resolver.GetCidrsFromObjectWithCache(context.Background(), objA, cache)
	require.NoError(t, err)
	_, err = resolver.GetCidrsFromObjectWithCache(context.Background(), objB, cache)
	require.NoError(t, err)

	// Both objects must have missingCIDRs = 1.0 (one group missing).
	// If the cache skips getIpsFromAnnotation for hits, objB's gauge stays at 0.0 —
	// a silent false-healthy reading.
	// The kind label is the kind from the scheme, also for objects without TypeMeta.
	gaugeA := testutil.ToFloat64(missingCIDRs.With(prometheus.Labels{"namespace": "ns-a", "kind": "Ingress", "name": "svc-a"}))
	gaugeB := testutil.ToFloat64(missingCIDRs.With(prometheus.Labels{"namespace": "ns-b", "kind": "Ingress", "name": "svc-b"}))

	assert.Equal(t, 1.0, gaugeA, "svc-a: one group missing")
	assert.Equal(t, 1.0, gaugeB, "svc-b: one group missing, even though its lookup was a cache hit — if 0, the cache skipped the metric update")
}
