package resolvers

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

func resetGroupMetrics(t *testing.T) {
	t.Helper()
	missingCIDRs.Reset()
	t.Cleanup(func() { missingCIDRs.Reset() })
}

// TestMissingCIDRsMetricCountsPerObject verifies the bounded metric: one series per object, the
// number of named groups that are missing or empty, over both annotations, a group named twice
// counted once.
func TestMissingCIDRsMetricCountsPerObject(t *testing.T) {
	resetGroupMetrics(t)
	existing := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "localnet", Namespace: "ns"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	c := fake.NewClientBuilder().WithScheme(cacheMetricsTestScheme).WithObjects(existing).Build()
	resolver := CidrResolver{Client: c, AnnotationPrefix: DefaultPrefix}
	ingress := &netv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns", Annotations: map[string]string{
		"ipam.adevinta.com/allowlist-group":         "localnet,missing-a,missing-b,missing-a",
		"ipam.adevinta.com/cluster-allowlist-group": "missing-c",
	}}}

	_, err := resolver.GetCidrsFromObject(context.Background(), ingress)
	require.NoError(t, err)

	assert.Equal(t, 3.0, testutil.ToFloat64(missingCIDRs.With(prometheus.Labels{"namespace": "ns", "kind": "Ingress", "name": "app"})))
	assert.Equal(t, 1, testutil.CollectAndCount(missingCIDRs), "one series per object")

	ForgetObject("ns", "Ingress", "app")
	assert.Equal(t, 0, testutil.CollectAndCount(missingCIDRs), "deleted with the object")
}

// TestMissingCIDRsMetricCountsEveryGroup verifies that an annotation naming hundreds of groups
// still gives one series, counting them all: the group names are never labels.
func TestMissingCIDRsMetricCountsEveryGroup(t *testing.T) {
	resetGroupMetrics(t)
	existing := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "localnet", Namespace: "ns"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	c := fake.NewClientBuilder().WithScheme(cacheMetricsTestScheme).WithObjects(existing).Build()
	resolver := CidrResolver{Client: c, AnnotationPrefix: DefaultPrefix}
	names := []string{"localnet"}
	for i := range 200 {
		names = append(names, fmt.Sprintf("missing-%03d", i))
	}
	ingress := &netv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns", Annotations: map[string]string{
		"ipam.adevinta.com/allowlist-group": strings.Join(names, ","),
	}}}

	_, err := resolver.GetCidrsFromObject(context.Background(), ingress)
	require.NoError(t, err)

	assert.Equal(t, 1, testutil.CollectAndCount(missingCIDRs), "one series, not one per group")
	assert.Equal(t, 200.0, testutil.ToFloat64(missingCIDRs.With(prometheus.Labels{"namespace": "ns", "kind": "Ingress", "name": "app"})))
}
