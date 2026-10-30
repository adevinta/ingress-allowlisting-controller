package resolvers

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// missingSeries returns cidrs_name -> value of the cidrsNotFound series in namespace.
func missingSeries(t *testing.T, namespace string) map[string]float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(cidrsNotFound))
	families, err := reg.Gather()
	require.NoError(t, err)
	series := map[string]float64{}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["namespace"] == namespace {
				series[labels["cidrs_name"]] = m.GetGauge().GetValue()
			}
		}
	}
	return series
}

func ingressWithGroups(namespace, groups string) *netv1.Ingress {
	ing := &netv1.Ingress{
		// The kind is set on objects read from the cache; it becomes the "object" label.
		TypeMeta:   metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: namespace},
	}
	if groups != "" {
		ing.Annotations = map[string]string{DefaultPrefix + "/allowlist-group": groups}
	}
	return ing
}

// TestMissingSeriesFollowAnnotation verifies that the cidrsNotFound series of an object are rebuilt
// from its current annotation, so a removed group or annotation doesn't leave a stale series.
func TestMissingSeriesFollowAnnotation(t *testing.T) {
	const ns = "metrics-follow-annotation"
	resolver := CidrResolver{Client: fake.NewClientBuilder().WithScheme(cacheMetricsTestScheme).Build(), AnnotationPrefix: DefaultPrefix}
	ctx := context.Background()

	_, err := resolver.GetCidrsFromObject(ctx, ingressWithGroups(ns, "a,b"))
	require.NoError(t, err)
	assert.Equal(t, map[string]float64{"a": 1, "b": 1}, missingSeries(t, ns))

	_, err = resolver.GetCidrsFromObject(ctx, ingressWithGroups(ns, "a"))
	require.NoError(t, err)
	assert.Equal(t, map[string]float64{"a": 1}, missingSeries(t, ns), "a group removed from the annotation loses its series")

	_, _ = resolver.GetCidrsFromObject(ctx, ingressWithGroups(ns, "")) // AnnotationNotFoundError
	assert.Empty(t, missingSeries(t, ns), "removing the annotation removes the series")
}

// TestForgetObject verifies that ForgetObject removes one object's series and nothing else.
func TestForgetObject(t *testing.T) {
	const ns = "metrics-forget-object"
	resolver := CidrResolver{Client: fake.NewClientBuilder().WithScheme(cacheMetricsTestScheme).Build(), AnnotationPrefix: DefaultPrefix}
	ctx := context.Background()
	other := ingressWithGroups(ns, "c")
	other.Name = "api"
	_, err := resolver.GetCidrsFromObject(ctx, ingressWithGroups(ns, "a"))
	require.NoError(t, err)
	_, err = resolver.GetCidrsFromObject(ctx, other)
	require.NoError(t, err)

	ForgetObject(ns, "Ingress", "web")

	assert.Equal(t, map[string]float64{"c": 1}, missingSeries(t, ns))
}
