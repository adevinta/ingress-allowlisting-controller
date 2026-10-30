package controllers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// TestLogAnnotationRemoval verifies that an in-place kind losing its allowlist annotation is logged
// once, at the removal, and that the predicate never filters anything.
func TestLogAnnotationRemoval(t *testing.T) {
	ingress := func(annotations map[string]string) *netv1.Ingress {
		return &netv1.Ingress{ObjectMeta: v1.ObjectMeta{Name: "web", Namespace: "team-a", Annotations: annotations}}
	}
	annotated := map[string]string{"ipam.adevinta.com/allowlist-group": "office"}
	clusterAnnotated := map[string]string{"ipam.adevinta.com/cluster-allowlist-group": "office"}
	other := map[string]string{"team": "a"}
	p := logAnnotationRemoval("Ingress", "ipam.adevinta.com")

	cases := []struct {
		name     string
		old, new map[string]string
		logged   bool
	}{
		{"allowlist-group removed", annotated, other, true},
		{"cluster-allowlist-group removed", clusterAnnotated, nil, true},
		{"still annotated", annotated, annotated, false},
		{"annotation added", other, annotated, false},
		{"never annotated (or resync)", other, other, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			assert.True(t, p.Update(event.UpdateEvent{ObjectOld: ingress(tc.old), ObjectNew: ingress(tc.new)}), "the predicate filters nothing")
			if tc.logged {
				assert.Equal(t, 1, strings.Count(logs.String(), "allowlist annotation removed"))
				assert.Contains(t, logs.String(), "Ingress team-a/web")
				assert.Contains(t, logs.String(), "stays in place")
			} else {
				assert.NotContains(t, logs.String(), "allowlist annotation removed")
			}
		})
	}

	logs := captureLogs(t)
	assert.True(t, p.Create(event.CreateEvent{Object: ingress(annotated)}))
	assert.True(t, p.Delete(event.DeleteEvent{Object: ingress(annotated)}), "a deleted object is gone, nothing stays")
	assert.Empty(t, logs.String())
}
