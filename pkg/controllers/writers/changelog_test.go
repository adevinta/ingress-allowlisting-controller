package writers

import (
	"bytes"
	"context"
	"strings"
	"testing"

	log "github.com/adevinta/go-log-toolkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// infoLines captures the info log lines written while f runs.
func infoLines(t *testing.T, f func()) []string {
	t.Helper()
	var buf bytes.Buffer
	out := log.DefaultLogger.Out
	log.DefaultLogger.SetOutput(&buf)
	t.Cleanup(func() { log.DefaultLogger.SetOutput(out) })
	f()
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.Contains(l, `"level":"info"`) {
			lines = append(lines, l)
		}
	}
	return lines
}

// TestWritersLogOnlyRealChanges verifies that a writer logs at info when it creates, updates or
// deletes an object, and stays quiet when a reconcile changes nothing, which is most of them.
func TestWritersLogOnlyRealChanges(t *testing.T) {
	ctx := context.Background()
	gw := testL4Gateway("my-gateway", "mynamespace")
	c := fake.NewClientBuilder().WithScheme(istioL4Scheme).WithObjects(gw).Build()
	w := NewIstioL4Writer(c, "ingress-allowlisting-controller", "ipam.adevinta.com")

	lines := infoLines(t, func() { require.NoError(t, w.Apply(ctx, istioL4Scheme, gw, []string{"10.0.0.0/8"})) })
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], "AuthorizationPolicy mynamespace/my-gateway created (Gateway my-gateway)")

	lines = infoLines(t, func() { require.NoError(t, w.Apply(ctx, istioL4Scheme, gw, []string{"10.0.0.0/8"})) })
	assert.Empty(t, lines, "unchanged: no info line")

	lines = infoLines(t, func() { require.NoError(t, w.Apply(ctx, istioL4Scheme, gw, []string{"192.0.2.0/24"})) })
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], "AuthorizationPolicy mynamespace/my-gateway updated")

	lines = infoLines(t, func() { require.NoError(t, w.Delete(ctx, gw)) })
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], "AuthorizationPolicy mynamespace/my-gateway deleted")

	lines = infoLines(t, func() { require.NoError(t, w.Delete(ctx, gw)) })
	assert.Empty(t, lines, "nothing to delete: no info line")
}

// TestRouteWritersLogOnlyRealChanges verifies the same for the HTTPRoute writers, including the
// case staging logged on every reconcile: removing the policies of a writer that has none for the
// route ("deleted stale policies") is not logged, since nothing was deleted.
func TestRouteWritersLogOnlyRealChanges(t *testing.T) {
	ctx := context.Background()
	gw := testGateway("my-gw", "mynamespace")
	route := testRoute("my-route", "mynamespace", "app.example.com")
	c := fake.NewClientBuilder().WithScheme(istioL7Scheme).WithObjects(gw, route).Build()
	istio := newIstioL7Writer(c)
	hosts := []string{"app.example.com"}

	lines := infoLines(t, func() {
		require.NoError(t, istio.Apply(ctx, istioL7Scheme, route, gw, []string{"10.0.0.0/8"}, hosts, nil))
	})
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], "created (HTTPRoute mynamespace/my-route)")

	lines = infoLines(t, func() {
		require.NoError(t, istio.Apply(ctx, istioL7Scheme, route, gw, []string{"10.0.0.0/8"}, hosts, nil))
	})
	assert.Empty(t, lines, "unchanged: no info line")

	// Its own client: the Traefik types are in another test scheme. It only has to find nothing.
	tc := fake.NewClientBuilder().WithScheme(traefikScheme).WithObjects(route.DeepCopy()).Build()
	traefik := NewTraefikL7Writer(tc, "ingress-allowlisting-controller", resolvers.CidrResolver{Client: tc, AnnotationPrefix: resolvers.DefaultPrefix})
	lines = infoLines(t, func() {
		require.NoError(t, traefik.DeleteForRoute(ctx, "ingress-allowlisting-controller", "mynamespace", "my-route"))
	})
	assert.Empty(t, lines, "a writer with nothing for the route: nothing deleted, nothing logged")

	lines = infoLines(t, func() {
		require.NoError(t, istio.DeleteForRoute(ctx, "ingress-allowlisting-controller", "mynamespace", "my-route"))
	})
	require.Len(t, lines, 1, "the route's real policy is deleted and logged")
	assert.Contains(t, lines[0], "deleted (HTTPRoute mynamespace/my-route no longer uses this writer)")
}
