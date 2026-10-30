package resolvers_test

import (
	"bytes"
	"context"
	"testing"

	log "github.com/adevinta/go-log-toolkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

func ingressWithoutAnnotation() *netv1.Ingress {
	return &netv1.Ingress{ObjectMeta: v1.ObjectMeta{Name: "web", Namespace: "team-a"}}
}

// setLevel sets the default logger's level by name.
func setLevel(t *testing.T, name string) {
	t.Helper()
	level := log.DefaultLogger.GetLevel()
	require.NoError(t, level.UnmarshalText([]byte(name)))
	log.DefaultLogger.SetLevel(level)
}

// TestUnannotatedObjectLoggedAtDebug verifies that resolving an object without the allowlist
// annotations logs at debug only: the in-place controllers do it for every object of their kind on
// every reconcile, which at info filled the logs.
func TestUnannotatedObjectLoggedAtDebug(t *testing.T) {
	var buf bytes.Buffer
	origOut, origLevel := log.DefaultLogger.Out, log.DefaultLogger.GetLevel()
	log.DefaultLogger.SetOutput(&buf)
	t.Cleanup(func() { log.DefaultLogger.SetOutput(origOut); log.DefaultLogger.SetLevel(origLevel) })
	r := resolvers.CidrResolver{Client: fake.NewClientBuilder().WithScheme(extendedScheme).Build(), AnnotationPrefix: resolvers.DefaultPrefix}

	setLevel(t, "info")
	_, _ = r.GetCidrsFromObject(context.Background(), ingressWithoutAnnotation())
	assert.NotContains(t, buf.String(), "does not have the allowlist group annotation", "hidden at info")

	setLevel(t, "debug")
	_, _ = r.GetCidrsFromObject(context.Background(), ingressWithoutAnnotation())
	assert.Contains(t, buf.String(), "does not have the allowlist group annotation", "shown at debug")
}
