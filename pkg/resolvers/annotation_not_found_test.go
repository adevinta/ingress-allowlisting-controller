package resolvers_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

func unannotatedIngress() *netv1.Ingress {
	return &netv1.Ingress{ObjectMeta: v1.ObjectMeta{Name: "web", Namespace: "team-a"}}
}

// TestErrAnnotationNotFound verifies that an object without the allowlist annotations is
// recognised with errors.Is in the cases where the old lazily built error and == failed: a copy of
// the resolver (controllers.go hands out copies), a wrapped error, and concurrent use.
func TestErrAnnotationNotFound(t *testing.T) {
	newResolver := func() resolvers.CidrResolver {
		return resolvers.CidrResolver{Client: fake.NewClientBuilder().WithScheme(extendedScheme).Build(), AnnotationPrefix: resolvers.DefaultPrefix}
	}

	t.Run("names both annotations", func(t *testing.T) {
		r := newResolver()
		_, err := r.GetCidrsFromObject(context.Background(), unannotatedIngress())
		require.ErrorIs(t, err, resolvers.ErrAnnotationNotFound)
		assert.Contains(t, err.Error(), `"ipam.adevinta.com/allowlist-group" or "ipam.adevinta.com/cluster-allowlist-group"`)
	})

	t.Run("from any copy of the resolver", func(t *testing.T) {
		a := newResolver()
		b := a // a copy made before first use
		_, errA := a.GetCidrsFromObject(context.Background(), unannotatedIngress())
		_, errB := b.GetCidrsFromObject(context.Background(), unannotatedIngress())
		assert.ErrorIs(t, errA, resolvers.ErrAnnotationNotFound)
		assert.ErrorIs(t, errB, resolvers.ErrAnnotationNotFound)
	})

	t.Run("still recognised once wrapped", func(t *testing.T) {
		r := newResolver()
		_, err := r.GetCidrsFromObject(context.Background(), unannotatedIngress())
		assert.ErrorIs(t, fmt.Errorf("resolving ingress team-a/web: %w", err), resolvers.ErrAnnotationNotFound)
	})

	t.Run("concurrent use shares no mutable state", func(t *testing.T) {
		r := newResolver()
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := r.GetCidrsFromObject(context.Background(), unannotatedIngress())
				assert.ErrorIs(t, err, resolvers.ErrAnnotationNotFound)
			}()
		}
		wg.Wait()
	})
}
