package controllers

import (
	"bytes"
	"context"
	"errors"
	"testing"

	log "github.com/adevinta/go-log-toolkit"
	"github.com/stretchr/testify/assert"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

// failingListClient returns a fake client whose List always fails, like a cache that isn't synced.
func failingListClient() client.Client {
	return fake.NewClientBuilder().WithScheme(extendedScheme).WithInterceptorFuncs(interceptor.Funcs{
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			return errors.New("cache not synced")
		},
	}).Build()
}

// captureLogs sends the default logger's output to a buffer for the rest of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	out := log.DefaultLogger.Out
	log.DefaultLogger.SetOutput(&buf)
	t.Cleanup(func() { log.DefaultLogger.SetOutput(out) })
	return &buf
}

// TestWatchMappersLogDroppedChanges verifies that a watch mapper whose List fails logs the dropped
// change instead of swallowing it: the referencing objects keep their allowlist until their next
// change or the resync, so it must be visible.
func TestWatchMappersLogDroppedChanges(t *testing.T) {
	cidrs := &ipamv1alpha1.CIDRs{ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "team-a"}}

	t.Run("CIDRs to referencing objects", func(t *testing.T) {
		logs := captureLogs(t)
		mapper := newObjectsFromCIDRFuncMap(failingListClient(), func() client.ObjectList { return &netv1.IngressList{} }, "ipam.adevinta.com/allowlist-group")

		assert.Empty(t, mapper(context.Background(), cidrs))
		assert.Contains(t, logs.String(), "dropped change of *v1alpha1.CIDRs team-a/localnet: listing *v1.IngressList")
		assert.Contains(t, logs.String(), "cache not synced")
	})

	t.Run("header source to CIDRs objects", func(t *testing.T) {
		logs := captureLogs(t)
		mapper := newObjectRefToCIDRsFuncMap(failingListClient(), &ipamv1alpha1.CIDRsList{}, func(h ipamv1alpha1.HeadersFrom) ipamv1alpha1.ObjectRef {
			return h.SecretRef
		})
		secret := &v1.PartialObjectMetadata{ObjectMeta: v1.ObjectMeta{Name: "token", Namespace: "team-a"}}

		assert.Empty(t, mapper(context.Background(), secret))
		assert.Contains(t, logs.String(), "dropped change of header source team-a/token: listing *v1alpha1.CIDRsList")
		assert.Contains(t, logs.String(), "cache not synced")
	})
}
