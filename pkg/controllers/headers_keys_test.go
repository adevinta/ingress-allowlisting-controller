package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

// sharedCredentials is a Secret holding the feed's token next to credentials meant for others.
func sharedCredentials(ns string) *v1.Secret {
	return &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "shared-credentials", Namespace: ns},
		Data: map[string][]byte{
			"Authorization": []byte("Bearer feed-token\n"),
			"db-password":   []byte("not-for-the-feed"),
		},
	}
}

// TestUpdateClientHeadersKeys verifies that headersFrom.keys sends only the listed keys of the
// Secret or ConfigMap, finds them in either object of an entry, and fails, naming the key but no
// value, when a listed key is in none of them. Without keys every key is sent, as before.
func TestUpdateClientHeadersKeys(t *testing.T) {
	ctx := context.Background()
	const ns = "team-a"
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "feed-settings", Namespace: ns},
		Data:       map[string]string{"X-Client": "allowlisting", "X-Debug": "on"},
	}
	r := &CIDRReconciler{Client: fake.NewClientBuilder().WithObjects(sharedCredentials(ns), cm).Build()}
	secretRef := ipamv1alpha1.ObjectRef{Name: "shared-credentials"}

	t.Run("only the listed keys", func(t *testing.T) {
		headers := http.Header{}
		require.NoError(t, r.updateClientHeaders(ctx, ns, headers, []ipamv1alpha1.HeadersFrom{{SecretRef: secretRef, Keys: []string{"Authorization"}}}))
		assert.Equal(t, http.Header{"Authorization": {"Bearer feed-token"}}, headers)
	})

	t.Run("keys found in either object of the entry", func(t *testing.T) {
		headers := http.Header{}
		require.NoError(t, r.updateClientHeaders(ctx, ns, headers, []ipamv1alpha1.HeadersFrom{{
			SecretRef: secretRef, ConfigMapRef: ipamv1alpha1.ObjectRef{Name: "feed-settings"}, Keys: []string{"Authorization", "X-Client"},
		}}))
		assert.Equal(t, http.Header{"Authorization": {"Bearer feed-token"}, "X-Client": {"allowlisting"}}, headers)
	})

	t.Run("a listed key that isn't there fails the fetch", func(t *testing.T) {
		headers := http.Header{}
		err := r.updateClientHeaders(ctx, ns, headers, []ipamv1alpha1.HeadersFrom{{SecretRef: secretRef, Keys: []string{"Authorization", "X-Api-Key"}}})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `key "X-Api-Key" not found in Secret team-a/shared-credentials`)
		assert.NotContains(t, err.Error(), "feed-token", "no value in the error")
	})

	t.Run("without keys every key is sent, as before", func(t *testing.T) {
		headers := http.Header{}
		require.NoError(t, r.updateClientHeaders(ctx, ns, headers, []ipamv1alpha1.HeadersFrom{{SecretRef: secretRef}}))
		assert.Equal(t, http.Header{"Authorization": {"Bearer feed-token"}, "Db-Password": {"not-for-the-feed"}}, headers)
	})
}

// TestCIDRsFetchSendsOnlyTheListedKeys verifies end to end that the source receives only the keys
// headersFrom lists, not the other credentials of the same Secret.
func TestCIDRsFetchSendsOnlyTheListedKeys(t *testing.T) {
	ctx := context.Background()
	const ns = "team-a"
	scheme, err := Scheme()
	require.NoError(t, err)
	var mu sync.Mutex
	var received http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = r.Header.Clone()
		mu.Unlock()
		_, _ = w.Write([]byte(`["192.0.2.0/24"]`))
	}))
	defer server.Close()
	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "feed", Namespace: ns},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{Location: ipamv1alpha1.CIDRsLocation{
			URI:         server.URL,
			HeadersFrom: []ipamv1alpha1.HeadersFrom{{SecretRef: ipamv1alpha1.ObjectRef{Name: "shared-credentials"}, Keys: []string{"Authorization"}}},
		}}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs, sharedCredentials(ns)).WithStatusSubresource(cidrs).Build()
	r := &CIDRReconciler{
		SourceOptions:      CIDRSourceOptions{AllowPrivateDestinations: true}, // the test server is on 127.0.0.1
		CIDRs:              &ipamv1alpha1.CIDRs{},
		CIDRsList:          &ipamv1alpha1.CIDRsList{},
		Client:             c,
		HTTPHeadersEnabled: true,
	}

	_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "Bearer feed-token", received.Get("Authorization"))
	assert.Empty(t, received.Get("Db-Password"), "the Secret's other credentials stay home")
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))
	assert.Equal(t, []string{"192.0.2.0/24"}, cidrs.Status.CIDRs)
}
