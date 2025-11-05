package controllers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestReconcileDoesNotFullyRemoveCIDRs(t *testing.T) {
	ctx := context.TODO()
	scheme, err := Scheme("")
	require.NoError(t, err)
	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: "mynamespace"},
		Status: ipamv1alpha1.CIDRsStatus{
			CIDRs: []string{
				"200.1.1.1/24",
				"10.0.0.1/24",
				"1.1.1.1/32",
				"10.0.0.1/24",
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		CIDRs:     &ipamv1alpha1.CIDRs{},
		CIDRsList: &ipamv1alpha1.CIDRsList{},
		Client:    fakeClient,
	}
	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	assert.Equal(t, reconcile.Result{}, result)

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, cidrs.GetStatus().State)
	assert.Equal(t, []string{
		"200.1.1.1/24",
		"10.0.0.1/24",
		"1.1.1.1/32",
		"10.0.0.1/24",
	}, cidrs.GetStatus().CIDRs)
	require.Len(t, cidrs.GetStatus().Conditions, 1)
	assert.Equal(t, ipamv1alpha1.CIDRsStatusConditionTypeUpToDate, cidrs.GetStatus().Conditions[0].Type)
	assert.Equal(t, v1.ConditionFalse, cidrs.GetStatus().Conditions[0].Status)
	assert.Contains(t, cidrs.GetStatus().Conditions[0].Message, "Refusing to update removing all CIDRs")
}

func TestCIDRsReconciler(t *testing.T) {
	ctx := context.TODO()
	scheme, err := Scheme("")
	require.NoError(t, err)
	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: "mynamespace"},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{
			"200.1.1.1/24",
			"10.0.0.1/24",
			"1.1.1.1",
			"10.0.0.1/24",
		}}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		CIDRs:     &ipamv1alpha1.CIDRs{},
		CIDRsList: &ipamv1alpha1.CIDRsList{},
		Client:    fakeClient,
	}
	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"1.1.1.1/32", "10.0.0.1/24", "200.1.1.1/24"}, cidrs.GetStatus().CIDRs)
}

func TestApplyProcessor(t *testing.T) {
	t.Run("When the content is json encoded", func(t *testing.T) {
		testApplyProcessor(t, toJsonReader)
	})
	t.Run("When the content is yaml encoded", func(t *testing.T) {
		testApplyProcessor(t, toYamlReader)
	})
}

func testApplyProcessor(t *testing.T, serialize func(*testing.T, any) io.Reader) {
	t.Helper()
	cidrs, err := applyProcessor(
		serialize(
			t,
			[]string{"127.0.0.1/32"},
		),
		ipamv1alpha1.Processing{},
	)
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1/32"}, cidrs)

	cidrs, err = applyProcessor(
		serialize(
			t,
			map[string][]string{
				"ips": {"127.0.0.1/32", "10.0.0.0/16"},
			},
		),
		ipamv1alpha1.Processing{
			JSONPath: "{.ips}",
		})
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1/32", "10.0.0.0/16"}, cidrs)

	_, err = applyProcessor(
		serialize(
			t,
			map[string][]any{
				"ips": {"127.0.0.1/32", 42},
			},
		),
		ipamv1alpha1.Processing{
			JSONPath: "{.ips}",
		})
	assert.Error(t, err)

	cidrs, err = applyProcessor(
		serialize(
			t,
			map[string][]string{
				"ips": {"127.0.0.1/32", "10.0.0.0/16"},
			},
		),
		ipamv1alpha1.Processing{
			JSONPath: "{.ips[*]}",
		})
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1/32", "10.0.0.0/16"}, cidrs)

	cidrs, err = applyProcessor(
		serialize(
			t,
			[]map[string]string{
				{"ip": "127.0.0.1/32"},
				{"ip": "10.0.0.0/16", "key": "value"},
			},
		),
		ipamv1alpha1.Processing{
			JSONPath: `{$[?(@.key=="value")].ip}`,
		})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0/16"}, cidrs)

	cidrs, err = applyProcessor(
		serialize(
			t,
			map[string]interface{}{
				"prefixes": []map[string]interface{}{
					{
						"service":   "other",
						"ip_prefix": "10.0.0.1/32",
					},
					{
						"service":   "my-service",
						"ip_prefix": "127.0.0.1/32",
					},
					{
						"service":   "my-service",
						"ip_prefix": "10.0.0.0/16",
					},
					{
						"service": "my-service",
					},
				},
			},
		),
		ipamv1alpha1.Processing{
			JSONPath: "{$.prefixes[?(@.service == 'my-service')].ip_prefix}",
		},
	)
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1/32", "10.0.0.0/16"}, cidrs)

	_, err = applyProcessor(
		serialize(
			t,
			map[string]interface{}{
				"prefixes": []map[string]interface{}{
					{
						"service":   "my-service",
						"ip_prefix": 42,
					},
				},
			},
		),
		ipamv1alpha1.Processing{
			JSONPath: "{$.prefixes[?(@.service == 'my-service')].ip_prefix}",
		},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "42")
	assert.Contains(t, err.Error(), "unexpected value type")
}

func TestCIDRsReconcileFromHTTP(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme("")
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		assert.Equal(t, "Bearer my-token", r.Header.Get("Authentication"))
		w.Write([]byte(`["200.1.1.1/24", "10.0.0.1/24", "1.1.1.1", "10.0.0.1/24"]`))
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
				HeadersFrom: []ipamv1alpha1.HeadersFrom{
					{
						SecretRef: ipamv1alpha1.ObjectRef{Name: "my-secret"},
					},
				},
			},
		}},
	}
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: testNamespaceName,
		},
		Data: map[string][]byte{
			"Authentication": []byte("Bearer my-token"),
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs, secret).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		CIDRs:     &ipamv1alpha1.CIDRs{},
		CIDRsList: &ipamv1alpha1.CIDRsList{},
		Client:    fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"1.1.1.1/32", "10.0.0.1/24", "200.1.1.1/24"}, cidrs.GetStatus().CIDRs)
}

func TestCIDRsReconcileFromGitHubBase64HTTPResponse(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme("")
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-github-media-type", "github.v3; format=json")
		w.WriteHeader(http.StatusOK)

		ips := `["200.1.1.1/24", "10.0.0.1/24", "1.1.1.1/32", "10.0.0.1/24"]`

		response := map[string]interface{}{
			"type":     "file",
			"content":  base64.StdEncoding.EncodeToString([]byte(ips)),
			"encoding": "base64",
		}

		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		CIDRs:     &ipamv1alpha1.CIDRs{},
		CIDRsList: &ipamv1alpha1.CIDRsList{},
		Client:    fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"1.1.1.1/32", "10.0.0.1/24", "200.1.1.1/24"}, cidrs.GetStatus().CIDRs)
}

func TestCIDRsReconcileFromGitHubNilEncodingHTTPResponse(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme("")
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-github-media-type", "github.v3; format=json")
		w.WriteHeader(http.StatusOK)

		ips := `["200.1.1.1/24", "10.0.0.1/24", "1.1.1.1/32", "10.0.0.1/24"]`

		response := map[string]interface{}{
			"type":    "file",
			"content": ips,
		}

		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		CIDRs:     &ipamv1alpha1.CIDRs{},
		CIDRsList: &ipamv1alpha1.CIDRsList{},
		Client:    fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"1.1.1.1/32", "10.0.0.1/24", "200.1.1.1/24"}, cidrs.GetStatus().CIDRs)
}

func TestCIDRsReconcileFromGitHubPlainTextHTTPResponse(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme("")
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-github-media-type", "github.v3; format=json")
		w.WriteHeader(http.StatusOK)

		ips := `["200.1.1.1/24", "10.0.0.1/24", "1.1.1.1/32", "10.0.0.1/24"]`

		response := map[string]interface{}{
			"type":     "file",
			"content":  ips,
			"encoding": "",
		}

		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		CIDRs:     &ipamv1alpha1.CIDRs{},
		CIDRsList: &ipamv1alpha1.CIDRsList{},
		Client:    fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"1.1.1.1/32", "10.0.0.1/24", "200.1.1.1/24"}, cidrs.GetStatus().CIDRs)
}

func TestCIDRsReconcileFromPlainTextHTTPResponse(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme("")
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("200.1.1.1/24\r\n10.0.0.1/24\n\n#8.8.8.8/32\n1.1.1.1/32 \n\n10.0.0.1/24\r\n\n"))
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
				Processing: ipamv1alpha1.Processing{
					Format: "LineSeparatedValues",
				},
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		CIDRs:     &ipamv1alpha1.CIDRs{},
		CIDRsList: &ipamv1alpha1.CIDRsList{},
		Client:    fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"1.1.1.1/32", "10.0.0.1/24", "200.1.1.1/24"}, cidrs.GetStatus().CIDRs)
}

func TestCIDRsReconcileFromGitHubInvalidEncodingHTTPResponse(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme("")
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-github-media-type", "github.v3; format=json")
		w.WriteHeader(http.StatusOK)

		ips := `["200.1.1.1/24", "10.0.0.1/24", "1.1.1.1/32", "10.0.0.1/24"]`

		response := map[string]interface{}{
			"type":     "file",
			"content":  ips,
			"encoding": "what-is-this",
		}

		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		CIDRs:     &ipamv1alpha1.CIDRs{},
		CIDRsList: &ipamv1alpha1.CIDRsList{},
		Client:    fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Nil(t, cidrs.GetStatus().CIDRs)
	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, cidrs.GetStatus().State)
	require.Len(t, cidrs.GetStatus().Conditions, 1)
	assert.Equal(t, ipamv1alpha1.CIDRsStatusConditionTypeUpToDate, cidrs.GetStatus().Conditions[0].Type)
	assert.Equal(t, v1.ConditionFalse, cidrs.GetStatus().Conditions[0].Status)
	assert.Contains(t, cidrs.GetStatus().Conditions[0].Message, "unexpected encoding")
	assert.Contains(t, cidrs.GetStatus().Conditions[0].Message, "what-is-this")
}

func TestCIDRsReconcileFromAWSRules(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme("")
	require.NoError(t, err)

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: "https://ip-ranges.amazonaws.com/ip-ranges.json",
				Processing: ipamv1alpha1.Processing{
					JSONPath: "{.prefixes[?(@.service == 'EC2')].ip_prefix}",
				},
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		CIDRs:     &ipamv1alpha1.CIDRs{},
		CIDRsList: &ipamv1alpha1.CIDRsList{},
		Client:    fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Greater(t, len(cidrs.GetStatus().CIDRs), 0)
}

func TestCIDRsReconcileFromHTTPWhenGetFails(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme("")
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{
			CIDRsSource: ipamv1alpha1.CIDRsSource{
				Location: ipamv1alpha1.CIDRsLocation{
					URI: server.URL,
				},
			},
		},
		Status: ipamv1alpha1.CIDRsStatus{
			// For example when switching from plain CIDRs to dynamic ones
			CIDRs: []string{"127.0.0.1/32"},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		CIDRs:     &ipamv1alpha1.CIDRs{},
		CIDRsList: &ipamv1alpha1.CIDRsList{},
		Client:    fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, cidrs.Status.State)

	assert.Equal(t, []string{"127.0.0.1/32"}, cidrs.GetStatus().CIDRs)

	require.Len(t, cidrs.GetStatus().Conditions, 1)

	assert.Equal(t, ipamv1alpha1.CIDRsStatusConditionTypeUpToDate, cidrs.GetStatus().Conditions[0].Type)
	assert.Equal(t, v1.ConditionFalse, cidrs.GetStatus().Conditions[0].Status)
	assert.Contains(t, cidrs.GetStatus().Conditions[0].Message, "Failed to get CIDRs from http source")
	assert.Contains(t, cidrs.GetStatus().Conditions[0].Message, "403")
}

func TestUpdateClientHeaders(t *testing.T) {
	testNamespaceName := "mynamespace"
	ctx := context.TODO()
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-configmap",
			Namespace: testNamespaceName,
		},
		Data: map[string]string{
			"header-in-cm":   "value1",
			"header-in-both": "value2",
		},
	}
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: testNamespaceName,
		},
		Data: map[string][]byte{
			"header-in-secret": []byte("value3"),
			"header-in-both":   []byte("value4"),
		},
	}
	fakeClient := fake.NewClientBuilder().WithObjects(cm, secret).Build()
	reconciler := &CIDRReconciler{
		Client: fakeClient,
	}

	t.Run("When the referenced secret does not exist", func(t *testing.T) {
		headers := http.Header{}
		assert.Error(t, reconciler.updateClientHeaders(ctx, testNamespaceName, headers, []ipamv1alpha1.HeadersFrom{
			{
				SecretRef: ipamv1alpha1.ObjectRef{Name: "non-existing"},
			},
		}))
		assert.Equal(
			t,
			http.Header{},
			headers,
		)
	})

	t.Run("When the referenced configmap does not exist", func(t *testing.T) {
		headers := http.Header{}
		assert.Error(t, reconciler.updateClientHeaders(ctx, testNamespaceName, headers, []ipamv1alpha1.HeadersFrom{
			{
				ConfigMapRef: ipamv1alpha1.ObjectRef{Name: "non-existing"},
			},
		}))
		assert.Equal(
			t,
			http.Header{},
			headers,
		)
	})

	t.Run("When the object is namespace-scoped", func(t *testing.T) {
		t.Run("When no namespace is provided in the objectRef", func(t *testing.T) {
			headers := http.Header{}
			assert.NoError(t, reconciler.updateClientHeaders(ctx, testNamespaceName, headers, []ipamv1alpha1.HeadersFrom{
				{
					ConfigMapRef: ipamv1alpha1.ObjectRef{Name: "my-configmap"},
				},
				{
					SecretRef: ipamv1alpha1.ObjectRef{Name: "my-secret"},
				},
			}))
			assert.Equal(
				t,
				http.Header{
					http.CanonicalHeaderKey("header-in-cm"):     []string{"value1"},
					http.CanonicalHeaderKey("header-in-both"):   []string{"value2", "value4"},
					http.CanonicalHeaderKey("header-in-secret"): []string{"value3"},
				},
				headers,
			)
		})
		t.Run("When the same namespace is provided in the objectRef", func(t *testing.T) {
			headers := http.Header{}
			assert.NoError(t, reconciler.updateClientHeaders(ctx, testNamespaceName, headers, []ipamv1alpha1.HeadersFrom{
				{
					ConfigMapRef: ipamv1alpha1.ObjectRef{Name: "my-configmap", Namespace: testNamespaceName},
				},
				{
					SecretRef: ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: testNamespaceName},
				},
			}))
			assert.Equal(
				t,
				http.Header{
					http.CanonicalHeaderKey("header-in-cm"):     []string{"value1"},
					http.CanonicalHeaderKey("header-in-both"):   []string{"value2", "value4"},
					http.CanonicalHeaderKey("header-in-secret"): []string{"value3"},
				},
				headers,
			)
		})
		t.Run("When another namespace is provided in the objectRef", func(t *testing.T) {
			headers := http.Header{}
			assert.Error(t, reconciler.updateClientHeaders(ctx, testNamespaceName, headers, []ipamv1alpha1.HeadersFrom{
				{
					ConfigMapRef: ipamv1alpha1.ObjectRef{Name: "my-configmap", Namespace: "other-namespace"},
				},
				{
					SecretRef: ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: "other-namespace"},
				},
			}))
			assert.Equal(
				t,
				http.Header{},
				headers,
			)
		})
	})
	t.Run("When the object is custer-scoped", func(t *testing.T) {
		t.Run("When no namespace is provided in the objectRef", func(t *testing.T) {
			headers := http.Header{}
			assert.Error(t, reconciler.updateClientHeaders(ctx, "", headers, []ipamv1alpha1.HeadersFrom{
				{
					ConfigMapRef: ipamv1alpha1.ObjectRef{Name: "my-configmap"},
				},
				{
					SecretRef: ipamv1alpha1.ObjectRef{Name: "my-secret"},
				},
			}))
			assert.Equal(
				t,
				http.Header{},
				headers,
			)
		})
		t.Run("when the namespace is provided in the objectRef", func(t *testing.T) {
			headers := http.Header{}
			assert.NoError(t, reconciler.updateClientHeaders(ctx, "", headers, []ipamv1alpha1.HeadersFrom{
				{
					ConfigMapRef: ipamv1alpha1.ObjectRef{Name: "my-configmap", Namespace: "mynamespace"},
				},
				{
					SecretRef: ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: "mynamespace"},
				},
			}))
			assert.Equal(
				t,
				http.Header{
					http.CanonicalHeaderKey("header-in-cm"):     []string{"value1"},
					http.CanonicalHeaderKey("header-in-both"):   []string{"value2", "value4"},
					http.CanonicalHeaderKey("header-in-secret"): []string{"value3"},
				},
				headers,
			)
		})
	})
}

func TestObjectLinks(t *testing.T) {
	headersFrom := ipamv1alpha1.HeadersFrom{
		ConfigMapRef: ipamv1alpha1.ObjectRef{
			Name:      "my-configmap",
			Namespace: "mynamespace",
		},
		SecretRef: ipamv1alpha1.ObjectRef{
			Name:      "my-secret",
			Namespace: "mynamespace",
		},
	}

	assert.Equal(
		t,
		ipamv1alpha1.ObjectRef{
			Name:      "my-secret",
			Namespace: "mynamespace",
		},
		secretSource(headersFrom),
	)

	assert.Equal(
		t,
		ipamv1alpha1.ObjectRef{
			Name:      "my-configmap",
			Namespace: "mynamespace",
		},
		configMapSource(headersFrom),
	)
}

func TestObjectRefToCIDRsMapper(t *testing.T) {
	t.Run("when using namespaced cidrs", func(t *testing.T) {
		t.Run("When cidrs are in the same namespaces as the secret", func(t *testing.T) {
			testCaseObjectRefToCIDRsMapper(
				t,
				&ipamv1alpha1.CIDRsList{},
				[]client.Object{
					newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("cidr-with-secret-ref").withNamespace("secret-namespace").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret"}).build(),
					newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("cidr-with-secret-ref-in-same-namespace").withNamespace("secret-namespace").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: "secret-namespace"}).build(),
				},
				"secret-namespace",
				"my-secret",
				[]client.ObjectKey{
					{Namespace: "secret-namespace", Name: "cidr-with-secret-ref"},
					{Namespace: "secret-namespace", Name: "cidr-with-secret-ref-in-same-namespace"},
				},
			)
		})
		t.Run("When cidrs are in the other namespaces than the secret", func(t *testing.T) {
			testCaseObjectRefToCIDRsMapper(
				t,
				&ipamv1alpha1.CIDRsList{},
				[]client.Object{
					newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("cidr-with-secret-ref").withNamespace("other-namespace").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret"}).build(),
					newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("cidr-with-secret-ref-in-other-namespace").withNamespace("other-namespace").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: "secret-namespace"}).build(),
				},
				"secret-namespace",
				"my-secret",
				[]client.ObjectKey{
					{Namespace: "other-namespace", Name: "cidr-with-secret-ref-in-other-namespace"},
				},
			)
		})
	})
	t.Run("when using cluster scope cidrs", func(t *testing.T) {
		t.Run("references have namespaces", func(t *testing.T) {
			testCaseObjectRefToCIDRsMapper(
				t,
				&ipamv1alpha1.CIDRsList{},
				[]client.Object{
					newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("one-cidr-with-secret-ref").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: "secret-namespace"}).build(),
					newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("other-cidr-with-secret-ref").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: "secret-namespace"}).build(),
				},
				"secret-namespace",
				"my-secret",
				[]client.ObjectKey{
					{Name: "one-cidr-with-secret-ref"},
					{Name: "other-cidr-with-secret-ref"},
				},
			)
		})
		t.Run("references have no namespaces", func(t *testing.T) {
			testCaseObjectRefToCIDRsMapper(
				t,
				&ipamv1alpha1.CIDRsList{},
				[]client.Object{
					newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("one-cidr-with-secret-ref").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret"}).build(),
					newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("other-cidr-with-secret-ref").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret"}).build(),
				},
				"secret-namespace",
				"my-secret",
				[]client.ObjectKey{},
			)
		})
	})
}

func testCaseObjectRefToCIDRsMapper(t *testing.T, cidrsList ipamv1alpha1.CIDRsGetterList, objects []client.Object, secretNamespace, secretName string, expectedRequestKeys []client.ObjectKey) {
	t.Helper()
	scheme, err := Scheme("")
	require.NoError(t, err)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		objects...,
	).Build()

	CIDRsSecretMapper := newObjectRefToCIDRsFuncMap(k8sClient, cidrsList, secretSource)

	expectedRequests := make([]reconcile.Request, len(expectedRequestKeys))
	for i, key := range expectedRequestKeys {
		expectedRequests[i] = reconcile.Request{NamespacedName: key}
	}

	assert.ElementsMatch(
		t,
		CIDRsSecretMapper(context.Background(), &v1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: secretNamespace, Name: secretName}}),
		expectedRequests,
	)
}

func toJsonReader(t *testing.T, data any) io.Reader {
	t.Helper()
	b, err := json.Marshal(data)
	require.NoError(t, err)
	return bytes.NewReader(b)
}

func toYamlReader(t *testing.T, data any) io.Reader {
	t.Helper()
	b, err := yaml.Marshal(data)
	require.NoError(t, err)
	return bytes.NewReader(b)
}
