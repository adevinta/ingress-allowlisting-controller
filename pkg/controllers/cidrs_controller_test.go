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
	"time"

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

func TestCIDRsReconciler(t *testing.T) {
	ctx := context.TODO()
	scheme, err := Scheme()
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
			CEL: "data.ips",
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
			CEL: "data.ips",
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
			CEL: "data.ips",
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
			CEL: `data.filter(d, has(d.key) && d.key == "value").map(d, d.ip)`,
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
			CEL: `data.prefixes.filter(p, p.service == "my-service" && has(p.ip_prefix)).map(p, p.ip_prefix)`,
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
			CEL: `data.prefixes.filter(p, p.service == "my-service" && has(p.ip_prefix)).map(p, p.ip_prefix)`,
		},
	)
	require.Error(t, err)
	// The error ends up in the object's condition, readable by its users: the type, not the
	// fetched value.
	assert.NotContains(t, err.Error(), "42")
	assert.Contains(t, err.Error(), "unexpected value type")
}

func TestApplyProcessorComplexFiltering(t *testing.T) {
	// Test case for issue #15: Complex filtering with AND/OR logic that JSONPath couldn't handle
	// JSONPath: "{.prefixes[?(@.service == 'EC2' && (@.region == 'eu-central-1' || @.region == 'GLOBAL'))].ip_prefix}"
	// This was failing with JSONPath due to unsupported && operator
	t.Run("Complex filtering with AND/OR logic", func(t *testing.T) {
		testComplexFiltering(t, toJsonReader)
	})
	t.Run("Complex filtering with AND/OR logic (YAML)", func(t *testing.T) {
		testComplexFiltering(t, toYamlReader)
	})
}

func testComplexFiltering(t *testing.T, serialize func(*testing.T, any) io.Reader) {
	t.Helper()

	// Test data similar to AWS IP ranges structure
	data := map[string]interface{}{
		"prefixes": []map[string]interface{}{
			{
				"service":   "EC2",
				"region":    "us-east-1",
				"ip_prefix": "10.0.0.1/32",
			},
			{
				"service":   "EC2",
				"region":    "eu-central-1",
				"ip_prefix": "10.0.0.2/32",
			},
			{
				"service":   "EC2",
				"region":    "GLOBAL",
				"ip_prefix": "10.0.0.3/32",
			},
			{
				"service":   "S3",
				"region":    "eu-central-1",
				"ip_prefix": "10.0.0.4/32",
			},
			{
				"service":   "EC2",
				"region":    "ap-southeast-1",
				"ip_prefix": "10.0.0.5/32",
			},
		},
	}

	// CEL expression equivalent to the JSONPath that was failing:
	// Filter prefixes where service == "EC2" AND (region == "eu-central-1" OR region == "GLOBAL")
	cidrs, err := applyProcessor(
		serialize(t, data),
		ipamv1alpha1.Processing{
			CEL: `data.prefixes.filter(p, p.service == "EC2" && (p.region == "eu-central-1" || p.region == "GLOBAL") && has(p.ip_prefix)).map(p, p.ip_prefix)`,
		},
	)
	require.NoError(t, err, "CEL expression should handle complex AND/OR logic without errors")
	assert.Equal(t, []string{"10.0.0.2/32", "10.0.0.3/32"}, cidrs, "Should only return EC2 prefixes from eu-central-1 or GLOBAL regions")
}

func TestApplyProcessorJSONPathBackwardCompatibility(t *testing.T) {
	// Test JSONPath backward compatibility - ensure existing JSONPath expressions still work
	t.Run("JSONPath backward compatibility", func(t *testing.T) {
		testJSONPathBackwardCompatibility(t, toJsonReader)
	})
	t.Run("JSONPath backward compatibility (YAML)", func(t *testing.T) {
		testJSONPathBackwardCompatibility(t, toYamlReader)
	})
}

func testJSONPathBackwardCompatibility(t *testing.T, serialize func(*testing.T, any) io.Reader) {
	t.Helper()

	// Test simple JSONPath expression
	cidrs, err := applyProcessor(
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

	// Test JSONPath with array access
	cidrs, err = applyProcessor(
		serialize(
			t,
			map[string]interface{}{
				"prefixes": []map[string]interface{}{
					{
						"service":   "EC2",
						"ip_prefix": "10.0.0.1/32",
					},
					{
						"service":   "S3",
						"ip_prefix": "10.0.0.2/32",
					},
				},
			},
		),
		ipamv1alpha1.Processing{
			JSONPath: "{$.prefixes[*].ip_prefix}",
		})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.1/32", "10.0.0.2/32"}, cidrs)

	// Test that CEL takes precedence when both are specified
	cidrs, err = applyProcessor(
		serialize(
			t,
			map[string][]string{
				"ips":   {"127.0.0.1/32"},
				"other": {"10.0.0.0/16"},
			},
		),
		ipamv1alpha1.Processing{
			CEL:      "data.other",
			JSONPath: "{.ips}",
		})
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.0/16"}, cidrs, "CEL should take precedence over JSONPath")
}

func TestCIDRsReconcileFromHTTP(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme()
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		assert.Equal(t, "Bearer my-token", r.Header.Get("Authentication"))
		_, _ = w.Write([]byte(`["200.1.1.1/24", "10.0.0.1/24", "1.1.1.1", "10.0.0.1/24"]`))
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
		SourceOptions:      CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:              &ipamv1alpha1.CIDRs{},
		CIDRsList:          &ipamv1alpha1.CIDRsList{},
		Client:             fakeClient,
		HTTPHeadersEnabled: true,
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
	scheme, err := Scheme()
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
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
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
	scheme, err := Scheme()
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
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
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
	scheme, err := Scheme()
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
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"1.1.1.1/32", "10.0.0.1/24", "200.1.1.1/24"}, cidrs.GetStatus().CIDRs)
}

func TestCIDRsReconcileFromCSV(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme()
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("10.0.0.0/8,192.168.0.0/16,,8.8.8.0/24\n8.8.8.8/24\n#1.1.1.1/24"))
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
				Processing: ipamv1alpha1.Processing{
					Format: "CSV",
				},
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16", "8.8.8.0/24", "8.8.8.8/24"}, cidrs.GetStatus().CIDRs)
}

func TestCIDRsReconcileFromLineSeparatedValues(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme()
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("200.1.1.1/24\r\n10.0.0.1/24\n\n#8.8.8.8/32\n 1.1.1.1/32 \n\n10.0.0.1/24\r\n\n"))
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
				Processing: ipamv1alpha1.Processing{
					Format: "CSV",
				},
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"1.1.1.1/32", "10.0.0.1/24", "200.1.1.1/24"}, cidrs.GetStatus().CIDRs)
}

func TestCIDRsReconcileFromCombinedSeparatedValues(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme()
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("200.1.1.1/24\r\n10.1.0.0/24,10.2.0.0/24\n\n#8.8.8.8/32\n1.1.1.1/32 \n\n10.3.0.0/24,10.2.0.0/24\r\n\n10.4.0.0/24"))
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
				Processing: ipamv1alpha1.Processing{
					Format: "CSV",
				},
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"1.1.1.1/32", "10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24", "10.4.0.0/24", "200.1.1.1/24"}, cidrs.GetStatus().CIDRs)
}

func TestCIDRsReconcileFromCSVWithBOM(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme()
	require.NoError(t, err)

	// Akamai-style CSV: UTF-8 BOM at the start, trailing spaces, CRLF line endings.
	// The BOM causes the first CIDR to be silently dropped without BOM stripping.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("\xef\xbb\xbf2.16.0.0/13  \r\n23.0.0.0/12  \r\n23.192.0.0/11  \r\n"))
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
				Processing: ipamv1alpha1.Processing{
					Format: "CSV",
				},
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"2.16.0.0/13", "23.0.0.0/12", "23.192.0.0/11"}, cidrs.GetStatus().CIDRs)
}

func TestCIDRsReconcileFromCombinedComplexSeparatedValues(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme()
	require.NoError(t, err)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Line,Network,Description\r\n1,10.0.0.0/8,Private RFC1918 Range\r\n2,192.168.0.0/16,Private RFC1918 Range\r\n3,8.8.8.0/24,Google DNS"))
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
				Processing: ipamv1alpha1.Processing{
					Format: "CSV",
				},
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16", "8.8.8.0/24"}, cidrs.GetStatus().CIDRs)
}

func TestCIDRsReconcileFromGitHubInvalidEncodingHTTPResponse(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme()
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
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: defaultRetryInterval}, result, "a failed fetch is retried")

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Nil(t, cidrs.GetStatus().CIDRs)
	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, cidrs.GetStatus().State)
	require.Len(t, cidrs.GetStatus().Conditions, 1)
	assert.Equal(t, ipamv1alpha1.CIDRsStatusConditionTypeUpToDate, cidrs.GetStatus().Conditions[0].Type)
	assert.Equal(t, v1.ConditionFalse, cidrs.GetStatus().Conditions[0].Status)
	assert.Contains(t, cidrs.GetStatus().Conditions[0].Message, "unexpected encoding")
	assert.NotContains(t, cidrs.GetStatus().Conditions[0].Message, "what-is-this", "the condition must not echo fetched content")
}

func TestCIDRsReconcileFromAWSRules(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme()
	require.NoError(t, err)

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: "https://ip-ranges.amazonaws.com/ip-ranges.json",
				Processing: ipamv1alpha1.Processing{
					CEL: `data.prefixes.filter(p, p.service == "EC2").map(p, p.ip_prefix)`,
				},
			},
		}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
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
	scheme, err := Scheme()
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
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		Client:        fakeClient,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, reconcile.Result{RequeueAfter: defaultRetryInterval}, result, "a failed fetch is retried")

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))

	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, cidrs.Status.State)

	assert.Equal(t, []string{"127.0.0.1/32"}, cidrs.GetStatus().CIDRs)

	require.Len(t, cidrs.GetStatus().Conditions, 1)

	assert.Equal(t, ipamv1alpha1.CIDRsStatusConditionTypeUpToDate, cidrs.GetStatus().Conditions[0].Type)
	assert.Equal(t, v1.ConditionFalse, cidrs.GetStatus().Conditions[0].Status)
	assert.Contains(t, cidrs.GetStatus().Conditions[0].Message, "Failed to get CIDRs from http source")
	assert.Contains(t, cidrs.GetStatus().Conditions[0].Message, "403")
}

func TestCIDRsReconcileFromHTTPDoesNotReadSecretsWhenHeadersDisabled(t *testing.T) {
	ctx := context.TODO()
	testNamespaceName := "mynamespace"
	scheme, err := Scheme()
	require.NoError(t, err)

	headersReceived := http.Header{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersReceived = r.Header
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`["10.0.0.0/8"]`))
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: testNamespaceName},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{
				URI: server.URL,
				HeadersFrom: []ipamv1alpha1.HeadersFrom{
					{SecretRef: ipamv1alpha1.ObjectRef{Name: "my-secret"}},
				},
			},
		}},
	}
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: testNamespaceName},
		Data:       map[string][]byte{"Authorization": []byte("Bearer secret-token")},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs, secret).WithStatusSubresource(cidrs).Build()
	reconciler := &CIDRReconciler{
		SourceOptions:      CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		CIDRs:              &ipamv1alpha1.CIDRs{},
		CIDRsList:          &ipamv1alpha1.CIDRsList{},
		Client:             fakeClient,
		HTTPHeadersEnabled: false,
	}

	result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)
	require.Equal(t, result, reconcile.Result{})

	assert.Empty(t, headersReceived.Get("Authorization"), "secret headers must not be sent when HTTPHeadersEnabled=false")

	require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(cidrs), cidrs))
	assert.Equal(t, []string{"10.0.0.0/8"}, cidrs.GetStatus().CIDRs)
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
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // tests fetch from 127.0.0.1
		Client:        fakeClient,
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
	// A ClusterCIDRs reads only from --cluster-cidrs-headers-namespace, here mynamespace.
	t.Run("When the object is cluster-scoped", func(t *testing.T) {
		clusterReconciler := &CIDRReconciler{
			SourceOptions: CIDRSourceOptions{ClusterHeadersNamespace: testNamespaceName},
			Client:        fakeClient,
		}
		want := http.Header{
			http.CanonicalHeaderKey("header-in-cm"):     []string{"value1"},
			http.CanonicalHeaderKey("header-in-both"):   []string{"value2", "value4"},
			http.CanonicalHeaderKey("header-in-secret"): []string{"value3"},
		}
		t.Run("When no namespace is provided in the objectRef, the allowed one is used", func(t *testing.T) {
			headers := http.Header{}
			assert.NoError(t, clusterReconciler.updateClientHeaders(ctx, "", headers, []ipamv1alpha1.HeadersFrom{
				{ConfigMapRef: ipamv1alpha1.ObjectRef{Name: "my-configmap"}},
				{SecretRef: ipamv1alpha1.ObjectRef{Name: "my-secret"}},
			}))
			assert.Equal(t, want, headers)
		})
		t.Run("When the allowed namespace is provided in the objectRef", func(t *testing.T) {
			headers := http.Header{}
			assert.NoError(t, clusterReconciler.updateClientHeaders(ctx, "", headers, []ipamv1alpha1.HeadersFrom{
				{ConfigMapRef: ipamv1alpha1.ObjectRef{Name: "my-configmap", Namespace: testNamespaceName}},
				{SecretRef: ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: testNamespaceName}},
			}))
			assert.Equal(t, want, headers)
		})
		t.Run("When another namespace is provided in the objectRef", func(t *testing.T) {
			headers := http.Header{}
			err := clusterReconciler.updateClientHeaders(ctx, "", headers, []ipamv1alpha1.HeadersFrom{
				{SecretRef: ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: "kube-system"}},
			})
			assert.ErrorContains(t, err, "may only read from namespace mynamespace (--cluster-cidrs-headers-namespace), not kube-system")
			assert.Equal(t, http.Header{}, headers)
		})
		t.Run("When no namespace is allowed", func(t *testing.T) {
			headers := http.Header{}
			err := reconciler.updateClientHeaders(ctx, "", headers, []ipamv1alpha1.HeadersFrom{
				{SecretRef: ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: testNamespaceName}},
			})
			assert.ErrorContains(t, err, "no --cluster-cidrs-headers-namespace is set")
			assert.Equal(t, http.Header{}, headers)
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
				"",
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
		t.Run("When the secret name does not match the reference", func(t *testing.T) {
			testCaseObjectRefToCIDRsMapper(
				t,
				&ipamv1alpha1.CIDRsList{},
				"",
				[]client.Object{
					newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("cidr-with-secret-ref").withNamespace("secret-namespace").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret"}).build(),
				},
				"secret-namespace",
				"unrelated-secret",
				[]client.ObjectKey{},
			)
		})
		// A CIDRs object only reads Secrets of its own namespace: a reference to another one fails
		// the fetch, so a change there must not trigger it either.
		t.Run("When cidrs are in the other namespaces than the secret", func(t *testing.T) {
			testCaseObjectRefToCIDRsMapper(
				t,
				&ipamv1alpha1.CIDRsList{},
				"",
				[]client.Object{
					newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("cidr-with-secret-ref").withNamespace("other-namespace").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret"}).build(),
					newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("cidr-with-secret-ref-in-other-namespace").withNamespace("other-namespace").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: "secret-namespace"}).build(),
				},
				"secret-namespace",
				"my-secret",
				[]client.ObjectKey{},
			)
		})
	})
	// A ClusterCIDRs reads only from --cluster-cidrs-headers-namespace (here secret-namespace); a
	// reference without a namespace means that one.
	t.Run("when using cluster scope cidrs", func(t *testing.T) {
		clusterObjects := []client.Object{
			newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("ref-with-namespace").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: "secret-namespace"}).build(),
			newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("ref-without-namespace").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret"}).build(),
			newCIDRBuilder(&ipamv1alpha1.CIDRs{}).withName("ref-to-kube-system").withSecretRef(ipamv1alpha1.ObjectRef{Name: "my-secret", Namespace: "kube-system"}).build(),
		}
		t.Run("a Secret in the allowed namespace", func(t *testing.T) {
			testCaseObjectRefToCIDRsMapper(t, &ipamv1alpha1.CIDRsList{}, "secret-namespace", clusterObjects,
				"secret-namespace", "my-secret",
				[]client.ObjectKey{{Name: "ref-with-namespace"}, {Name: "ref-without-namespace"}},
			)
		})
		t.Run("a Secret in another namespace", func(t *testing.T) {
			testCaseObjectRefToCIDRsMapper(t, &ipamv1alpha1.CIDRsList{}, "secret-namespace", clusterObjects,
				"kube-system", "my-secret",
				[]client.ObjectKey{},
			)
		})
		t.Run("no allowed namespace", func(t *testing.T) {
			testCaseObjectRefToCIDRsMapper(t, &ipamv1alpha1.CIDRsList{}, "", clusterObjects,
				"secret-namespace", "my-secret",
				[]client.ObjectKey{},
			)
		})
	})
	t.Run("when using a configmap reference", func(t *testing.T) {
		scheme, err := Scheme()
		require.NoError(t, err)
		cidrs := newCIDRBuilder(&ipamv1alpha1.CIDRs{}).
			withName("cidr-with-configmap-ref").
			withNamespace("configmap-namespace").
			withConfigMapRef(ipamv1alpha1.ObjectRef{Name: "my-configmap"}).
			build()
		k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).Build()
		mapper := newObjectRefToCIDRsFuncMap(k8sClient, &ipamv1alpha1.CIDRsList{}, configMapSource, (&CIDRReconciler{}).resolveNamespace)

		requests := mapper(context.Background(), &v1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
			Namespace: "configmap-namespace",
			Name:      "my-configmap",
		}})

		assert.Equal(t, []reconcile.Request{{NamespacedName: client.ObjectKeyFromObject(cidrs)}}, requests)
	})
}

// testCaseObjectRefToCIDRsMapper maps a change of the Secret secretNamespace/secretName, with
// clusterHeadersNamespace as --cluster-cidrs-headers-namespace.
func testCaseObjectRefToCIDRsMapper(t *testing.T, cidrsList ipamv1alpha1.CIDRsGetterList, clusterHeadersNamespace string, objects []client.Object, secretNamespace, secretName string, expectedRequestKeys []client.ObjectKey) {
	t.Helper()
	scheme, err := Scheme()
	require.NoError(t, err)
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		objects...,
	).Build()

	reconciler := &CIDRReconciler{SourceOptions: CIDRSourceOptions{ClusterHeadersNamespace: clusterHeadersNamespace}}
	CIDRsSecretMapper := newObjectRefToCIDRsFuncMap(k8sClient, cidrsList, secretSource, reconciler.resolveNamespace)

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

// TestCIDRsStateFollowsTheLastReconcile verifies that status.state says how the last reconcile went,
// like the UpToDate condition: an object whose fetch failed once must not stay UpdateFailed after
// the source works again, and an object that never failed is Ready too.
func TestCIDRsStateFollowsTheLastReconcile(t *testing.T) {
	ctx := context.TODO()
	scheme, err := Scheme()
	require.NoError(t, err)

	failing := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("- 10.1.0.0/16\n"))
	}))
	t.Cleanup(server.Close)

	remote := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "remote", Namespace: "mynamespace"},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			Location: ipamv1alpha1.CIDRsLocation{URI: server.URL},
		}},
	}
	inline := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "inline", Namespace: "mynamespace"},
		Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{"10.2.0.0/16"}}},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(remote, inline).WithStatusSubresource(remote, inline).Build()
	reconciler := &CIDRReconciler{
		CIDRs: &ipamv1alpha1.CIDRs{}, CIDRsList: &ipamv1alpha1.CIDRsList{}, Client: fakeClient,
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // the feed is on 127.0.0.1
	}
	reconcileAndGet := func(t *testing.T, obj *ipamv1alpha1.CIDRs) *ipamv1alpha1.CIDRs {
		t.Helper()
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
		require.NoError(t, err)
		got := &ipamv1alpha1.CIDRs{}
		require.NoError(t, fakeClient.Get(ctx, client.ObjectKeyFromObject(obj), got))
		require.Len(t, got.Status.Conditions, 1)
		return got
	}

	got := reconcileAndGet(t, remote)
	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, got.Status.State, "the fetch failed")
	assert.Equal(t, v1.ConditionFalse, got.Status.Conditions[0].Status)

	failing = false
	got = reconcileAndGet(t, remote)
	assert.Equal(t, []string{"10.1.0.0/16"}, got.Status.CIDRs)
	assert.Equal(t, v1.ConditionTrue, got.Status.Conditions[0].Status)
	assert.Equal(t, ipamv1alpha1.CIDRsStateReady, got.Status.State, "the source works again: no longer UpdateFailed")

	got = reconcileAndGet(t, inline)
	assert.Equal(t, ipamv1alpha1.CIDRsStateReady, got.Status.State, "an object that never failed is Ready")
}

// TestRequeueAfterMinimum verifies that spec.requeueAfter below one minute is raised to it, on a
// successful fetch and when retrying a failed one, and that the condition says so: a tiny value
// would otherwise make the single worker refetch that source nonstop.
func TestRequeueAfterMinimum(t *testing.T) {
	ctx := context.TODO()
	scheme, err := Scheme()
	require.NoError(t, err)
	failing := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("- 10.1.0.0/16\n"))
	}))
	t.Cleanup(server.Close)

	reconcileWith := func(t *testing.T, requeueAfter *metav1.Duration) (reconcile.Result, *ipamv1alpha1.CIDRs) {
		t.Helper()
		obj := &ipamv1alpha1.CIDRs{
			ObjectMeta: metav1.ObjectMeta{Name: "feed", Namespace: "mynamespace"},
			Spec: ipamv1alpha1.CIDRsSpec{RequeueAfter: requeueAfter, CIDRsSource: ipamv1alpha1.CIDRsSource{
				Location: ipamv1alpha1.CIDRsLocation{URI: server.URL},
			}},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(obj).WithStatusSubresource(obj).Build()
		reconciler := &CIDRReconciler{
			CIDRs: &ipamv1alpha1.CIDRs{}, CIDRsList: &ipamv1alpha1.CIDRsList{}, Client: c,
			SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // the feed is on 127.0.0.1
		}
		result, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
		require.NoError(t, err)
		got := &ipamv1alpha1.CIDRs{}
		require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(obj), got))
		require.Len(t, got.Status.Conditions, 1)
		return result, got
	}

	result, got := reconcileWith(t, &metav1.Duration{Duration: time.Millisecond})
	assert.Equal(t, time.Minute, result.RequeueAfter, "1ms is raised to the minimum")
	assert.Equal(t, "All CIDRs are up to date (requeueAfter 1ms is below the minimum, refetched every 1m0s)", got.Status.Conditions[0].Message)

	result, got = reconcileWith(t, &metav1.Duration{Duration: 15 * time.Minute})
	assert.Equal(t, 15*time.Minute, result.RequeueAfter)
	assert.Equal(t, "All CIDRs are up to date", got.Status.Conditions[0].Message)

	result, _ = reconcileWith(t, nil)
	assert.Zero(t, result.RequeueAfter, "unset: no periodic refetch")

	failing = true
	result, _ = reconcileWith(t, &metav1.Duration{Duration: time.Millisecond})
	assert.Equal(t, time.Minute, result.RequeueAfter, "a failed fetch is retried at the minimum too, not every millisecond")
}

// TestCIDRsReconcileFromGitHubResponsesWithoutContent verifies that api.github.com responses other
// than the Contents API are processed as they are. GitHub sends x-github-media-type: github.v3 on
// every response, so /meta (GitHub's own IP ranges, an object without "content") and list
// endpoints (arrays) used to fail: the body was consumed while looking for "content".
func TestCIDRsReconcileFromGitHubResponsesWithoutContent(t *testing.T) {
	cases := []struct {
		name, body, cel string
		want            []string
	}{
		{
			name: "object without content, like /meta",
			body: `{"verifiable_password_authentication":false,"hooks":["192.30.252.0/22","185.199.108.0/22"],"actions":["4.148.0.0/16"]}`,
			cel:  `data.hooks`,
			want: []string{"185.199.108.0/22", "192.30.252.0/22"},
		},
		{
			name: "array",
			body: `[{"cidr":"10.1.0.0/16"},{"cidr":"10.2.0.0/16"}]`,
			cel:  `data.map(e, e.cidr)`,
			want: []string{"10.1.0.0/16", "10.2.0.0/16"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("x-github-media-type", "github.v3; format=json")
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(server.Close)

			cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{CEL: tc.cel}, CIDRSourceOptions{})

			require.Len(t, cidrs.Status.Conditions, 1)
			assert.Equal(t, "All CIDRs are up to date", cidrs.Status.Conditions[0].Message)
			assert.Equal(t, tc.want, cidrs.Status.CIDRs)
		})
	}
}

// TestGitHubResponseKeepsTheSizeCap verifies that a GitHub response, now read in one piece to look
// for "content", is still refused when it exceeds the response size cap.
func TestGitHubResponseKeepsTheSizeCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-github-media-type", "github.v3; format=json")
		_, _ = w.Write([]byte(`{"hooks":["192.30.252.0/22","185.199.108.0/22","140.82.112.0/20"]}`))
	}))
	t.Cleanup(server.Close)

	cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{CEL: `data.hooks`}, CIDRSourceOptions{MaxResponseBytes: 20})

	requireFailedKeepingLastGood(t, cidrs, "response body too large")
}

// TestCIDRsReconcileFromCSVWithBareIPs verifies that a CSV source is handled like a YAML one: bare
// IPs become host routes (/32, /128) and other values are counted as ignored. Before, CSV kept only
// values that parsed as CIDRs, so a feed of bare IPs ended up empty, and nothing was counted.
func TestCIDRsReconcileFromCSVWithBareIPs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("10.0.0.0/8,192.0.2.7\n2001:db8::1, not-an-ip \n#1.1.1.1"))
	}))
	t.Cleanup(server.Close)

	cidrs := reconcileFromServer(t, server.URL, ipamv1alpha1.Processing{Format: ipamv1alpha1.CSV}, CIDRSourceOptions{})

	assert.Equal(t, []string{"10.0.0.0/8", "192.0.2.7/32", "2001:db8::1/128"}, cidrs.Status.CIDRs)
	require.Len(t, cidrs.Status.Conditions, 1)
	assert.Equal(t, "All CIDRs are up to date (1 invalid entries ignored)", cidrs.Status.Conditions[0].Message)
}

// TestInvalidInlineCIDRsAreReported verifies that invalid entries in spec.cidrs are left out of
// status.cidrs and named in the condition, so the object's author sees the typo. Before, they were
// copied into the status, the condition said everything was up to date, and only a log line of the
// controller, on every reconcile of every object using the group, mentioned them.
func TestInvalidInlineCIDRsAreReported(t *testing.T) {
	ctx := context.TODO()
	scheme, err := Scheme()
	require.NoError(t, err)
	obj := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "office", Namespace: "mynamespace"},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
			CIDRs: []string{"203.0.113.0/24", "198.51.100.7", "10.20.30", "192.0.2.0/33", "10.0.0.5/8"},
		}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(obj).WithStatusSubresource(obj).Build()
	reconciler := &CIDRReconciler{CIDRs: &ipamv1alpha1.CIDRs{}, CIDRsList: &ipamv1alpha1.CIDRsList{}, Client: c}

	_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(obj)})
	require.NoError(t, err)
	got := &ipamv1alpha1.CIDRs{}
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(obj), got))

	assert.Equal(t, []string{"10.0.0.5/8", "198.51.100.7/32", "203.0.113.0/24"}, got.Status.CIDRs, "valid entries kept as written, the bare IP as a host route")
	require.Len(t, got.Status.Conditions, 1)
	assert.Equal(t, `All CIDRs are up to date (invalid entries in spec.cidrs ignored: "10.20.30", "192.0.2.0/33")`, got.Status.Conditions[0].Message)
	assert.Equal(t, []string{"203.0.113.0/24", "198.51.100.7", "10.20.30", "192.0.2.0/33", "10.0.0.5/8"}, got.Spec.CIDRs, "the spec is unchanged")
}

// TestQuoteFirst verifies that the condition names at most a few invalid entries.
func TestQuoteFirst(t *testing.T) {
	assert.Equal(t, `"a"`, quoteFirst([]string{"a"}, 5))
	assert.Equal(t, `"a", "b", and 3 more`, quoteFirst([]string{"a", "b", "c", "d", "e"}, 2))
	assert.Equal(t, `"10.0.0 "`, quoteFirst([]string{"10.0.0 "}, 5), "quoted, so stray spaces are visible")
}

// TestHeaderValuesAreTrimmed verifies that header values from Secrets and ConfigMaps lose
// surrounding whitespace. A value created with kubectl --from-file usually ends in a newline, and
// Go refuses to send such a header ("invalid header field value"), so the whole fetch failed.
func TestHeaderValuesAreTrimmed(t *testing.T) {
	ctx := context.TODO()
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "api-key", Namespace: "mynamespace"},
		Data:       map[string][]byte{"X-Api-Key": []byte("s3cr3t\n")},
	}
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "extra", Namespace: "mynamespace"},
		Data:       map[string]string{"X-Client": "  ingress-allowlisting\r\n"},
	}
	reconciler := &CIDRReconciler{Client: fake.NewClientBuilder().WithObjects(secret, cm).Build()}
	headers := http.Header{}

	require.NoError(t, reconciler.updateClientHeaders(ctx, "mynamespace", headers, []ipamv1alpha1.HeadersFrom{
		{SecretRef: ipamv1alpha1.ObjectRef{Name: "api-key"}},
		{ConfigMapRef: ipamv1alpha1.ObjectRef{Name: "extra"}},
	}))

	assert.Equal(t, http.Header{"X-Api-Key": {"s3cr3t"}, "X-Client": {"ingress-allowlisting"}}, headers)
}
