package controllers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

// celFailureText is what the UpToDate condition says when a CEL expression fails on a response.
const celFailureText = "failed to evaluate CEL expression: it failed on the response (the details are in the controller log)"

// TestCELEvalErrorDoesNotShowItsCause verifies that the text of an expression failing on a response
// is not the text of cel-go's error: that can quote the response (a key it didn't find, a value it
// couldn't convert), and the error text goes into the condition, readable by whoever can read the
// object. The details stay reachable for the log.
func TestCELEvalErrorDoesNotShowItsCause(t *testing.T) {
	const marker = "response-value-123"
	body := func() *strings.Reader { return strings.NewReader(`{"name": "` + marker + `", "n": "` + marker + `"}`) }

	t.Run("the message is fixed, the cause is kept", func(t *testing.T) {
		for name, cel := range map[string]string{
			"a missing key":       `[data.missing_key]`,
			"a failed conversion": `[string(int(data.n))]`,
		} {
			_, err := applyProcessor(body(), ipamv1alpha1.Processing{CEL: cel})
			require.Error(t, err, name)
			assert.Equal(t, celFailureText, err.Error(), name)
			assert.NotContains(t, err.Error(), marker, name)

			var evalErr *celEvalError
			require.True(t, errors.As(err, &evalErr), "%s: the error is a celEvalError", name)
			assert.NotEmpty(t, evalErr.cause.Error(), "%s: the details are kept for the log", name)
		}
	})

	t.Run("a cost limit says so", func(t *testing.T) {
		_, err := applyProcessorWithCostLimit(body(), ipamv1alpha1.Processing{CEL: `[data.name, data.n].map(s, s.size())`}, 1)
		require.Error(t, err)
		assert.Equal(t, "failed to evaluate CEL expression: cost limit exceeded", err.Error())
	})

	t.Run("a compile error is shown as it is: it holds nothing of the response", func(t *testing.T) {
		_, err := applyProcessor(body(), ipamv1alpha1.Processing{CEL: `data.(`})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to compile CEL expression")
		var evalErr *celEvalError
		assert.False(t, errors.As(err, &evalErr))
	})
}

// TestCIDRsCELFailureIsNotShownInTheCondition verifies the same through Reconcile: the condition
// says the expression failed, the previous list stays, and the details are in the controller log.
func TestCIDRsCELFailureIsNotShownInTheCondition(t *testing.T) {
	const marker = "response-value-123"
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name": "` + marker + `"}`))
	}))
	defer server.Close()

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: metav1.ObjectMeta{Name: "my-net", Namespace: "team-a"},
		Spec: ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{Location: ipamv1alpha1.CIDRsLocation{
			URI:        server.URL,
			Processing: ipamv1alpha1.Processing{CEL: `[data.missing_key]`},
		}}},
		Status: ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.0.2.0/24"}},
	}
	scheme, err := Scheme()
	require.NoError(t, err)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cidrs).WithStatusSubresource(cidrs).Build()
	r := &CIDRReconciler{
		Client:        c,
		CIDRs:         &ipamv1alpha1.CIDRs{},
		CIDRsList:     &ipamv1alpha1.CIDRsList{},
		SourceOptions: CIDRSourceOptions{AllowPrivateDestinations: true}, // the test server is on 127.0.0.1
	}
	logs := captureLogs(t)

	_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
	require.NoError(t, err)

	got := &ipamv1alpha1.CIDRs{}
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(cidrs), got))
	assert.Equal(t, ipamv1alpha1.CIDRsStateUpdateFailed, got.Status.State)
	assert.Equal(t, []string{"192.0.2.0/24"}, got.Status.CIDRs, "the last list stays")
	require.Len(t, got.Status.Conditions, 1)
	assert.Contains(t, got.Status.Conditions[0].Message, celFailureText)
	assert.NotContains(t, got.Status.Conditions[0].Message, "missing_key", "no text of cel-go's error")

	assert.Contains(t, logs.String(), "the CEL expression failed on the response", "the controller log has the failure")
	assert.Contains(t, logs.String(), "missing_key", "and the details of cel-go's error")
}
