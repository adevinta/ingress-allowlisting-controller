package resolvers_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// failOnEvents fails the test on any Event read or write through the client: Events must only
// go through the recorder, so the cached client never starts a cluster-wide Event informer.
func failOnEvents(t *testing.T) interceptor.Funcs {
	isEvent := func(obj client.Object) bool { _, ok := obj.(*corev1.Event); return ok }
	return interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if isEvent(obj) {
				t.Errorf("resolver read Event %s through the client", key)
			}
			return c.Get(ctx, key, obj, opts...)
		},
		List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*corev1.EventList); ok {
				t.Errorf("resolver listed Events through the client")
			}
			return c.List(ctx, list, opts...)
		},
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if isEvent(obj) {
				t.Errorf("resolver created an Event through the client")
			}
			return c.Create(ctx, obj, opts...)
		},
	}
}

// TestGetCidrsFromObjectRecordsEventForMissingGroup verifies that each missing CIDRs/ClusterCIDRs
// group is reported with one Warning Event through the recorder, that existing groups produce
// none, and that the client is never used for Events.
func TestGetCidrsFromObjectRecordsEventForMissingGroup(t *testing.T) {
	existing := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "localnet", Namespace: "mynamespace"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"10.0.0.0/8"}},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(existing).
		WithInterceptorFuncs(failOnEvents(t)).Build()
	recorder := events.NewFakeRecorder(10)
	cidrResolver := resolvers.CidrResolver{Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix, Recorder: recorder}
	ingress := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{Name: "myingress", Namespace: "mynamespace", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group":         "localnet,missing",
			"ipam.adevinta.com/cluster-allowlist-group": "missing-cluster",
		}},
	}

	ips, err := cidrResolver.GetCidrsFromObject(context.Background(), ingress)

	require.NoError(t, err)
	assert.Contains(t, ips, "10.0.0.0/8", "the existing group still applies")
	close(recorder.Events)
	var recorded []string
	for e := range recorder.Events {
		recorded = append(recorded, e)
	}
	assert.Equal(t, []string{
		`Warning AllowlistGroupNotFound Couldn't update the allowlist because NamespacedCIDRs "missing" was not found`,
		`Warning AllowlistGroupNotFound Couldn't update the allowlist because ClusterCIDRs "missing-cluster" was not found`,
	}, recorded)
}

// TestRepeatedMissingGroupIsOneEvent verifies, with client-go's real recorder, that resolving the
// same object again and again (every update gives it a new resourceVersion) produces one Event
// with a series, not one Event per reconcile: the recorder only aggregates identical Events, and
// the object reference is part of that identity.
func TestRepeatedMissingGroupIsOneEvent(t *testing.T) {
	clientset := kubefake.NewClientset()
	broadcaster := events.NewBroadcaster(&events.EventSinkImpl{Interface: clientset.EventsV1()})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	broadcaster.StartRecordingToSink(ctx.Done())
	t.Cleanup(broadcaster.Shutdown)

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithInterceptorFuncs(failOnEvents(t)).Build()
	cidrResolver := resolvers.CidrResolver{
		Client: k8sClient, AnnotationPrefix: resolvers.DefaultPrefix,
		Recorder: broadcaster.NewRecorder(extendedScheme, "ingress-allowlisting-controller"),
	}
	policy := &netv1.NetworkPolicy{
		ObjectMeta: v1.ObjectMeta{Name: "mypolicy", Namespace: "mynamespace", UID: "policy-uid", Annotations: map[string]string{
			"ipam.adevinta.com/allowlist-group": "missing",
		}},
	}
	for i := 1; i <= 20; i++ {
		policy.ResourceVersion = strconv.Itoa(i)
		_, err := cidrResolver.GetCidrsFromObject(context.Background(), policy)
		require.NoError(t, err)
	}

	var recorded []eventsv1.Event
	assert.Eventually(t, func() bool {
		list, err := clientset.EventsV1().Events("mynamespace").List(context.Background(), v1.ListOptions{})
		require.NoError(t, err)
		recorded = list.Items
		return len(recorded) > 0 && recorded[0].Series != nil
	}, 5*time.Second, 20*time.Millisecond, "the repeats must become a series of the first Event")
	assert.Equal(t, 1, len(recorded), "one Event for the object, not one per reconcile")
	require.NotEmpty(t, recorded)
	assert.Equal(t, "NetworkPolicy", recorded[0].Regarding.Kind)
	assert.Equal(t, "mypolicy", recorded[0].Regarding.Name)
	assert.Equal(t, "policy-uid", string(recorded[0].Regarding.UID))
}
