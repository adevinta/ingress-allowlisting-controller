package writers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
)

var istioL4Scheme = func() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = gatewayApiv1.Install(s)
	_ = istiosecurityv1.AddToScheme(s)
	return s
}()

func testL4Gateway(name, namespace string) *gatewayApiv1.Gateway {
	return &gatewayApiv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
}

func TestIstioL4Writer_Apply_CreatesAP(t *testing.T) {
	gw := testL4Gateway("my-gateway", "mynamespace")
	k8sClient := fake.NewClientBuilder().WithScheme(istioL4Scheme).WithObjects(gw).Build()
	w := NewIstioL4Writer(k8sClient)

	err := w.Apply(context.Background(), istioL4Scheme, gw, []string{"10.0.0.0/8"})
	assert.NoError(t, err)

	ap := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-gateway", Namespace: "mynamespace"}, ap)
	assert.NoError(t, err)
	assert.Equal(t, "my-gateway", ap.Spec.TargetRefs[0].Name)
}

func TestIstioL4Writer_Apply_SetsOwnerReference(t *testing.T) {
	gw := testL4Gateway("my-gateway", "mynamespace")
	k8sClient := fake.NewClientBuilder().WithScheme(istioL4Scheme).WithObjects(gw).Build()
	w := NewIstioL4Writer(k8sClient)

	err := w.Apply(context.Background(), istioL4Scheme, gw, []string{"10.0.0.0/8"})
	assert.NoError(t, err)

	ap := &istiosecurityv1.AuthorizationPolicy{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-gateway", Namespace: "mynamespace"}, ap)
	assert.NoError(t, err)
	assert.Len(t, ap.OwnerReferences, 1)
	assert.Equal(t, "my-gateway", ap.OwnerReferences[0].Name)
	assert.True(t, *ap.OwnerReferences[0].Controller)
}

func TestIstioL4Writer_Apply_UpdatesExistingAP(t *testing.T) {
	gw := testL4Gateway("my-gateway", "mynamespace")
	k8sClient := fake.NewClientBuilder().WithScheme(istioL4Scheme).WithObjects(gw).Build()
	w := NewIstioL4Writer(k8sClient)

	assert.NoError(t, w.Apply(context.Background(), istioL4Scheme, gw, []string{"10.0.0.0/8"}))
	assert.NoError(t, w.Apply(context.Background(), istioL4Scheme, gw, []string{"192.168.0.0/16"}))

	ap := &istiosecurityv1.AuthorizationPolicy{}
	assert.NoError(t, k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-gateway", Namespace: "mynamespace"}, ap))
	assert.Equal(t, []string{"192.168.0.0/16"}, ap.Spec.Rules[0].From[0].Source.RemoteIpBlocks)
}

func TestIstioL4Writer_Delete_RemovesAP(t *testing.T) {
	gw := testL4Gateway("my-gateway", "mynamespace")
	k8sClient := fake.NewClientBuilder().WithScheme(istioL4Scheme).WithObjects(gw).Build()
	w := NewIstioL4Writer(k8sClient)

	assert.NoError(t, w.Apply(context.Background(), istioL4Scheme, gw, []string{"10.0.0.0/8"}))
	assert.NoError(t, w.Delete(context.Background(), gw))

	ap := &istiosecurityv1.AuthorizationPolicy{}
	err := k8sClient.Get(context.Background(), client.ObjectKey{Name: "my-gateway", Namespace: "mynamespace"}, ap)
	assert.True(t, client.IgnoreNotFound(err) == nil && err != nil, "AP should be gone")
}

func TestIstioL4Writer_Delete_ToleratesNotFound(t *testing.T) {
	gw := testL4Gateway("my-gateway", "mynamespace")
	k8sClient := fake.NewClientBuilder().WithScheme(istioL4Scheme).WithObjects(gw).Build()
	w := NewIstioL4Writer(k8sClient)

	assert.NoError(t, w.Delete(context.Background(), gw))
}
