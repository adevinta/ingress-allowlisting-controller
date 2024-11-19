package controllers_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	ipamv1alpha1_legacy "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/legacy/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

type testInformer struct {
	handlers []toolscache.ResourceEventHandler
}

var _ cache.Informer = &testInformer{}

func (i *testInformer) AddEventHandler(handler toolscache.ResourceEventHandler) (toolscache.ResourceEventHandlerRegistration, error) {
	i.handlers = append(i.handlers, handler)
	return nil, nil
}

func (i *testInformer) RemoveEventHandler(handler toolscache.ResourceEventHandlerRegistration) error {
	return nil
}

// AddEventHandlerWithResyncPeriod adds an event handler to the shared informer using the
// specified resync period.  Events to a single handler are delivered sequentially, but there is
// no coordination between different handlers.
func (i *testInformer) AddEventHandlerWithResyncPeriod(handler toolscache.ResourceEventHandler, resyncPeriod time.Duration) (toolscache.ResourceEventHandlerRegistration, error) {
	i.handlers = append(i.handlers, handler)
	return nil, nil
}

func (i *testInformer) IsStopped() bool {
	return false
}

// AddIndexers adds more indexers to this store.  If you call this after you already have data
// in the store, the results are undefined.
func (i *testInformer) AddIndexers(indexers toolscache.Indexers) error {
	return nil
}

// HasSynced return true if the informers underlying store has synced
func (i *testInformer) HasSynced() bool {
	return true
}

type testCache struct {
	m sync.Mutex
	client.Client
	scheme    *runtime.Scheme
	informers map[schema.GroupVersionKind]*testInformer
	synced    bool
}

var _ cache.Cache = &testCache{}

func (c *testCache) GetInformer(ctx context.Context, obj client.Object, opts ...cache.InformerGetOption) (cache.Informer, error) {
	groupVersionKinds, _, err := c.scheme.ObjectKinds(obj)
	if err == nil {
		for _, gvk := range groupVersionKinds {
			return c.GetInformerForKind(ctx, gvk)
		}
	}
	return nil, fmt.Errorf("GetInformer not implemented for object %T", obj)
}

func (c *testCache) GetInformerForKind(ctx context.Context, gvk schema.GroupVersionKind, opts ...cache.InformerGetOption) (cache.Informer, error) {
	c.m.Lock()
	defer c.m.Unlock()
	if c.informers == nil {
		c.informers = map[schema.GroupVersionKind]*testInformer{}
	}
	i, ok := c.informers[gvk]
	if !ok {
		i = &testInformer{}
		c.informers[gvk] = i
	}
	return i, nil
}

func (c *testCache) RemoveInformer(ctx context.Context, obj client.Object) error {
	// Not implemented
	return nil
}

func (c *testCache) Start(ctx context.Context) error {
	return nil
}

func (c *testCache) WaitForCacheSync(ctx context.Context) bool {
	c.synced = true
	return true
}

func (c *testCache) IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error {
	return errors.New("IndexField not implemented")
}

func TestLegacyWorks(t *testing.T) {
	extendedScheme, err := controllers.Scheme("legacy.ipam.com/v1alpha1")
	require.NoError(t, err)

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "brand-new-cidr", Namespace: "test"},
		Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}}},
	}
	legacycidrs := &ipamv1alpha1_legacy.CIDRs{
		CIDRs: ipamv1alpha1.CIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "legacy-cidr", Namespace: "test"},
			Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{"192.168.0.0/24", "172.16.0.0/24", "10.0.0.0/24"}}},
		},
	}

	clustercidrs := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "brand-new-cluster-cidr"},
		Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}}},
	}
	legacyclustercidrs := &ipamv1alpha1_legacy.ClusterCIDRs{
		ClusterCIDRs: ipamv1alpha1.ClusterCIDRs{
			ObjectMeta: v1.ObjectMeta{Name: "legacy-cluster-cidr"},
			Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{"192.168.0.0/24", "172.16.0.0/24", "10.0.0.0/24"}}},
		},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs, legacycidrs, clustercidrs, legacyclustercidrs).Build()

	readCidr := &ipamv1alpha1.CIDRs{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "brand-new-cidr", Namespace: "test"}, readCidr)
	assert.NoError(t, err)
	assert.ElementsMatch(t, readCidr.Spec.CIDRsSource.CIDRs, cidrs.Spec.CIDRsSource.CIDRs)
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "legacy-cidr", Namespace: "test"}, readCidr)
	assert.True(t, apierrors.IsNotFound(err))

	readClusterCidr := &ipamv1alpha1.ClusterCIDRs{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "brand-new-cluster-cidr"}, readClusterCidr)
	assert.NoError(t, err)
	assert.ElementsMatch(t, readClusterCidr.Spec.CIDRsSource.CIDRs, clustercidrs.Spec.CIDRsSource.CIDRs)
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "legacy-cluster-cidr"}, readClusterCidr)
	assert.True(t, apierrors.IsNotFound(err))

	readLegCidr := &ipamv1alpha1_legacy.CIDRs{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "brand-new-cidr", Namespace: "test"}, readLegCidr)
	assert.True(t, apierrors.IsNotFound(err))
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "legacy-cidr", Namespace: "test"}, readLegCidr)
	assert.NoError(t, err)
	assert.ElementsMatch(t, readLegCidr.Spec.CIDRsSource.CIDRs, legacycidrs.Spec.CIDRsSource.CIDRs)

	readLegClusterCidr := &ipamv1alpha1_legacy.ClusterCIDRs{}
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "brand-new-cluster-cidr"}, readLegClusterCidr)
	assert.True(t, apierrors.IsNotFound(err))
	err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "legacy-cluster-cidr"}, readLegClusterCidr)
	assert.NoError(t, err)
	assert.ElementsMatch(t, readLegClusterCidr.Spec.CIDRsSource.CIDRs, legacyclustercidrs.Spec.CIDRsSource.CIDRs)
}

func TestCIDRsControllerTriggersIngressReconciliation(t *testing.T) {
	extendedScheme, err := controllers.Scheme("legacy.ipam.com/v1alpha1")
	assert.NoError(t, err)

	currentNamespaceName := "namespace-" + uuid.New().String()[:8]

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "group-name", Namespace: currentNamespaceName},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	ing := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Name:      "ing1",
			Namespace: currentNamespaceName,
			Annotations: map[string]string{
				"ipam.example.com/allowlist-group": "group-name",
			},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs, ing).Build()

	k8sCache := &testCache{Client: k8sClient, scheme: extendedScheme}

	// Some dirty dependency injections to be able to fake the ingestion of a new CIDR
	mgr, err := manager.New(&rest.Config{}, manager.Options{
		Scheme: extendedScheme,
		MapperProvider: func(c *rest.Config, httpClient *http.Client) (meta.RESTMapper, error) {
			return meta.NewDefaultRESTMapper(extendedScheme.PrioritizedVersionsAllGroups()), nil
		},
		NewClient: func(config *rest.Config, options client.Options) (client.Client, error) {
			return k8sClient, nil
		},
		NewCache: func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
			return k8sCache, nil
		},
	})
	require.NoError(t, err)
	require.NoError(t, controllers.SetupControllersWithManager(mgr, false, "", t.Name(), "ipam.example.com"))

	go func() {
		require.NoError(t, mgr.Start(context.Background()))
	}()

	// we don't have a mean to know when the manager has actually started completely
	// Hence try to see if there has been any informer registration for the CIDRs.
	// This should be enough to consider it has started
	require.Eventually(
		t,
		func() bool {
			informer, ok := k8sCache.informers[ipamv1alpha1.GroupVersion.WithKind("CIDRs")]
			if ok && informer != nil && len(informer.handlers) > 0 {
				return true
			}
			return false
		},
		5*time.Second,
		100*time.Millisecond,
	)

	// Simulate the addition of a CIDR in the list
	informer := k8sCache.informers[ipamv1alpha1.GroupVersion.WithKind("CIDRs")]
	for _, handler := range informer.handlers {
		handler.OnAdd(cidrs, false)
	}

	// Eventually the reconcilers will go through and update the objects
	// Just give them some time to do so
	assert.Eventually(
		t,
		func() bool {
			ing := &netv1.Ingress{}
			require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Namespace: currentNamespaceName, Name: "ing1"}, ing))
			return ing.Annotations["nginx.ingress.kubernetes.io/whitelist-source-range"] == "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8"
		},
		5*time.Second,
		100*time.Millisecond,
	)
}

func TestClusterCIDRsControllerTriggersIngressReconciliation(t *testing.T) {
	extendedScheme, err := controllers.Scheme("legacy.ipam.com/v1alpha1")
	assert.NoError(t, err)

	cidrs := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "group-name"},
		Spec:       ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}}},
	}

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs).Build()

	k8sCache := &testCache{Client: k8sClient, scheme: extendedScheme}

	// Some dirty dependency injections to be able to fake the ingestion of a new CIDR
	mgr, err := manager.New(&rest.Config{}, manager.Options{
		Scheme: extendedScheme,
		MapperProvider: func(c *rest.Config, httpClient *http.Client) (meta.RESTMapper, error) {
			return meta.NewDefaultRESTMapper(extendedScheme.PrioritizedVersionsAllGroups()), nil
		},
		NewClient: func(config *rest.Config, options client.Options) (client.Client, error) {
			return k8sClient, nil
		},
		NewCache: func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
			return k8sCache, nil
		},
		Metrics: metricsserver.Options{
			BindAddress: ":8081",
		},
	})
	require.NoError(t, err)
	require.NoError(t, controllers.SetupControllersWithManager(mgr, false, "", t.Name(), "legacy.example.com"))

	go func() {
		require.NoError(t, mgr.Start(context.Background()))
	}()

	// we don't have a mean to know when the manager has actually started completely
	// Hence try to see if there has been any informer registration for the CIDRs.
	// This should be enough to consider it has started
	require.Eventually(
		t,
		func() bool {
			informer, ok := k8sCache.informers[ipamv1alpha1.GroupVersion.WithKind("ClusterCIDRs")]
			if ok && informer != nil && len(informer.handlers) > 0 {
				return true
			}
			return false
		},
		5*time.Second,
		100*time.Millisecond,
	)

	// Simulate the addition of a CIDR in the list
	informer := k8sCache.informers[ipamv1alpha1.GroupVersion.WithKind("CIDRs")]
	for _, handler := range informer.handlers {
		handler.OnAdd(cidrs, false)
	}
}

func TestCIDRsControllerTriggersGatewayReconciliation(t *testing.T) {
	extendedScheme, err := controllers.Scheme("legacy.ipam.com/v1alpha1")
	assert.NoError(t, err)

	currentNamespaceName := "namespace-" + uuid.New().String()[:8]

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "group-name", Namespace: currentNamespaceName},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test",
			Namespace: currentNamespaceName,
			Annotations: map[string]string{
				"ipam.example.com/allowlist-group": "group-name",
			},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs, gateway).Build()

	k8sCache := &testCache{Client: k8sClient, scheme: extendedScheme}

	// Some dirty dependency injections to be able to fake the ingestion of a new CIDR
	mgr, err := manager.New(&rest.Config{}, manager.Options{
		Scheme: extendedScheme,
		MapperProvider: func(c *rest.Config, httpClient *http.Client) (meta.RESTMapper, error) {
			return meta.NewDefaultRESTMapper(extendedScheme.PrioritizedVersionsAllGroups()), nil
		},
		NewClient: func(config *rest.Config, options client.Options) (client.Client, error) {
			return k8sClient, nil
		},
		NewCache: func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
			return k8sCache, nil
		},
		Metrics: metricsserver.Options{
			BindAddress: ":8082",
		},
	})
	require.NoError(t, err)
	require.NoError(t, controllers.SetupControllersWithManager(mgr, true, "legacy.ipam.com/v1alpha1", t.Name(), "ipam.example.com"))

	go func() {
		require.NoError(t, mgr.Start(context.Background()))
	}()

	// we don't have a mean to know when the manager has actually started completely
	// Hence try to see if there has been any informer registration for the CIDRs.
	// This should be enough to consider it has started
	require.Eventually(
		t,
		func() bool {
			informer, ok := k8sCache.informers[ipamv1alpha1.GroupVersion.WithKind("CIDRs")]
			if ok && informer != nil && len(informer.handlers) > 0 {
				return true
			}
			return false
		},
		5*time.Second,
		100*time.Millisecond,
	)

	// Simulate the addition of a CIDR in the list
	informer := k8sCache.informers[ipamv1alpha1.GroupVersion.WithKind("CIDRs")]
	for _, handler := range informer.handlers {
		handler.OnAdd(cidrs, false)
	}

	// Eventually the reconcilers will go through and update the objects
	// Just give them some time to do so
	assert.Eventually(
		t,
		func() bool {
			generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
			err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: currentNamespaceName}, generatedAuthorizationPolicy)
			assert.NoError(t, err)
			actual := generatedAuthorizationPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks
			expected := []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}
			return reflect.DeepEqual(actual, expected)
		},
		5*time.Second,
		100*time.Millisecond,
	)
}

func TestClusterCIDRsControllerTriggersGatewayReconciliation(t *testing.T) {
	extendedScheme, err := controllers.Scheme("legacy.ipam.com/v1alpha1")
	assert.NoError(t, err)

	currentNamespaceName := "namespace-" + uuid.New().String()[:8]

	cidrs := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "group-name"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test",
			Namespace: currentNamespaceName,
			Annotations: map[string]string{
				"ipam.example.com/cluster-allowlist-group": "group-name",
			},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs, gateway).Build()

	k8sCache := &testCache{Client: k8sClient, scheme: extendedScheme}

	// Some dirty dependency injections to be able to fake the ingestion of a new CIDR
	mgr, err := manager.New(&rest.Config{}, manager.Options{
		Scheme: extendedScheme,
		MapperProvider: func(c *rest.Config, httpClient *http.Client) (meta.RESTMapper, error) {
			return meta.NewDefaultRESTMapper(extendedScheme.PrioritizedVersionsAllGroups()), nil
		},
		NewClient: func(config *rest.Config, options client.Options) (client.Client, error) {
			return k8sClient, nil
		},
		NewCache: func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
			return k8sCache, nil
		},
		Metrics: metricsserver.Options{
			BindAddress: ":8083",
		},
	})
	require.NoError(t, err)
	require.NoError(t, controllers.SetupControllersWithManager(mgr, true, "legacy.ipam.com/v1alpha1", t.Name(), "ipam.example.com"))

	go func() {
		require.NoError(t, mgr.Start(context.Background()))
	}()

	// we don't have a mean to know when the manager has actually started completely
	// Hence try to see if there has been any informer registration for the CIDRs.
	// This should be enough to consider it has started
	require.Eventually(
		t,
		func() bool {
			informer, ok := k8sCache.informers[ipamv1alpha1.GroupVersion.WithKind("ClusterCIDRs")]
			if ok && informer != nil && len(informer.handlers) > 0 {
				return true
			}
			return false
		},
		5*time.Second,
		100*time.Millisecond,
	)

	// Simulate the addition of a CIDR in the list
	informer := k8sCache.informers[ipamv1alpha1.GroupVersion.WithKind("ClusterCIDRs")]
	for _, handler := range informer.handlers {
		handler.OnAdd(cidrs, false)
	}

	// Eventually the reconcilers will go through and update the objects
	// Just give them some time to do so
	assert.Eventually(
		t,
		func() bool {
			generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
			err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: currentNamespaceName}, generatedAuthorizationPolicy)
			assert.NoError(t, err)
			actual := generatedAuthorizationPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks
			expected := []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}
			return reflect.DeepEqual(actual, expected)
		},
		5*time.Second,
		100*time.Millisecond,
	)
}
