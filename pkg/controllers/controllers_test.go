package controllers_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	netv1 "k8s.io/api/networking/v1"
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

// namespacedScope implements meta.RESTScope for namespace-scoped resources.
type namespacedScope struct{}

func (namespacedScope) Name() meta.RESTScopeName { return meta.RESTScopeNameNamespace }

// schemeRESTMapper builds a DefaultRESTMapper that includes every GVK registered
// in the scheme. All types are treated as namespaced (sufficient for isCRDInstalled checks).
func schemeRESTMapper(s *runtime.Scheme) meta.RESTMapper {
	mapper := meta.NewDefaultRESTMapper(s.PrioritizedVersionsAllGroups())
	for gvk := range s.AllKnownTypes() {
		mapper.Add(gvk, namespacedScope{})
	}
	return mapper
}

type testHandlerRegistration struct{}

func (r *testHandlerRegistration) HasSynced() bool { return true }
func (r *testHandlerRegistration) HasSyncedChecker() toolscache.DoneChecker {
	ch := make(chan struct{})
	close(ch)
	return &testDoneChecker{ch: ch}
}

type testDoneChecker struct{ ch chan struct{} }

func (d *testDoneChecker) Name() string          { return "testInformer" }
func (d *testDoneChecker) Done() <-chan struct{} { return d.ch }

// testInformer is a fake informer. Like a real one, a handler registered after objects were added
// still receives an Add for each of them, so tests don't depend on the order in which the
// controllers start and register their handlers. Safe for concurrent use.
type testInformer struct {
	mu       sync.Mutex
	handlers []toolscache.ResourceEventHandler
	objects  []interface{}
}

func (i *testInformer) addHandler(handler toolscache.ResourceEventHandler) (toolscache.ResourceEventHandlerRegistration, error) {
	i.mu.Lock()
	i.handlers = append(i.handlers, handler)
	objects := slices.Clone(i.objects)
	i.mu.Unlock()
	for _, obj := range objects {
		handler.OnAdd(obj, false)
	}
	return &testHandlerRegistration{}, nil
}

// Add sends obj to the registered handlers and keeps it for handlers registered later. Each handler
// gets it exactly once: adding it and registering a handler each happen under the lock.
func (i *testInformer) Add(obj interface{}) {
	i.mu.Lock()
	i.objects = append(i.objects, obj)
	handlers := slices.Clone(i.handlers)
	i.mu.Unlock()
	for _, handler := range handlers {
		handler.OnAdd(obj, false)
	}
}

func (i *testInformer) handlerCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.handlers)
}

var _ cache.Informer = &testInformer{}

func (i *testInformer) AddEventHandler(handler toolscache.ResourceEventHandler) (toolscache.ResourceEventHandlerRegistration, error) {
	return i.addHandler(handler)
}

func (i *testInformer) RemoveEventHandler(handler toolscache.ResourceEventHandlerRegistration) error {
	return nil
}

func (i *testInformer) AddEventHandlerWithResyncPeriod(handler toolscache.ResourceEventHandler, resyncPeriod time.Duration) (toolscache.ResourceEventHandlerRegistration, error) {
	return i.addHandler(handler)
}

func (i *testInformer) AddEventHandlerWithOptions(handler toolscache.ResourceEventHandler, options toolscache.HandlerOptions) (toolscache.ResourceEventHandlerRegistration, error) {
	return i.addHandler(handler)
}

func (i *testInformer) IsStopped() bool {
	return false
}

func (i *testInformer) AddIndexers(indexers toolscache.Indexers) error {
	return nil
}

func (i *testInformer) HasSynced() bool {
	return true
}

func (i *testInformer) HasSyncedChecker() toolscache.DoneChecker {
	ch := make(chan struct{})
	close(ch)
	return &testDoneChecker{ch: ch}
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
	c.m.Lock()
	defer c.m.Unlock()
	c.synced = true
	return true
}

// informer returns the informer for gvk, creating it if no controller asked for it yet.
func (c *testCache) informer(gvk schema.GroupVersionKind) *testInformer {
	i, _ := c.GetInformerForKind(context.Background(), gvk)
	return i.(*testInformer)
}

// hasInformer reports whether a controller asked for an informer for gvk.
func (c *testCache) hasInformer(gvk schema.GroupVersionKind) bool {
	c.m.Lock()
	defer c.m.Unlock()
	_, ok := c.informers[gvk]
	return ok
}

func (c *testCache) IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error {
	return errors.New("IndexField not implemented")
}

func TestCIDRsControllerTriggersIngressReconciliation(t *testing.T) {
	extendedScheme, err := controllers.Scheme()
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
			return schemeRESTMapper(extendedScheme), nil
		},
		NewClient: func(config *rest.Config, options client.Options) (client.Client, error) {
			return k8sClient, nil
		},
		NewCache: func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
			return k8sCache, nil
		},
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	require.NoError(t, err)
	require.NoError(t, controllers.SetupControllersWithManager(mgr, true, false, false, false, false, t.Name(), "ipam.example.com", true, controllers.DefaultCIDRSourceOptions()))

	go func() {
		require.NoError(t, mgr.Start(context.Background()))
	}()

	// we don't have a mean to know when the manager has actually started completely
	// Hence try to see if there has been any informer registration for the CIDRs.
	// This should be enough to consider it has started
	require.Eventually(
		t,
		func() bool {
			return k8sCache.informer(ipamv1alpha1.GroupVersion.WithKind("CIDRs")).handlerCount() > 0
		},
		5*time.Second,
		100*time.Millisecond,
	)

	// Simulate the addition of a CIDR in the list
	k8sCache.informer(ipamv1alpha1.GroupVersion.WithKind("CIDRs")).Add(cidrs)

	// Eventually the reconcilers will go through and update the objects
	// Just give them some time to do so
	assert.Eventually(
		t,
		func() bool {
			ing := &netv1.Ingress{}
			require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Namespace: currentNamespaceName, Name: "ing1"}, ing))
			return ing.Annotations["nginx.ingress.kubernetes.io/whitelist-source-range"] == "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
		},
		5*time.Second,
		100*time.Millisecond,
	)
}

func TestClusterCIDRsControllerTriggersIngressReconciliation(t *testing.T) {
	extendedScheme, err := controllers.Scheme()
	assert.NoError(t, err)

	currentNamespaceName := "namespace-" + uuid.New().String()[:8]

	cidrs := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "group-name"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	ing := &netv1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Name:      "ing1",
			Namespace: currentNamespaceName,
			Annotations: map[string]string{
				"custom.example.com/cluster-allowlist-group": "group-name",
			},
		},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs, ing).Build()

	k8sCache := &testCache{Client: k8sClient, scheme: extendedScheme}

	// Some dirty dependency injections to be able to fake the ingestion of a new CIDR
	mgr, err := manager.New(&rest.Config{}, manager.Options{
		Scheme: extendedScheme,
		MapperProvider: func(c *rest.Config, httpClient *http.Client) (meta.RESTMapper, error) {
			return schemeRESTMapper(extendedScheme), nil
		},
		NewClient: func(config *rest.Config, options client.Options) (client.Client, error) {
			return k8sClient, nil
		},
		NewCache: func(config *rest.Config, opts cache.Options) (cache.Cache, error) {
			return k8sCache, nil
		},
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	require.NoError(t, err)
	require.NoError(t, controllers.SetupControllersWithManager(mgr, true, false, false, false, false, t.Name(), "custom.example.com", true, controllers.DefaultCIDRSourceOptions()))

	go func() {
		require.NoError(t, mgr.Start(context.Background()))
	}()

	// we don't have a mean to know when the manager has actually started completely
	// Hence try to see if there has been any informer registration for the CIDRs.
	// This should be enough to consider it has started
	require.Eventually(
		t,
		func() bool {
			return k8sCache.informer(ipamv1alpha1.GroupVersion.WithKind("ClusterCIDRs")).handlerCount() > 0
		},
		5*time.Second,
		100*time.Millisecond,
	)

	// Simulate the addition of a ClusterCIDRs object
	k8sCache.informer(ipamv1alpha1.GroupVersion.WithKind("ClusterCIDRs")).Add(cidrs)

	// The Ingress referencing it gets its CIDRs.
	assert.Eventually(
		t,
		func() bool {
			ing := &netv1.Ingress{}
			require.NoError(t, k8sClient.Get(context.Background(), types.NamespacedName{Namespace: currentNamespaceName, Name: "ing1"}, ing))
			return ing.Annotations["nginx.ingress.kubernetes.io/whitelist-source-range"] == "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
		},
		5*time.Second,
		100*time.Millisecond,
	)
}

func TestCIDRsControllerTriggersGatewayReconciliation(t *testing.T) {
	extendedScheme, err := controllers.Scheme()
	assert.NoError(t, err)

	currentNamespaceName := "namespace-" + uuid.New().String()[:8]

	cidrs := &ipamv1alpha1.CIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "group-name", Namespace: currentNamespaceName},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	gwClass := &gatewayApiv1.GatewayClass{
		ObjectMeta: v1.ObjectMeta{Name: "istio"},
		Spec:       gatewayApiv1.GatewayClassSpec{ControllerName: "istio.io/gateway-controller"},
	}
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test",
			Namespace: currentNamespaceName,
			Annotations: map[string]string{
				"ipam.example.com/allowlist-group": "group-name",
			},
		},
		Spec: gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs, gwClass, gateway).Build()

	k8sCache := &testCache{Client: k8sClient, scheme: extendedScheme}

	// Some dirty dependency injections to be able to fake the ingestion of a new CIDR
	mgr, err := manager.New(&rest.Config{}, manager.Options{
		Scheme: extendedScheme,
		MapperProvider: func(c *rest.Config, httpClient *http.Client) (meta.RESTMapper, error) {
			return schemeRESTMapper(extendedScheme), nil
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
	require.NoError(t, controllers.SetupControllersWithManager(mgr, true, true, false, false, false, t.Name(), "ipam.example.com", true, controllers.DefaultCIDRSourceOptions()))

	go func() {
		require.NoError(t, mgr.Start(context.Background()))
	}()

	// we don't have a mean to know when the manager has actually started completely
	// Hence try to see if there has been any informer registration for the CIDRs.
	// This should be enough to consider it has started
	require.Eventually(
		t,
		func() bool {
			return k8sCache.informer(ipamv1alpha1.GroupVersion.WithKind("CIDRs")).handlerCount() > 0
		},
		5*time.Second,
		100*time.Millisecond,
	)

	// Simulate the addition of a CIDR in the list
	k8sCache.informer(ipamv1alpha1.GroupVersion.WithKind("CIDRs")).Add(cidrs)

	// Eventually the reconcilers will go through and update the objects
	// Just give them some time to do so
	assert.Eventually(
		t,
		func() bool {
			generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
			err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: currentNamespaceName}, generatedAuthorizationPolicy)
			if err != nil {
				return false
			}
			if len(generatedAuthorizationPolicy.Spec.Rules) == 0 {
				return false
			}
			actual := generatedAuthorizationPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks
			expected := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
			return reflect.DeepEqual(actual, expected)
		},
		5*time.Second,
		100*time.Millisecond,
	)
}

func TestCIDRsControllerDoesNotWatchSecretsAndConfigMapsWhenDisabled(t *testing.T) {
	extendedScheme, err := controllers.Scheme()
	require.NoError(t, err)

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).Build()
	k8sCache := &testCache{Client: k8sClient, scheme: extendedScheme}

	mgr, err := manager.New(&rest.Config{}, manager.Options{
		Scheme:  extendedScheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
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
	require.NoError(t, controllers.SetupControllersWithManager(mgr, false, false, false, false, false, t.Name(), "ipam.adevinta.com", false, controllers.DefaultCIDRSourceOptions()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		require.NoError(t, mgr.Start(ctx))
	}()

	require.Eventually(
		t,
		func() bool {
			return k8sCache.informer(ipamv1alpha1.GroupVersion.WithKind("CIDRs")).handlerCount() > 0
		},
		5*time.Second,
		100*time.Millisecond,
	)

	secretGVK := schema.GroupVersionKind{Version: "v1", Kind: "Secret"}
	configMapGVK := schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}
	secretWatched := k8sCache.hasInformer(secretGVK)
	configMapWatched := k8sCache.hasInformer(configMapGVK)
	assert.False(t, secretWatched, "Secret informer must not be registered when httpHeadersEnabled=false")
	assert.False(t, configMapWatched, "ConfigMap informer must not be registered when httpHeadersEnabled=false")
}

func TestCIDRsControllerWatchesSecretsAndConfigMapsWhenEnabled(t *testing.T) {
	extendedScheme, err := controllers.Scheme()
	require.NoError(t, err)

	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).Build()
	k8sCache := &testCache{Client: k8sClient, scheme: extendedScheme}

	mgr, err := manager.New(&rest.Config{}, manager.Options{
		Scheme:  extendedScheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
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
	require.NoError(t, controllers.SetupControllersWithManager(mgr, false, false, false, false, false, t.Name(), "ipam.adevinta.com", true, controllers.DefaultCIDRSourceOptions()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		require.NoError(t, mgr.Start(ctx))
	}()

	secretGVK := schema.GroupVersionKind{Version: "v1", Kind: "Secret"}
	configMapGVK := schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}

	require.Eventually(
		t,
		func() bool {
			return k8sCache.informer(secretGVK).handlerCount() > 0 && k8sCache.informer(configMapGVK).handlerCount() > 0
		},
		5*time.Second,
		100*time.Millisecond,
	)
}

func TestClusterCIDRsControllerTriggersGatewayReconciliation(t *testing.T) {
	extendedScheme, err := controllers.Scheme()
	assert.NoError(t, err)

	currentNamespaceName := "namespace-" + uuid.New().String()[:8]

	cidrs := &ipamv1alpha1.ClusterCIDRs{
		ObjectMeta: v1.ObjectMeta{Name: "group-name"},
		Status:     ipamv1alpha1.CIDRsStatus{CIDRs: []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}},
	}
	gwClass := &gatewayApiv1.GatewayClass{
		ObjectMeta: v1.ObjectMeta{Name: "istio"},
		Spec:       gatewayApiv1.GatewayClassSpec{ControllerName: "istio.io/gateway-controller"},
	}
	gateway := &gatewayApiv1.Gateway{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test",
			Namespace: currentNamespaceName,
			Annotations: map[string]string{
				"ipam.example.com/cluster-allowlist-group": "group-name",
			},
		},
		Spec: gatewayApiv1.GatewaySpec{GatewayClassName: "istio"},
	}
	k8sClient := fake.NewClientBuilder().WithScheme(extendedScheme).WithObjects(cidrs, gwClass, gateway).Build()

	k8sCache := &testCache{Client: k8sClient, scheme: extendedScheme}

	// Some dirty dependency injections to be able to fake the ingestion of a new CIDR
	mgr, err := manager.New(&rest.Config{}, manager.Options{
		Scheme: extendedScheme,
		MapperProvider: func(c *rest.Config, httpClient *http.Client) (meta.RESTMapper, error) {
			return schemeRESTMapper(extendedScheme), nil
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
	require.NoError(t, controllers.SetupControllersWithManager(mgr, true, true, false, false, false, t.Name(), "ipam.example.com", true, controllers.DefaultCIDRSourceOptions()))

	go func() {
		require.NoError(t, mgr.Start(context.Background()))
	}()

	// we don't have a mean to know when the manager has actually started completely
	// Hence try to see if there has been any informer registration for the CIDRs.
	// This should be enough to consider it has started
	require.Eventually(
		t,
		func() bool {
			return k8sCache.informer(ipamv1alpha1.GroupVersion.WithKind("ClusterCIDRs")).handlerCount() > 0
		},
		5*time.Second,
		100*time.Millisecond,
	)

	// Simulate the addition of a CIDR in the list
	k8sCache.informer(ipamv1alpha1.GroupVersion.WithKind("ClusterCIDRs")).Add(cidrs)

	// Eventually the reconcilers will go through and update the objects
	// Just give them some time to do so
	assert.Eventually(
		t,
		func() bool {
			generatedAuthorizationPolicy := &istiosecurityv1.AuthorizationPolicy{}
			err = k8sClient.Get(context.Background(), client.ObjectKey{Name: "test", Namespace: currentNamespaceName}, generatedAuthorizationPolicy)
			if err != nil {
				return false
			}
			if len(generatedAuthorizationPolicy.Spec.Rules) == 0 {
				return false
			}
			actual := generatedAuthorizationPolicy.Spec.Rules[0].From[0].Source.RemoteIpBlocks
			expected := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
			return reflect.DeepEqual(actual, expected)
		},
		5*time.Second,
		100*time.Millisecond,
	)
}

// TestTestInformerDeliversToLateHandlers checks the fake informer the manager tests rely on: every
// handler gets every object exactly once, whether it registers before or after the object was
// added, also when both happen concurrently (the controllers start in parallel). Without that, a
// controller starting late misses the event and the test times out (the CI flake of #59).
func TestTestInformerDeliversToLateHandlers(t *testing.T) {
	const handlers, objects = 20, 20
	informer := &testInformer{}
	counts := make([]atomic.Int32, handlers)
	var wg sync.WaitGroup
	for h := 0; h < handlers; h++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) { counts[h].Add(1) },
			})
		}()
	}
	for o := 0; o < objects; o++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			informer.Add(o)
		}()
	}
	wg.Wait()
	for h := range counts {
		assert.Equal(t, int32(objects), counts[h].Load(), "handler %d", h)
	}
}
