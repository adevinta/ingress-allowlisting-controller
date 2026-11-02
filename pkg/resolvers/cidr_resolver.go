package resolvers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	log "github.com/adevinta/go-log-toolkit"
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

var DefaultPrefix = "ipam.adevinta.com"

// ErrAnnotationNotFound is returned (wrapped, with the annotation names) for an object that has
// neither allowlist annotation. Check it with errors.Is: a sentinel works for every resolver copy
// and still matches once the error is wrapped.
var ErrAnnotationNotFound = errors.New("allowlist annotation not found")

func (r *CidrResolver) ClusterAnnotation() string {
	return r.AnnotationPrefix + "/cluster-allowlist-group"
}

func (r *CidrResolver) Annotation() string {
	return r.AnnotationPrefix + "/allowlist-group"
}

type cidrResolver interface {
	ResolveCidrs(ctx context.Context, namespace string, name string) ([]string, error)
	Kind() string
	IsClusterScoped() bool
}

// ResolutionCache deduplicates Kubernetes API calls for CIDR lookups within a single reconcile.
// Metrics and events are still emitted for every object; only the underlying Get is cached.
type ResolutionCache struct {
	m map[resolutionCacheKey]resolutionCacheEntry
}

type resolutionCacheKey struct {
	kind      string
	namespace string
	name      string
}

type resolutionCacheEntry struct {
	ips      []string
	notFound bool
}

func NewResolutionCache() *ResolutionCache {
	return &ResolutionCache{m: make(map[resolutionCacheKey]resolutionCacheEntry)}
}

type ClusterCIDRResolver struct {
	client.Client
}

type NamespacedCIDRResolver struct {
	client.Client
}

func (r *ClusterCIDRResolver) ResolveCidrs(ctx context.Context, namespace string, name string) ([]string, error) {
	cidrObj := &ipamv1alpha1.ClusterCIDRs{}
	if err := r.Client.Get(ctx, types.NamespacedName{Name: name}, cidrObj); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, err
		}
		return []string{}, apierrors.NewNotFound(schema.GroupResource{Group: ipamv1alpha1.GroupVersion.Group, Resource: ipamv1alpha1.ClusterCIDRs{}.Kind}, name)
	}
	return cidrObj.GetStatus().CIDRs, nil
}

func (r *ClusterCIDRResolver) Kind() string          { return "ClusterCIDRs" }
func (r *ClusterCIDRResolver) IsClusterScoped() bool { return true }

func (r *NamespacedCIDRResolver) ResolveCidrs(ctx context.Context, namespace string, name string) ([]string, error) {
	cidrObj := &ipamv1alpha1.CIDRs{}
	if err := r.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, cidrObj); err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, err
		}
		return []string{}, apierrors.NewNotFound(schema.GroupResource{Group: ipamv1alpha1.GroupVersion.Group, Resource: ipamv1alpha1.CIDRs{}.Kind}, name)
	}
	return cidrObj.GetStatus().CIDRs, nil
}

// resolveName fetches CIDRs for a single named group, using cache when provided.
// Returns (ips, notFound, error): notFound=true means a 404 (caller emits event/metric);
// non-nil error means a real API failure (never cached).
func resolveName(ctx context.Context, namespace, name string, resolver cidrResolver, cache *ResolutionCache) ([]string, bool, error) {
	// Cache lookup. The key drops the namespace for cluster-scoped resolvers so the same
	// ClusterCIDRs object is shared across namespaces. On a hit we're done; otherwise fall
	// through to resolve and, if caching, record the result below.
	var key resolutionCacheKey
	if cache != nil {
		ns := namespace
		if resolver.IsClusterScoped() {
			ns = ""
		}
		key = resolutionCacheKey{kind: resolver.Kind(), namespace: ns, name: name}
		if entry, ok := cache.m[key]; ok {
			return entry.ips, entry.notFound, nil
		}
	}

	log.DefaultLogger.WithContext(ctx).Infof("resolving allowlist name %s", name)
	ips, err := resolver.ResolveCidrs(ctx, namespace, name)
	if err != nil && client.IgnoreNotFound(err) == nil {
		if cache != nil {
			cache.m[key] = resolutionCacheEntry{notFound: true}
		}
		return nil, true, nil
	}
	if err != nil {
		// Real API failure: never cached, so a transient error is retried next reconcile.
		return nil, false, err
	}
	if cache != nil {
		cache.m[key] = resolutionCacheEntry{ips: ips}
	}
	return ips, false, nil
}

func getIpsFromAnnotation(ctx context.Context, annotationValue string, resolver cidrResolver, object client.Object, c client.Client, recorder events.EventRecorder, cache *ResolutionCache, groups *[]groupResult) ([]string, error) {
	log := log.DefaultLogger.WithContext(ctx)
	allowNames := strings.Split(annotationValue, ",")
	var allowedIps []string
	for _, group := range allowNames {
		trimmedName := strings.TrimSpace(group)

		ipList, notFound, err := resolveName(ctx, object.GetNamespace(), trimmedName, resolver, cache)

		if notFound {
			notFoundEvent(recorder, c, object, resolver.Kind(), trimmedName)
		}

		*groups = append(*groups, groupResult{kind: resolver.Kind(), name: trimmedName, missing: err != nil || notFound || len(ipList) == 0})
		if err != nil {
			return nil, err
		}

		for _, ip := range ipList {
			_, ipNet, err := net.ParseCIDR(ip)
			if err != nil {
				log.Warnf("Invalid IP range: %s, error: %s, skipping this one", ip, err.Error())
				continue
			}

			allowedIps = append(allowedIps, ipNet.String())
		}
	}

	if (len(allowNames) > 0) && len(allowedIps) == 0 {
		allowedIps = []string{"127.0.0.2/32"}
		log.Warnf("No valid CIDRsList object found for '%s'. Check object exists and annotation is comma-separated. %s %s configured to DenyAll", annotationValue, object.GetObjectKind().GroupVersionKind().Kind, object.GetName())
	}
	return allowedIps, nil
}

func (r *NamespacedCIDRResolver) Kind() string          { return "NamespacedCIDRs" }
func (r *NamespacedCIDRResolver) IsClusterScoped() bool { return false }

// metricKind is the "object" label: the object's kind, from the scheme when the object doesn't
// carry it (typed objects don't always have TypeMeta set), so the label is the same however the
// object was read and matches what ForgetObject is given.
func metricKind(c client.Client, object client.Object) string {
	if kind := object.GetObjectKind().GroupVersionKind().Kind; kind != "" {
		return kind
	}
	if c == nil {
		return ""
	}
	gvk, err := apiutil.GVKForObject(object, c.Scheme())
	if err != nil {
		return ""
	}
	return gvk.Kind
}

// notFoundEvent records a Warning Event on the object referencing a missing CIDRs object. The
// recorder aggregates repeats into one Event with a series, and never reads Events, so no watch is
// started. It is fire-and-forget: a failure to write the Event doesn't affect the resolution.
func notFoundEvent(recorder events.EventRecorder, c client.Client, object client.Object, kind string, name string) {
	if recorder == nil {
		return
	}
	recorder.Eventf(eventReference(c, object), nil, v1.EventTypeWarning, "AllowlistGroupNotFound", "LookupAllowListingGroup",
		"Couldn't update the allowlist because %s %q was not found", kind, name)
}

// eventReference is the object an Event is about, without its resourceVersion. The recorder only
// aggregates identical Events, and the reference is part of that identity: with the version, every
// update of the object (each reconcile writes it) would start a new Event instead of counting.
func eventReference(c client.Client, object client.Object) runtime.Object {
	gvk := object.GetObjectKind().GroupVersionKind()
	if gvk.Kind == "" && c != nil {
		var err error
		if gvk, err = apiutil.GVKForObject(object, c.Scheme()); err != nil {
			return object // the recorder resolves the reference itself, version included
		}
	}
	if gvk.Kind == "" {
		return object
	}
	return &v1.ObjectReference{
		APIVersion: gvk.GroupVersion().String(),
		Kind:       gvk.Kind,
		Namespace:  object.GetNamespace(),
		Name:       object.GetName(),
		UID:        object.GetUID(),
	}
}

type CidrResolver struct {
	Client           client.Client
	AnnotationPrefix string
	// Recorder emits an Event when a referenced CIDRs/ClusterCIDRs object is missing. Optional:
	// nil emits none (e.g. the preflight registry).
	Recorder events.EventRecorder
}

func (r *CidrResolver) GetCidrsFromObject(ctx context.Context, object client.Object) ([]string, error) {
	return r.GetCidrsFromObjectWithCache(ctx, object, nil)
}

// GetCidrsFromObjectWithCache resolves CIDRs for object, using cache to deduplicate Kubernetes
// API calls across siblings. Metrics and events are emitted for every object regardless of cache hits.
func (r *CidrResolver) GetCidrsFromObjectWithCache(ctx context.Context, object client.Object, cache *ResolutionCache) ([]string, error) {
	log := log.DefaultLogger.WithContext(ctx)
	// The series are rebuilt from the current annotation: a group removed from it, or the whole
	// annotation, takes its series with it.
	kind := metricKind(r.Client, object)
	ForgetObject(object.GetNamespace(), kind, object.GetName())
	allowlistedGroups, okCidrAnnotation := object.GetAnnotations()[r.Annotation()]
	allowlistedClusterGroups, okClusterCidrAnnotation := object.GetAnnotations()[r.ClusterAnnotation()]
	if !okCidrAnnotation && !okClusterCidrAnnotation {
		// Debug: the in-place controllers reconcile every object of their kind, so at info this would
		// be logged for every unannotated Ingress, Service and NetworkPolicy on every change and resync.
		log.Debug(object.GetObjectKind().GroupVersionKind().Kind, " does not have the allowlist group annotation, ignoring ", object.GetName(), "namespace", object.GetNamespace())
		return []string{}, fmt.Errorf("%w: %q or %q", ErrAnnotationNotFound, r.Annotation(), r.ClusterAnnotation())
	}
	// Written once both annotations are resolved, also when one fails.
	var groups []groupResult
	defer func() { recordGroupMetrics(object.GetNamespace(), kind, object.GetName(), groups) }()
	var allowedIps []string
	var err error
	if okCidrAnnotation {
		namespacedCIDRResolver := &NamespacedCIDRResolver{Client: r.Client}
		allowedIps, err = getIpsFromAnnotation(ctx, allowlistedGroups, namespacedCIDRResolver, object, r.Client, r.Recorder, cache, &groups)
		if err != nil {
			return []string{}, err
		}
	}
	var allowedClusterIps []string
	if okClusterCidrAnnotation {
		clusterCIDRResolver := &ClusterCIDRResolver{Client: r.Client}
		allowedClusterIps, err = getIpsFromAnnotation(ctx, allowlistedClusterGroups, clusterCIDRResolver, object, r.Client, r.Recorder, cache, &groups)
		if err != nil {
			return []string{}, err
		}
		allowedIps = append(allowedIps, allowedClusterIps...)
	}
	return util.DedupSorted(allowedIps), nil
}
