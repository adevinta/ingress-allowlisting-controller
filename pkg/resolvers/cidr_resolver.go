package resolvers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	log "github.com/adevinta/go-log-toolkit"
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	ipamv1alpha1_legacy "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/legacy/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var DefaultPrefix = "ipam.adevinta.com"

func (r *CidrResolver) AnnotationNotFoundError() error {
	if r.annotationNotFoundError == nil {
		r.annotationNotFoundError = errors.New("Annotation '" + r.Annotation() + "' or '" + r.ClusterAnnotation() + "' not found")
	}
	return r.annotationNotFoundError
}

func (r *CidrResolver) ClusterAnnotation() string {
	return r.AnnotationPrefix + "/cluster-allowlist-group"
}

func (r *CidrResolver) Annotation() string {
	return r.AnnotationPrefix + "/allowlist-group"
}

type cidrResolver interface {
	ResolveCidrs(namespace string, name string) ([]string, error)
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

func (r *ClusterCIDRResolver) ResolveCidrs(namespace string, name string) ([]string, error) {
	var candidates []ipamv1alpha1.CIDRsGetter = []ipamv1alpha1.CIDRsGetter{&ipamv1alpha1.ClusterCIDRs{}, &ipamv1alpha1_legacy.ClusterCIDRs{}}
	for _, cidrObj := range candidates {
		err := r.Client.Get(context.Background(), types.NamespacedName{Name: name}, cidrObj)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return cidrObj.GetStatus().CIDRs, nil
	}
	return []string{}, apierrors.NewNotFound(schema.GroupResource{Group: ipamv1alpha1.GroupVersion.Group, Resource: ipamv1alpha1.ClusterCIDRs{}.Kind}, name)
}

func (r *ClusterCIDRResolver) Kind() string        { return "ClusterCIDRs" }
func (r *ClusterCIDRResolver) IsClusterScoped() bool { return true }

func (r *NamespacedCIDRResolver) ResolveCidrs(namespace string, name string) ([]string, error) {
	var candidates []ipamv1alpha1.CIDRsGetter = []ipamv1alpha1.CIDRsGetter{&ipamv1alpha1.CIDRs{}, &ipamv1alpha1_legacy.CIDRs{}}
	for _, cidrObj := range candidates {
		err := r.Client.Get(context.Background(), types.NamespacedName{Namespace: namespace, Name: name}, cidrObj)
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return cidrObj.GetStatus().CIDRs, nil
	}
	return []string{}, apierrors.NewNotFound(schema.GroupResource{Group: ipamv1alpha1.GroupVersion.Group, Resource: ipamv1alpha1.CIDRs{}.Kind}, name)
}

// resolveName fetches CIDRs for a single named group, using cache when provided.
// Returns (ips, notFound, error): notFound=true means a 404 (caller emits event/metric);
// non-nil error means a real API failure (never cached).
func resolveName(namespace, name string, resolver cidrResolver, cache *ResolutionCache) ([]string, bool, error) {
	if cache != nil {
		ns := namespace
		if resolver.IsClusterScoped() {
			ns = ""
		}
		key := resolutionCacheKey{kind: resolver.Kind(), namespace: ns, name: name}
		if entry, ok := cache.m[key]; ok {
			return entry.ips, entry.notFound, nil
		}
		ips, err := resolver.ResolveCidrs(namespace, name)
		if err != nil && client.IgnoreNotFound(err) == nil {
			cache.m[key] = resolutionCacheEntry{notFound: true}
			return nil, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		cache.m[key] = resolutionCacheEntry{ips: ips}
		return ips, false, nil
	}

	ips, err := resolver.ResolveCidrs(namespace, name)
	if err != nil && client.IgnoreNotFound(err) == nil {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	return ips, false, nil
}

func getIpsFromAnnotation(ctx context.Context, annotationValue string, resolver cidrResolver, object client.Object, c client.Client, cache *ResolutionCache) ([]string, error) {
	log := log.DefaultLogger.WithContext(ctx)
	allowNames := strings.Split(annotationValue, ",")
	var allowedIps []string
	for _, group := range allowNames {
		trimmedName := strings.TrimSpace(group)
		log.Infof("resolving allowlist name %s", trimmedName)

		ipList, notFound, err := resolveName(object.GetNamespace(), trimmedName, resolver, cache)

		if notFound {
			if evtErr := notFoundEvent(c, object, resolver.Kind(), trimmedName); evtErr != nil {
				return nil, evtErr
			}
		}

		if err != nil {
			cidrsNotFound.With(prometheus.Labels{"namespace": object.GetNamespace(), "object": object.GetObjectKind().GroupVersionKind().Kind, "name": object.GetName(), "cidrs_name": trimmedName}).Set(1.0)
			return nil, err
		}
		if notFound || len(ipList) == 0 {
			cidrsNotFound.With(prometheus.Labels{"namespace": object.GetNamespace(), "object": object.GetObjectKind().GroupVersionKind().Kind, "name": object.GetName(), "cidrs_name": trimmedName}).Set(1.0)
		} else {
			cidrsNotFound.With(prometheus.Labels{"namespace": object.GetNamespace(), "object": object.GetObjectKind().GroupVersionKind().Kind, "name": object.GetName(), "cidrs_name": trimmedName}).Set(0.0)
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

func (r *NamespacedCIDRResolver) Kind() string        { return "NamespacedCIDRs" }
func (r *NamespacedCIDRResolver) IsClusterScoped() bool { return false }

func notFoundEvent(c client.Client, owner client.Object, kind string, notFoundObject string) error {
	evt := v1.Event{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    owner.GetNamespace(),
			GenerateName: owner.GetName() + "-allowlist-cidrs-not-found",
		},
	}

	_, err := ctrl.CreateOrUpdate(context.TODO(), c, &evt, func() error {
		evt.Message = fmt.Sprintf("Couldn't update %s %s:%s allowlist because CIDR Group %s:%s was not found", owner.GetObjectKind().GroupVersionKind().Kind, owner.GetNamespace(), owner.GetName(), kind, notFoundObject)
		evt.Action = "LookupAllowListingGroup"
		if evt.Series == nil {
			evt.Series = &v1.EventSeries{}
		}
		evt.Count++
		evt.Series.Count++
		evt.Series.LastObservedTime = metav1.NewMicroTime(time.Now())
		evt.Reason = ""
		evt.Source.Component = "ingress-allowlisting-controller"
		evt.LastTimestamp = metav1.NewTime(time.Now())
		if evt.FirstTimestamp.IsZero() {
			evt.FirstTimestamp = evt.LastTimestamp
		}
		evt.InvolvedObject = v1.ObjectReference{
			APIVersion: owner.GetObjectKind().GroupVersionKind().GroupVersion().String(),
			Kind:       owner.GetObjectKind().GroupVersionKind().Kind,
			Name:       owner.GetName(),
			Namespace:  owner.GetNamespace(),
			UID:        owner.GetUID(),
		}
		return nil
	})

	return err
}

type CidrResolver struct {
	Client                  client.Client
	AnnotationPrefix        string
	annotationNotFoundError error
}

func (r *CidrResolver) GetCidrsFromObject(ctx context.Context, object client.Object) ([]string, error) {
	return r.GetCidrsFromObjectWithCache(ctx, object, nil)
}

// GetCidrsFromObjectWithCache resolves CIDRs for object, using cache to deduplicate Kubernetes
// API calls across siblings. Metrics and events are emitted for every object regardless of cache hits.
func (r *CidrResolver) GetCidrsFromObjectWithCache(ctx context.Context, object client.Object, cache *ResolutionCache) ([]string, error) {
	log := log.DefaultLogger.WithContext(ctx)
	allowlistedGroups, okCidrAnnotation := object.GetAnnotations()[r.Annotation()]
	allowlistedClusterGroups, okClusterCidrAnnotation := object.GetAnnotations()[r.ClusterAnnotation()]
	if !okCidrAnnotation && !okClusterCidrAnnotation {
		log.Info(object.GetObjectKind().GroupVersionKind().Kind, " does not have the allowlist group annotation, ignoring ", object.GetName(), "namespace", object.GetNamespace())
		return []string{}, r.AnnotationNotFoundError()
	}
	var allowedIps []string
	var err error
	if okCidrAnnotation {
		namespacedCIDRResolver := &NamespacedCIDRResolver{Client: r.Client}
		allowedIps, err = getIpsFromAnnotation(ctx, allowlistedGroups, namespacedCIDRResolver, object, r.Client, cache)
		if err != nil {
			return []string{}, err
		}
	}
	var allowedClusterIps []string
	if okClusterCidrAnnotation {
		clusterCIDRResolver := &ClusterCIDRResolver{Client: r.Client}
		allowedClusterIps, err = getIpsFromAnnotation(ctx, allowlistedClusterGroups, clusterCIDRResolver, object, r.Client, cache)
		if err != nil {
			return []string{}, err
		}
		allowedIps = append(allowedIps, allowedClusterIps...)
	}
	return util.DedupSorted(allowedIps), nil
}
