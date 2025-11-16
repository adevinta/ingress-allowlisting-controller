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
	generate "github.com/adevinta/ingress-allowlisting-controller/pkg/hash"
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

func (r *CidrResolver) HashAlreadyMatchError() error {
	if r.hashAlreadyMatchError == nil {
		r.hashAlreadyMatchError = errors.New("Calculated hash match the annotation hash")
	}
	return r.hashAlreadyMatchError
}

func (r *CidrResolver) ClusterAnnotation() string {
	return r.AnnotationPrefix + "/cluster-allowlist-group"
}

func (r *CidrResolver) Annotation() string {
	return r.AnnotationPrefix + "/allowlist-group"
}

func (r *CidrResolver) Hash() string {
	return r.AnnotationPrefix + "/hash"
}

type cidrResolver interface {
	ResolveCidrs(namespace string, name string) ([]string, error)
	Kind() string
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

func (r *ClusterCIDRResolver) Kind() string {
	return "ClusterCIDRs"
}

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

func getIpsFromAnnotation(ctx context.Context, annotationValue string, resolver cidrResolver, object client.Object, c client.Client) ([]string, error) {
	log := log.DefaultLogger.WithContext(ctx)
	allowNames := strings.Split(annotationValue, ",")
	var allowedIps []string
	for _, group := range allowNames {
		trimmedName := strings.TrimSpace(group)
		log.Infof("resolving allowlist name %s", trimmedName)

		ipList, err := resolver.ResolveCidrs(object.GetNamespace(), trimmedName)

		if err != nil && client.IgnoreNotFound(err) == nil {
			err := notFoundEvent(c, object, resolver.Kind(), trimmedName)
			if err != nil {
				return nil, err
			}
		}

		if client.IgnoreNotFound(err) != nil {
			cidrsNotFound.With(prometheus.Labels{"namespace": object.GetNamespace(), "object": object.GetObjectKind().GroupVersionKind().Kind, "name": object.GetName(), "cidrs_name": trimmedName}).Set(1.0)
			return nil, err
		}
		if len(ipList) == 0 {
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

			// Only append valid ip ranges
			allowedIps = append(allowedIps, ipNet.String())
		}
	}

	if (len(allowNames) > 0) && len(allowedIps) == 0 {
		allowedIps = []string{"127.0.0.2/32"}
		log.Warnf("No valid CIDRsList object found for '%s'. Check object exists and annotation is comma-separated. %s %s configured to DenyAll", annotationValue, object.GetObjectKind().GroupVersionKind().Kind, object.GetName())
	}
	return allowedIps, nil
}

func (r *NamespacedCIDRResolver) Kind() string {
	return "NamespacedCIDRs"
}

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
	hashAlreadyMatchError   error
}

func (r *CidrResolver) GetCidrsFromObject(ctx context.Context, object client.Object) ([]string, error) {
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
		allowedIps, err = getIpsFromAnnotation(ctx, allowlistedGroups, namespacedCIDRResolver, object, r.Client)
		if err != nil {
			return []string{}, err
		}
	}
	var allowedClusterIps []string
	if okClusterCidrAnnotation {
		clusterCIDRResolver := &ClusterCIDRResolver{Client: r.Client}
		allowedClusterIps, err = getIpsFromAnnotation(ctx, allowlistedClusterGroups, clusterCIDRResolver, object, r.Client)
		if err != nil {
			return []string{}, err
		}
		allowedIps = append(allowedIps, allowedClusterIps...)
	}
	return allowedIps, nil
}

func (r *CidrResolver) CompareHashWithObject(ctx context.Context, object client.Object, allValues ...any) (string, error) {
	log := log.DefaultLogger.WithContext(ctx)
	newHash := generate.GenerateCIDRsHash(allValues)
	oldHash, ok := object.GetAnnotations()[r.Hash()]
	if ok {
		if oldHash == newHash {
			// bingo, we dont have to do anything
			return "", r.HashAlreadyMatchError()
		}
	}
	log.Info(object.GetObjectKind().GroupVersionKind().Kind, " fresh object, no hash yet in ", object.GetName(), "namespace", object.GetNamespace())
	return newHash, nil
}
