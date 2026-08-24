package writers

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	TraefikSchemeGroupVersion = schema.GroupVersion{Group: "traefik.io", Version: "v1alpha1"}
	TraefikSchemeBuilder      = runtime.NewSchemeBuilder(addTraefikTypes)
	AddTraefikToScheme        = TraefikSchemeBuilder.AddToScheme
)

func addTraefikTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypeWithName(TraefikSchemeGroupVersion.WithKind("Middleware"), &TraefikMiddleware{})
	scheme.AddKnownTypeWithName(TraefikSchemeGroupVersion.WithKind("MiddlewareList"), &TraefikMiddlewareList{})
	metav1.AddToGroupVersion(scheme, TraefikSchemeGroupVersion)
	return nil
}

// TraefikMiddleware is a minimal representation of the Traefik Middleware CRD.
type TraefikMiddleware struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TraefikMiddlewareSpec `json:"spec,omitempty"`
}

func (in *TraefikMiddleware) DeepCopyObject() runtime.Object {
	out := new(TraefikMiddleware)
	*out = *in
	out.Spec = in.Spec.deepCopy()
	return out
}

// TraefikMiddlewareList contains a list of TraefikMiddleware.
type TraefikMiddlewareList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TraefikMiddleware `json:"items"`
}

func (in *TraefikMiddlewareList) DeepCopyObject() runtime.Object {
	out := new(TraefikMiddlewareList)
	*out = *in
	out.Items = make([]TraefikMiddleware, len(in.Items))
	for i := range in.Items {
		out.Items[i] = *in.Items[i].DeepCopyObject().(*TraefikMiddleware)
	}
	return out
}

// TraefikMiddlewareSpec holds the relevant subset of Traefik MiddlewareSpec fields.
type TraefikMiddlewareSpec struct {
	IPAllowList *TraefikIPAllowList `json:"ipAllowList,omitempty"`
}

func (s TraefikMiddlewareSpec) deepCopy() TraefikMiddlewareSpec {
	if s.IPAllowList == nil {
		return s
	}
	ranges := make([]string, len(s.IPAllowList.SourceRange))
	copy(ranges, s.IPAllowList.SourceRange)
	return TraefikMiddlewareSpec{IPAllowList: &TraefikIPAllowList{SourceRange: ranges}}
}

// TraefikIPAllowList holds the IP allowlist configuration.
type TraefikIPAllowList struct {
	SourceRange []string `json:"sourceRange,omitempty"`
}
