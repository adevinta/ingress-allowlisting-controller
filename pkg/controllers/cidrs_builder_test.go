package controllers

import (
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/google/uuid"
	v1 "k8s.io/api/core/v1"
)

type cidrBuilder struct {
	CIDRs  ipamv1alpha1.CIDRsGetter
	spec   ipamv1alpha1.CIDRsSpec
	status *ipamv1alpha1.CIDRsStatus
}

func newCIDRBuilder(cidrs ipamv1alpha1.CIDRsGetter) *cidrBuilder {
	return &cidrBuilder{
		CIDRs: cidrs,
		spec: ipamv1alpha1.CIDRsSpec{
			CIDRsSource: ipamv1alpha1.CIDRsSource{
				CIDRs: []string{"127.0.0.1/8"},
			},
		},
	}
}

func (b *cidrBuilder) build() ipamv1alpha1.CIDRsGetter {
	out := b.CIDRs.DeepCopyCIDRs()

	if out.GetName() == "" {
		out.SetName("default-" + uuid.NewString())
	}
	// TODO: only set namespace for namespaced resources
	out.SetSpec(b.spec)
	if b.status == nil {
		b.status = &ipamv1alpha1.CIDRsStatus{
			CIDRs: b.spec.CIDRsSource.CIDRs,
			State: ipamv1alpha1.CIDRsStateReady,
		}
		b.status.UpsertCondition(ipamv1alpha1.Condition{
			Type:    ipamv1alpha1.CIDRsStatusConditionTypeUpToDate,
			Status:  v1.ConditionTrue,
			Message: "All CIDRs are up to date",
		})
	}
	out.SetStatus(*b.status)
	return out
}

func (b *cidrBuilder) withName(name string) *cidrBuilder {
	b.CIDRs.SetName(name)
	return b
}

func (b *cidrBuilder) withNamespace(namespace string) *cidrBuilder {
	b.CIDRs.SetNamespace(namespace)
	return b
}

func (b *cidrBuilder) withSpec(spec ipamv1alpha1.CIDRsSpec) *cidrBuilder {
	b.spec = spec
	return b
}

func (b *cidrBuilder) withStatus(status ipamv1alpha1.CIDRsStatus) *cidrBuilder {
	b.status = &status
	return b
}

func (b *cidrBuilder) withCIDRs(cidrs []string) *cidrBuilder {
	b.spec.CIDRsSource.CIDRs = cidrs
	return b
}

func (b *cidrBuilder) withoutCIDRs() *cidrBuilder {
	b.spec.CIDRsSource.CIDRs = nil
	return b
}

func (b *cidrBuilder) withState(state ipamv1alpha1.CIDRsState) *cidrBuilder {
	if b.status == nil {
		b.status = &ipamv1alpha1.CIDRsStatus{}
	}
	b.status.State = state
	switch state {
	case ipamv1alpha1.CIDRsStateUpdateFailed:
		b.status.UpsertCondition(ipamv1alpha1.Condition{
			Type:    ipamv1alpha1.CIDRsStatusConditionTypeUpToDate,
			Status:  v1.ConditionFalse,
			Message: "Faked because of state failed for test purposed",
		})
	case ipamv1alpha1.CIDRsStateReady:
		b.status.UpsertCondition(ipamv1alpha1.Condition{
			Type:    ipamv1alpha1.CIDRsStatusConditionTypeUpToDate,
			Status:  v1.ConditionTrue,
			Message: "Faked because of state ready for test purposed",
		})
	}
	return b
}

func (b *cidrBuilder) withFetchURL(url string) *cidrBuilder {
	b.spec.CIDRsSource.Location.URI = url
	return b
}

func (b *cidrBuilder) withSecretRef(secretRef ipamv1alpha1.ObjectRef) *cidrBuilder {
	b.spec.CIDRsSource.Location.HeadersFrom = append(b.spec.CIDRsSource.Location.HeadersFrom, ipamv1alpha1.HeadersFrom{SecretRef: secretRef})
	return b
}

func (b *cidrBuilder) withConfigMapRef(configMapRef ipamv1alpha1.ObjectRef) *cidrBuilder {
	b.spec.CIDRsSource.Location.HeadersFrom = append(b.spec.CIDRsSource.Location.HeadersFrom, ipamv1alpha1.HeadersFrom{ConfigMapRef: configMapRef})
	return b
}
