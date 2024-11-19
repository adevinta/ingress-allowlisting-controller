package v1alpha1legacy

import (
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CIDRs struct {
	ipamv1alpha1.CIDRs
}

type CIDRsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CIDRs `json:"items"`
}

type ClusterCIDRs struct {
	ipamv1alpha1.ClusterCIDRs
}
type ClusterCIDRsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterCIDRs `json:"items"`
}

func (c *CIDRsList) GetCIDRsItems() []ipamv1alpha1.CIDRsGetter {
	items := make([]ipamv1alpha1.CIDRsGetter, len(c.Items))
	for i := range c.Items {
		items[i] = &c.Items[i]
	}
	return items
}

func (c *ClusterCIDRsList) GetCIDRsItems() []ipamv1alpha1.CIDRsGetter {
	items := make([]ipamv1alpha1.CIDRsGetter, len(c.Items))
	for i := range c.Items {
		items[i] = &c.Items[i]
	}
	return items
}

func (c *CIDRs) DeepCopyCIDRs() ipamv1alpha1.CIDRsGetter {
	return &CIDRs{CIDRs: *c.CIDRs.DeepCopy()}
}

func (c *ClusterCIDRs) DeepCopyCIDRs() ipamv1alpha1.CIDRsGetter {
	return &ClusterCIDRs{ClusterCIDRs: *c.ClusterCIDRs.DeepCopy()}
}

func (c *CIDRsList) DeepCopyCIDRs() ipamv1alpha1.CIDRsGetterList {
	return c.DeepCopy()
}

func (c *ClusterCIDRsList) DeepCopyCIDRs() ipamv1alpha1.CIDRsGetterList {
	return c.DeepCopy()
}

var (
	_ ipamv1alpha1.CIDRsGetter = &CIDRs{}
	_ ipamv1alpha1.CIDRsGetter = &ClusterCIDRs{}
)

var (
	_ ipamv1alpha1.CIDRsGetterList = &CIDRsList{}
	_ ipamv1alpha1.CIDRsGetterList = &ClusterCIDRsList{}
)
