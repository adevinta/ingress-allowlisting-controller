package v1alpha1legacy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeepCopyCIDRsReturnsLegacyCIDRs(t *testing.T) {
	assert.IsType(t, &CIDRs{}, (&CIDRs{}).DeepCopyCIDRs())
	assert.IsType(t, &CIDRsList{}, (&CIDRsList{}).DeepCopyCIDRs())

	assert.IsType(t, &ClusterCIDRs{}, (&ClusterCIDRs{}).DeepCopyCIDRs())
	assert.IsType(t, &ClusterCIDRsList{}, (&ClusterCIDRsList{}).DeepCopyCIDRs())
}

func TestDeepCopyReturnsLegacyCIDRs(t *testing.T) {
	assert.IsType(t, &CIDRs{}, (&CIDRs{}).DeepCopy())
	assert.IsType(t, &CIDRsList{}, (&CIDRsList{}).DeepCopy())

	assert.IsType(t, &ClusterCIDRs{}, (&ClusterCIDRs{}).DeepCopy())
	assert.IsType(t, &ClusterCIDRsList{}, (&ClusterCIDRsList{}).DeepCopy())
}

func TestDeepCopyObjectReturnsLegacyCIDRs(t *testing.T) {
	assert.IsType(t, &CIDRs{}, (&CIDRs{}).DeepCopyObject())
	assert.IsType(t, &CIDRsList{}, (&CIDRsList{}).DeepCopyObject())

	assert.IsType(t, &ClusterCIDRs{}, (&ClusterCIDRs{}).DeepCopyObject())
	assert.IsType(t, &ClusterCIDRsList{}, (&ClusterCIDRsList{}).DeepCopyObject())
}
