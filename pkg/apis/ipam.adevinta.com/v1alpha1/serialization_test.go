package v1alpha1_test

import (
	"bytes"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/kubectl/pkg/scheme"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSerialization(t *testing.T) {
	cidr := v1alpha1.CIDRs{
		Spec: v1alpha1.CIDRsSpec{
			CIDRsSource: v1alpha1.CIDRsSource{
				CIDRs: []string{"127.0.0.1/24"},
			},
		},
	}
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	buffer := &bytes.Buffer{}

	require.NoError(t, serializer.NewCodecFactory(scheme).WithoutConversion().EncoderForVersion(
		json.NewSerializerWithOptions(
			json.DefaultMetaFactory,
			scheme,
			scheme,
			json.SerializerOptions{
				Yaml:   false,
				Strict: true,
				Pretty: false,
			}),
		nil,
	).Encode(&cidr, buffer))

	assert.JSONEq(t, `{"kind":"CIDRs","apiVersion":"ipam.adevinta.com/v1alpha1","metadata":{"creationTimestamp":null},"spec":{"location":{},"cidrs":["127.0.0.1/24"]}, "status":{"lastUpdate":null}}`, buffer.String())
}

func TestDeserialization(t *testing.T) {
	serialized := `apiVersion: ipam.adevinta.com/v1alpha1
kind: CIDRs
spec:
  cidrs:
  - 127.0.0.1/24
`

	cidrs := v1alpha1.CIDRs{}
	object, _, err := scheme.Codecs.UniversalDeserializer().Decode([]byte(serialized), nil, &cidrs)
	require.NoError(t, err)
	assert.Equal(
		t,
		&v1alpha1.CIDRs{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "ipam.adevinta.com/v1alpha1",
				Kind:       "CIDRs",
			},
			Spec: v1alpha1.CIDRsSpec{
				CIDRsSource: v1alpha1.CIDRsSource{
					CIDRs: []string{"127.0.0.1/24"},
				},
			},
		},
		object,
	)
}

func TestClusterCIDRsSerialization(t *testing.T) {
	cidr := v1alpha1.ClusterCIDRs{
		Spec: v1alpha1.CIDRsSpec{
			CIDRsSource: v1alpha1.CIDRsSource{
				CIDRs: []string{"127.0.0.1/24"},
			},
		},
	}
	scheme := runtime.NewScheme()

	require.NoError(t, v1alpha1.AddToScheme(scheme))

	buffer := &bytes.Buffer{}

	require.NoError(t, serializer.NewCodecFactory(scheme).WithoutConversion().EncoderForVersion(
		json.NewSerializerWithOptions(
			json.DefaultMetaFactory,
			scheme,
			scheme,
			json.SerializerOptions{
				Yaml:   false,
				Strict: true,
				Pretty: false,
			}),
		nil,
	).Encode(&cidr, buffer))

	assert.JSONEq(t, `{"kind":"ClusterCIDRs","apiVersion":"ipam.adevinta.com/v1alpha1","metadata":{"creationTimestamp":null},"spec":{"location":{},"cidrs":["127.0.0.1/24"]}, "status":{"lastUpdate":null}}`, buffer.String())
}

func TestClusterCIDRsDeserialization(t *testing.T) {
	serialized := `apiVersion: ipam.adevinta.com/v1alpha1
kind: ClusterCIDRs
spec:
  cidrs:
  - 127.0.0.1/24
`

	cidrs := v1alpha1.ClusterCIDRs{}
	object, _, err := scheme.Codecs.UniversalDeserializer().Decode([]byte(serialized), nil, &cidrs)
	require.NoError(t, err)
	assert.Equal(
		t,
		&v1alpha1.ClusterCIDRs{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "ipam.adevinta.com/v1alpha1",
				Kind:       "ClusterCIDRs",
			},
			Spec: v1alpha1.CIDRsSpec{
				CIDRsSource: v1alpha1.CIDRsSource{
					CIDRs: []string{"127.0.0.1/24"},
				},
			},
		},
		object,
	)
}
