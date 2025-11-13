package v1alpha1

import (
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type (
	CIDRsStatusConditionType string
	CIDRsState               string
	// +kubebuilder:validation:Enum=CSV;YAML
	Format string
)

const (
	CIDRsStatusConditionTypeUpToDate CIDRsStatusConditionType = "UpToDate"
	CIDRsStateReady                  CIDRsState               = "Ready"
	CIDRsStateUpdateFailed           CIDRsState               = "UpdateFailed"

	// CSV indicates data is multi-line comma-separated
	CSV Format = "CSV"

	// YAML indicates data is in YAML format (default for backward compatibility)
	// it supports JSON as well  (YAML being a superset of JSON)
	YAML Format = "YAML"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type CIDRsLocation struct {
	// URI should be a URL to fetch the CIDRs from
	// remote services.
	// The response should be a JSON array of strings, or transformable to a JSON array of strings
	// through JSONPath.
	// The response status code must be 200.
	// +kubebuilder:validation:Optional
	URI string `json:"uri,omitempty" yaml:"uri,omitempty"`
	// HeadersFrom holds the names of secrets where the headers should be pulled from
	// +kubebuilder:validation:Optional
	HeadersFrom []HeadersFrom `json:"headersFrom,omitempty" yaml:"headersFrom,omitempty"`

	// Processing holds the configuration to process the response to convert it into a list of CIDR strings
	Processing `json:",inline" yaml:",inline"`
}

type Processing struct {
	// JSONPath is an expression to convert the response to a list of CIDR string
	// as expected by the CIDRs status
	// +kubebuilder:validation:Optional
	JSONPath string `json:"jsonPath,omitempty" yaml:"jsonPath,omitempty"`
	// Format specifies the format of the data
	// +kubebuilder:default=YAML
	// +optional
	Format Format `json:"format,omitempty"`
}

type CIDRsSource struct {
	// +kubebuilder:validation:Optional
	Location CIDRsLocation `json:"location,omitempty" yaml:"location,omitempty"`

	// +kubebuilder:validation:Optional
	CIDRs []string `json:"cidrs,omitempty"`
}

// CIDRsSpec defines the desired state of CIDRs
type CIDRsSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of IpAllowlistingGroup
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:Optional
	RequeueAfter *metav1.Duration `json:"requeueAfter,omitempty"`

	CIDRsSource `json:",inline" yaml:",inline"`
}

type HeadersFrom struct {
	// +kubebuilder:validation:Optional
	SecretRef ObjectRef `json:"secretRef,omitempty" yaml:"secretRef,omitempty"`
	// +kubebuilder:validation:Optional
	ConfigMapRef ObjectRef `json:"configMapRef,omitempty" yaml:"configMapRef,omitempty"`
}

type ObjectRef struct {
	Name      string `json:"name" yaml:"name"`
	Namespace string `json:"namespace" yaml:"namespace"`
}

type Condition struct {
	LastTransitionTime metav1.Time              `json:"lastTransitionTime"`
	Message            string                   `json:"message"`
	Status             v1.ConditionStatus       `json:"status,omitempty"`
	Type               CIDRsStatusConditionType `json:"type"`
}

// CIDRsStatus defines the observed state of CIDRs
type CIDRsStatus struct {
	// +kubebuilder:validation:Optional
	CIDRs []string `json:"cidrs,omitempty"`

	// +kubebuilder:validation:Optional
	LastUpdate metav1.Time `json:"lastUpdate,omitempty"`

	// +kubebuilder:validation:Optional
	State CIDRsState `json:"state,omitempty"`

	// +kubebuilder:validation:Optional
	Conditions []Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// CIDRs is the Schema for the CIDRs API
type CIDRs struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CIDRsSpec   `json:"spec,omitempty"`
	Status CIDRsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status

// ClusterCIDRs is the Schema for the ClusterCIDRs API
type ClusterCIDRs struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CIDRsSpec   `json:"spec,omitempty"`
	Status CIDRsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CIDRsList contains a list of CIDR
type CIDRsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CIDRs `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster

// ClusterCIDRsList contains a list of CIDR
type ClusterCIDRsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterCIDRs `json:"items"`
}

func (c *CIDRs) IsSubmitted() bool {
	return !c.ObjectMeta.CreationTimestamp.IsZero()
}

func (c *CIDRs) IsBeingDeleted() bool {
	return !c.ObjectMeta.DeletionTimestamp.IsZero()
}

func (c *CIDRs) SetInitialStatus() {
}

func (c *CIDRs) DeepCopyCIDRs() CIDRsGetter {
	return c.DeepCopy()
}

func (c *CIDRs) GetSpec() CIDRsSpec {
	return c.Spec
}

func (c *CIDRs) SetSpec(spec CIDRsSpec) {
	c.Spec = spec
}

func (c *ClusterCIDRs) DeepCopyCIDRs() CIDRsGetter {
	return c.DeepCopy()
}

func (c *ClusterCIDRs) GetSpec() CIDRsSpec {
	return c.Spec
}

func (c *ClusterCIDRs) SetSpec(spec CIDRsSpec) {
	c.Spec = spec
}

func (c CIDRs) GetStatus() CIDRsStatus {
	return c.Status
}

func (c ClusterCIDRs) GetStatus() CIDRsStatus {
	return c.Status
}

func (c *CIDRs) SetStatus(status CIDRsStatus) {
	c.Status = status
}

func (c *ClusterCIDRs) SetStatus(status CIDRsStatus) {
	c.Status = status
}

func (c *CIDRsList) GetCIDRsItems() []CIDRsGetter {
	items := make([]CIDRsGetter, len(c.Items))
	for i := range c.Items {
		items[i] = &c.Items[i]
	}
	return items
}

func (c *ClusterCIDRsList) GetCIDRsItems() []CIDRsGetter {
	items := make([]CIDRsGetter, len(c.Items))
	for i := range c.Items {
		items[i] = &c.Items[i]
	}
	return items
}

func (c *CIDRsList) DeepCopyCIDRs() CIDRsGetterList {
	return c.DeepCopy()
}

func (c *ClusterCIDRsList) DeepCopyCIDRs() CIDRsGetterList {
	return c.DeepCopy()
}

func (s *CIDRsStatus) UpsertCondition(condition Condition) {
	condition.LastTransitionTime = metav1.Now()
	for i, cd := range s.Conditions {
		if cd.Type == condition.Type {
			if cd.Status != condition.Status {
				s.Conditions[i] = condition
			}
			return
		}
	}
	s.Conditions = append(s.Conditions, condition)
}

func and(bs ...bool) bool {
	for _, b := range bs {
		if !b {
			return false
		}
	}
	return true
}

func init() {
	SchemeBuilder.Register(&CIDRs{}, &CIDRsList{}, &ClusterCIDRs{}, &ClusterCIDRsList{})
}

// +kubebuilder:object:generate=false
type CIDRsGetter interface {
	GetCIDRs() []string
	DeepCopyCIDRs() CIDRsGetter
	GetSpec() CIDRsSpec
	SetSpec(CIDRsSpec)
	GetStatus() CIDRsStatus
	SetStatus(CIDRsStatus)
	client.Object
}

// +kubebuilder:object:generate=false
type CIDRsGetterList interface {
	GetCIDRsItems() []CIDRsGetter
	DeepCopyCIDRs() CIDRsGetterList
	client.ObjectList
}

var (
	_ CIDRsGetter = &CIDRs{}
	_ CIDRsGetter = &ClusterCIDRs{}
)

var (
	_ CIDRsGetterList = &CIDRsList{}
	_ CIDRsGetterList = &ClusterCIDRsList{}
)

func (c *CIDRs) GetCIDRs() []string        { return c.Spec.CIDRsSource.CIDRs }
func (c *ClusterCIDRs) GetCIDRs() []string { return c.Spec.CIDRsSource.CIDRs }
