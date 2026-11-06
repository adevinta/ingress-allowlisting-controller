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

type CIDRsLocation struct {
	// URI should be a URL to fetch the CIDRs from
	// remote services.
	// The response should be a JSON array of strings, or transformable to a JSON array of strings
	// through CEL (Common Expression Language).
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
	// CEL is a Common Expression Language expression to convert the response to a list of CIDR string
	// as expected by the CIDRs status. The expression should evaluate to a list of strings or a single string.
	// The input data is available as the variable 'data' in the CEL expression.
	// Examples:
	//   - data.ips (access a field)
	//   - data.prefixes.filter(p, p.service == 'EC2').map(p, p.ip_prefix) (filter and map)
	//   - data (return the data as-is if it's already a list of strings)
	// If both CEL and JSONPath are specified, CEL takes precedence.
	// +kubebuilder:validation:Optional
	CEL string `json:"cel,omitempty" yaml:"cel,omitempty"`
	// JSONPath is a JSONPath expression to convert the response to a list of CIDR string
	// as expected by the CIDRs status. This is deprecated in favor of CEL but kept for backward compatibility.
	// Note: JSONPath has limited support for complex expressions (e.g., && operator may not work).
	// For complex filtering, use CEL instead.
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

	// CIDRs are CIDRs or IP addresses (an IP becomes a /32 or /128), at most 10000 entries of at
	// most 64 characters. Each entry is checked when the object is written, so a typo is refused
	// by the API server instead of being ignored later. Surrounding spaces are allowed;
	// IPv4-mapped IPv6 (::ffff:a.b.c.d) is not: write a.b.c.d. Needs Kubernetes 1.32 or later.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=10000
	// +kubebuilder:validation:items:MaxLength=64
	// +kubebuilder:validation:items:XValidation:rule="isCIDR(self.trim()) || isIP(self.trim())",message="must be a CIDR (e.g. 192.0.2.0/24) or an IP address; write IPv4 addresses as a.b.c.d, not ::ffff:a.b.c.d"
	CIDRs []string `json:"cidrs,omitempty"`
}

// CIDRsSpec defines the desired state of CIDRs
type CIDRsSpec struct {
	// RequeueAfter is how often a remote source is fetched again (e.g. 15m). At least 1m: one worker
	// fetches every source in turn, so a shorter interval would delay every other object.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:XValidation:rule="duration(self) >= duration('1m')",message="requeueAfter must be at least 1m"
	RequeueAfter *metav1.Duration `json:"requeueAfter,omitempty"`

	CIDRsSource `json:",inline" yaml:",inline"`
}

type HeadersFrom struct {
	// +kubebuilder:validation:Optional
	SecretRef ObjectRef `json:"secretRef,omitempty" yaml:"secretRef,omitempty"`
	// +kubebuilder:validation:Optional
	ConfigMapRef ObjectRef `json:"configMapRef,omitempty" yaml:"configMapRef,omitempty"`
	// Keys, when set, are the only keys of the Secret or ConfigMap sent as headers (the key is the
	// header name). A key that isn't there fails the fetch. Without it, every key is sent. A key in
	// both the ConfigMap and the Secret is sent once, with the Secret's value.
	// +kubebuilder:validation:Optional
	// +listType=set
	Keys []string `json:"keys,omitempty" yaml:"keys,omitempty"`
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

	// LastUpdate is when cidrs last changed. A fetch that returns the same list doesn't change it:
	// see the UpToDate condition for how the last fetch went.
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

// UpsertCondition sets the condition of its type, always with the latest message. As for
// Kubernetes conditions, LastTransitionTime only changes when the status does.
func (s *CIDRsStatus) UpsertCondition(condition Condition) {
	for i, cd := range s.Conditions {
		if cd.Type == condition.Type {
			if cd.Status == condition.Status {
				condition.LastTransitionTime = cd.LastTransitionTime
			} else {
				condition.LastTransitionTime = metav1.Now()
			}
			s.Conditions[i] = condition
			return
		}
	}
	condition.LastTransitionTime = metav1.Now()
	s.Conditions = append(s.Conditions, condition)
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
