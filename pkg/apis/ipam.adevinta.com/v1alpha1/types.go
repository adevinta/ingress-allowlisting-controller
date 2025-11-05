package v1alpha1

// Format defines the format of the data returned by the HTTP source
// +kubebuilder:validation:Enum=CommaSeparatedValues;LineSeparatedValues;YAML
type Format string

const (
	// CommaSeparatedValues indicates data is comma-separated
	CommaSeparatedValues Format = "CommaSeparatedValues"

	// LineSeparatedValues indicates data is line-separated (newline delimited)
	LineSeparatedValues Format = "LineSeparatedValues"

	// YAML indicates data is in YAML format (default for backward compatibility)
	YAML Format = "YAML"
)

// Location defines where to fetch CIDRs from
type Location struct {
	// URI is the HTTP(S) URL to fetch CIDRs from
	URI string `json:"uri,omitempty"`

	// HeadersFrom references ConfigMaps and Secrets to get HTTP headers from
	HeadersFrom []HeadersFrom `json:"headersFrom,omitempty"`

	// Processing defines how to process the fetched data
	Processing Processing `json:"processing,omitempty"`
}
