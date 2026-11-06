package controllers

// The processing of a remote source's response: the body in one of the supported formats (CSV,
// YAML/JSON with an optional JSONPath or CEL expression) turned into the list of strings that
// becomes status.cidrs once normalized (see normalizeExternalCIDRs).

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/util/jsonpath"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

func applyProcessor(reader io.Reader, processing ipamv1alpha1.Processing) ([]string, error) {
	return applyProcessorWithCostLimit(reader, processing, defaultCELCostLimit)
}

// applyProcessorWithCostLimit is applyProcessor with an explicit cap on the cost of a CEL evaluation.
func applyProcessorWithCostLimit(reader io.Reader, processing ipamv1alpha1.Processing, celCostLimit uint64) ([]string, error) {
	// Default to YAML format if not specified (backward compatibility)
	format := processing.Format
	if format == "" {
		format = ipamv1alpha1.YAML
	}

	switch format {
	// Handle simple text formats CSV/LVS
	case ipamv1alpha1.CSV:
		return processCSV(reader, processing)
	// Handle YAML format (existing logic)
	case ipamv1alpha1.YAML:
		return processYAMLFormat(reader, processing, celCostLimit)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func processCSV(reader io.Reader, processing ipamv1alpha1.Processing) ([]string, error) {
	// remove Byte Order Mark
	br := bufio.NewReader(reader)
	if b, err := br.Peek(3); err == nil && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
		_, _ = br.Discard(3)
	}
	data := csv.NewReader(br)
	data.Comment = '#'        // Ignore comments
	data.FieldsPerRecord = -1 // Disable strict field count checking
	data.LazyQuotes = true    // Allow unescaped quotes inside fields
	data.TrimLeadingSpace = true
	csvArray, err := data.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read comma-separated values: %w", err)
	}

	// Every value goes on as it is: like the YAML path, normalizeExternalCIDRs turns bare IPs into
	// host routes and counts what is neither a CIDR nor an IP.
	cidrValues := []string{}
	for _, records := range csvArray {
		for _, record := range records {
			if v := strings.TrimSpace(record); v != "" {
				cidrValues = append(cidrValues, v)
			}
		}
	}

	return cidrValues, nil
}

// processYAMLFormat handles YAML processing with optional CEL expression or JSONPath
func processYAMLFormat(reader io.Reader, processing ipamv1alpha1.Processing, celCostLimit uint64) ([]string, error) {
	var data interface{}
	err := yaml.NewDecoder(reader).Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode yaml: %w", err)
	}

	// Prefer CEL if both are specified
	if processing.CEL != "" {
		// Convert Go data to CEL value
		celData := convertToCELValue(data)

		// Determine the type based on the data structure
		var varType *cel.Type
		if _, isList := celData.([]interface{}); isList {
			varType = cel.ListType(cel.AnyType)
		} else {
			varType = cel.AnyType
		}

		// Create CEL environment
		env, err := cel.NewEnv(
			cel.Variable("data", varType),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create CEL environment: %w", err)
		}

		// Parse and type-check the expression
		ast, issues := env.Compile(processing.CEL)
		if issues != nil && issues.Err() != nil {
			return nil, fmt.Errorf("failed to compile CEL expression: %w", issues.Err())
		}

		// Create the program
		prg, err := env.Program(ast, cel.CostLimit(celCostLimit))
		if err != nil {
			return nil, fmt.Errorf("failed to create CEL program: %w", err)
		}

		// Evaluate the expression
		out, _, err := prg.Eval(map[string]interface{}{
			"data": celData,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate CEL expression: %w", err)
		}

		// Convert CEL result to list of strings
		return extractCIDRsFromCELValue(out)
	}

	// Fall back to JSONPath for backward compatibility
	if processing.JSONPath != "" {
		parser := jsonpath.New("cidrs")
		err := parser.Parse(processing.JSONPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse jsonpath: %w", err)
		}

		parser.AllowMissingKeys(true)
		results, err := parser.FindResults(data)
		if err != nil {
			return nil, fmt.Errorf("failed to find results: %w", err)
		}

		cidrValues := []string{}
		for _, result := range results {
			for _, value := range result {
				if !value.CanInterface() {
					return nil, fmt.Errorf("unexpected value type %T", value.Kind())
				}
				switch v := value.Interface().(type) {
				case []any:
					for _, item := range v {
						cidr, ok := item.(string)
						if !ok {
							return nil, fmt.Errorf("unexpected value type %T", item)
						}
						cidrValues = append(cidrValues, cidr)
					}
				case []string:
					cidrValues = append(cidrValues, v...)
				case string:
					cidrValues = append(cidrValues, v)
				default:
					return nil, fmt.Errorf("unexpected value type %T", v)
				}
			}
		}
		return cidrValues, nil
	}

	// Default YAML decoding (expecting a list of strings)
	// Decode directly from the data we already have
	if strSlice, ok := data.([]string); ok {
		return strSlice, nil
	}
	if strSlice, ok := data.([]interface{}); ok {
		result := []string{}
		for _, item := range strSlice {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result, nil
	}
	return nil, fmt.Errorf("failed to decode yaml CIDRs: expected list of strings")
}

// convertToCELValue converts Go interface{} to CEL-compatible value
func convertToCELValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[interface{}]interface{}:
		// YAML maps are map[interface{}]interface{}, convert to map[string]interface{}
		result := make(map[string]interface{})
		for k, v := range val {
			key, ok := k.(string)
			if !ok {
				key = fmt.Sprintf("%v", k)
			}
			result[key] = convertToCELValue(v)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = convertToCELValue(item)
		}
		return result
	default:
		return v
	}
}

// extractCIDRsFromCELValue extracts CIDR strings from a CEL value
func extractCIDRsFromCELValue(val ref.Val) ([]string, error) {
	cidrValues := []string{}

	// Check if it's a string
	if strVal, ok := val.(types.String); ok {
		return []string{string(strVal)}, nil
	}

	// Check if it's a list/lister
	if lister, ok := val.(traits.Lister); ok {
		iter := lister.Iterator()
		for iter.HasNext() == types.True {
			item := iter.Next()
			// Check if item is a string
			if strVal, ok := item.(types.String); ok {
				cidrValues = append(cidrValues, string(strVal))
			} else {
				// Try to get underlying Go value
				goItemVal := item.Value()
				if str, ok := goItemVal.(string); ok {
					cidrValues = append(cidrValues, str)
				} else {
					// Non-string value - this is an error
					return nil, fmt.Errorf("unexpected value type %T", goItemVal)
				}
			}
		}
		return cidrValues, nil
	}

	// Try to get the underlying Go value
	goVal := val.Value()
	if goVal == nil {
		return nil, fmt.Errorf("CEL value is nil")
	}

	// Handle Go native types
	switch v := goVal.(type) {
	case string:
		return []string{v}, nil
	case []string:
		return v, nil
	case []interface{}:
		for _, item := range v {
			if str, ok := item.(string); ok {
				cidrValues = append(cidrValues, str)
			} else {
				// Non-string value - this is an error
				return nil, fmt.Errorf("unexpected value type %T", item)
			}
		}
		return cidrValues, nil
	default:
		// Try to convert to string
		if strVal, ok := val.ConvertToType(types.StringType).(types.String); ok {
			return []string{string(strVal)}, nil
		}
		return nil, fmt.Errorf("unexpected CEL value type %T (Go value: %T)", val, goVal)
	}
}
