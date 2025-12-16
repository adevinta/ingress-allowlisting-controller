package controllers

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/jsonpath"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

var ipv4RegExp = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}.\d{1,3}$`)

type CIDRReconciler struct {
	client.Client
	CIDRs     ipamv1alpha1.CIDRsGetter
	CIDRsList ipamv1alpha1.CIDRsGetterList
}

// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=clustercidrs,verbs=get;list;watch;create;update;patch;delete

// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs/status,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=clustercidrs/status,verbs=get;list;watch;create;update;patch;delete

func (r *CIDRReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	cidrs := r.CIDRs.DeepCopyCIDRs()
	if err := r.Get(ctx, req.NamespacedName, cidrs); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	status := cidrs.GetStatus()
	specs := cidrs.GetSpec()

	status.CIDRs = specs.CIDRsSource.CIDRs

	err := r.addHTTPSource(ctx, cidrs, &status)

	if err != nil {
		status = cidrs.GetStatus()
		status.State = ipamv1alpha1.CIDRsStateUpdateFailed
		status.UpsertCondition(ipamv1alpha1.Condition{
			Type:    ipamv1alpha1.CIDRsStatusConditionTypeUpToDate,
			Status:  v1.ConditionFalse,
			Message: fmt.Sprintf("Failed to get CIDRs from http source: %v", err),
		})
	} else {
		status.UpsertCondition(ipamv1alpha1.Condition{
			Type:    ipamv1alpha1.CIDRsStatusConditionTypeUpToDate,
			Status:  v1.ConditionTrue,
			Message: "All CIDRs are up to date",
		})
	}

	for i, cidr := range status.CIDRs {
		_, _, err := net.ParseCIDR(cidr)
		if err != nil {
			if ipv4RegExp.Match([]byte(cidr)) {
				status.CIDRs[i] = fmt.Sprintf("%s/32", cidr)
			}
		}
	}

	sort.Strings(status.CIDRs)
	status.CIDRs = slices.Compact(status.CIDRs)

	if len(cidrs.GetStatus().CIDRs) > 0 && len(status.CIDRs) == 0 {
		// If the update consists of removing all CIDRs, we refuse to update
		status = cidrs.GetStatus()
		status.State = ipamv1alpha1.CIDRsStateUpdateFailed
		status.UpsertCondition(ipamv1alpha1.Condition{
			Type:    ipamv1alpha1.CIDRsStatusConditionTypeUpToDate,
			Status:  v1.ConditionFalse,
			Message: "Refusing to update removing all CIDRs",
		})
	}

	cidrs.SetStatus(status)

	if err := r.Status().Update(ctx, cidrs); err != nil {
		return ctrl.Result{}, err
	}

	if specs.RequeueAfter != nil && specs.RequeueAfter.Duration > 0 {
		return ctrl.Result{RequeueAfter: specs.RequeueAfter.Duration, Requeue: true}, nil
	}

	return ctrl.Result{}, nil
}

func applyProcessor(reader io.Reader, processing ipamv1alpha1.Processing) ([]string, error) {
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
		return processYAMLFormat(reader, processing)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func processCSV(reader io.Reader, processing ipamv1alpha1.Processing) ([]string, error) {
	data := csv.NewReader(reader)
	data.Comment = '#'        // Ignore comments
	data.FieldsPerRecord = -1 // Disable strict field count checking
	data.LazyQuotes = true    // Allow unescaped quotes inside fields
	data.TrimLeadingSpace = true
	csvArray, err := data.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read comma-separated values: %w", err)
	}

	var cidrs []string
	for _, records := range csvArray {
		for _, record := range records {
			if record != "" {
				cidr := strings.TrimSpace(record)
				_, _, err := net.ParseCIDR(cidr)
				if err == nil {
					cidrs = append(cidrs, cidr)
				}
			}
		}
	}

	return cidrs, nil
}

// processYAMLFormat handles YAML processing with optional CEL expression or JSONPath
func processYAMLFormat(reader io.Reader, processing ipamv1alpha1.Processing) ([]string, error) {
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
		prg, err := env.Program(ast)
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
							return nil, fmt.Errorf("unexpected value type %T for %v", item, item)
						}
						cidrValues = append(cidrValues, cidr)
					}
				case []string:
					cidrValues = append(cidrValues, v...)
				case string:
					cidrValues = append(cidrValues, v)
				default:
					return nil, fmt.Errorf("unexpected value type %T for %v", v, v)
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
					return nil, fmt.Errorf("unexpected value type %T for %v", goItemVal, goItemVal)
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
				return nil, fmt.Errorf("unexpected value type %T for %v", item, item)
			}
		}
		return cidrValues, nil
	default:
		// Try to convert to string
		if strVal, ok := val.ConvertToType(types.StringType).(types.String); ok {
			return []string{string(strVal)}, nil
		}
		return nil, fmt.Errorf("unexpected CEL value type %T: %v (Go value: %T: %v)", val, val, goVal, goVal)
	}
}

func (r *CIDRReconciler) addHTTPSource(ctx context.Context, cidrs ipamv1alpha1.CIDRsGetter, status *ipamv1alpha1.CIDRsStatus) error {
	if status == nil {
		return nil
	}
	spec := cidrs.GetSpec()
	if spec.CIDRsSource.Location.URI == "" {
		return nil
	}
	req, err := http.NewRequest("GET", spec.CIDRsSource.Location.URI, nil)
	if err != nil {
		return err
	}
	err = r.updateClientHeaders(ctx, cidrs.GetNamespace(), req.Header, spec.CIDRsSource.Location.HeadersFrom)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := getHTTPResponseBody(resp)
	if err != nil {
		return err
	}

	cidrValues, err := applyProcessor(body, spec.CIDRsSource.Location.Processing)
	if err != nil {
		return err
	}
	status.CIDRs = append(status.CIDRs, cidrValues...)

	return nil
}

func (r *CIDRReconciler) resolveNamespace(objectNamespace string, objectRef ipamv1alpha1.ObjectRef) (string, error) {
	if objectNamespace == "" {
		if objectRef.Namespace == "" {
			return "", fmt.Errorf("no namespace provided. Can't resolve resolve object %s", objectRef.Name)
		}
		return objectRef.Namespace, nil
	}
	if objectRef.Namespace != "" && objectNamespace != objectRef.Namespace {
		return "", fmt.Errorf("namespace mismatch: %s != %s", objectNamespace, objectRef.Namespace)
	}
	return objectNamespace, nil
}

func (r *CIDRReconciler) getObjectFromRef(ctx context.Context, namespace string, objectRef ipamv1alpha1.ObjectRef, dest client.Object) error {
	ns, err := r.resolveNamespace(namespace, objectRef)
	if err != nil {
		return fmt.Errorf("failed to resolve secret namespace: %w", err)
	}
	dest.SetName(objectRef.Name)
	dest.SetNamespace(ns)
	return r.Get(ctx, client.ObjectKeyFromObject(dest), dest)
}

func (r *CIDRReconciler) updateClientHeaders(ctx context.Context, namespace string, headers http.Header, headersRef []ipamv1alpha1.HeadersFrom) error {
	for _, source := range headersRef {
		if source.ConfigMapRef.Name != "" {
			cm := &v1.ConfigMap{}
			err := r.getObjectFromRef(ctx, namespace, source.ConfigMapRef, cm)
			if err != nil {
				return err
			}
			for k, v := range cm.Data {
				headers.Add(k, v)
			}
		}
		if source.SecretRef.Name != "" {
			secret := &v1.Secret{}
			err := r.getObjectFromRef(ctx, namespace, source.SecretRef, secret)
			if err != nil {
				return err
			}
			for k, v := range secret.Data {
				headers.Add(k, string(v))
			}
		}
	}
	return nil
}

func (r *CIDRReconciler) SetupWithManager(mgr ctrl.Manager, namePrefix string) error {
	build := ctrl.NewControllerManagedBy(mgr)
	if namePrefix != "" {
		build = build.Named(fmt.Sprintf("%s-%T", namePrefix, r.CIDRs))
	} else {
		build = build.Named(fmt.Sprintf("%T", r.CIDRs))
	}
	build = build.For(r.CIDRs)
	build = build.Watches(
		&v1.Secret{},
		handler.EnqueueRequestsFromMapFunc(
			newObjectRefToCIDRsFuncMap(
				r.Client,
				r.CIDRsList,
				secretSource,
			),
		),
	)
	build = build.Watches(
		&v1.ConfigMap{},
		handler.EnqueueRequestsFromMapFunc(
			newObjectRefToCIDRsFuncMap(
				r.Client,
				r.CIDRsList,
				configMapSource,
			),
		),
	)
	return build.Complete(r)
}

func getHTTPResponseBody(resp *http.Response) (io.Reader, error) {
	if githubMediaTypeHeader := resp.Header.Get("x-github-media-type"); githubMediaTypeHeader != "" {
		mediaType := strings.Split(githubMediaTypeHeader, ";")[0]
		if mediaType == "github.v3" {
			response := map[string]interface{}{}
			err := json.NewDecoder(resp.Body).Decode(&response)
			if err != nil {
				return nil, fmt.Errorf("failed to decode github response: %w", err)
			}
			if content, ok := response["content"]; ok {
				contentString, ok := content.(string)
				if !ok {
					return nil, fmt.Errorf("failed to decode github response, unexpected content type %T for message", content)
				}
				switch response["encoding"] {
				case "base64":
					decoded, err := base64.StdEncoding.DecodeString(contentString)
					if err != nil {
						return nil, fmt.Errorf("failed to decode base64 content: %w", err)
					}
					return strings.NewReader(string(decoded)), nil
				case "", nil:
					return strings.NewReader(contentString), nil
				default:
					return nil, fmt.Errorf("unexpected encoding %s", response["encoding"])
				}
			}
		}
	}
	return resp.Body, nil
}

func secretSource(headerFrom ipamv1alpha1.HeadersFrom) ipamv1alpha1.ObjectRef {
	return headerFrom.SecretRef
}

func configMapSource(headerFrom ipamv1alpha1.HeadersFrom) ipamv1alpha1.ObjectRef {
	return headerFrom.ConfigMapRef
}

func newObjectRefToCIDRsFuncMap(c client.Client, cidrsKind ipamv1alpha1.CIDRsGetterList, findRef func(headerFrom ipamv1alpha1.HeadersFrom) ipamv1alpha1.ObjectRef) handler.MapFunc {
	return func(ctx context.Context, object client.Object) []reconcile.Request {
		cidrsList := cidrsKind.DeepCopyCIDRs()
		err := c.List(ctx, cidrsList)
		if err != nil {
			return nil
		}
		var requests []reconcile.Request
		for _, cidrs := range cidrsList.GetCIDRsItems() {
			for _, source := range cidrs.GetSpec().CIDRsSource.Location.HeadersFrom {
				objectRef := findRef(source)
				namespace := objectRef.Namespace
				if namespace == "" {
					namespace = cidrs.GetNamespace()
				}
				if namespace != object.GetNamespace() {
					continue
				}
				if source.SecretRef.Name == objectRef.Name {
					requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
				}
			}
		}
		return requests
	}
}
