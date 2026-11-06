package v1alpha1_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsvalidation "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/validation"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	schemacel "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"sigs.k8s.io/yaml"
)

// TestRequeueAfterRuleInCRDs verifies that both generated CRDs carry the CEL rule refusing a
// requeueAfter below one minute, and evaluates it with cel-go, the library the API server uses.
func TestRequeueAfterRuleInCRDs(t *testing.T) {
	for _, file := range []string{"ipam.adevinta.com_cidrs.yaml", "ipam.adevinta.com_clustercidrs.yaml"} {
		t.Run(file, func(t *testing.T) {
			b, err := os.ReadFile("../../../../config/crd/bases/" + file)
			require.NoError(t, err)
			var crd apiextensionsv1.CustomResourceDefinition
			require.NoError(t, yaml.Unmarshal(b, &crd))
			require.Len(t, crd.Spec.Versions, 1)
			field := crd.Spec.Versions[0].Schema.OpenAPIV3Schema.Properties["spec"].Properties["requeueAfter"]
			require.Len(t, field.XValidations, 1, "requeueAfter must have its validation rule")
			rule := field.XValidations[0]
			assert.Equal(t, "requeueAfter must be at least 1m", rule.Message)

			env, err := cel.NewEnv(cel.Variable("self", cel.StringType))
			require.NoError(t, err)
			ast, issues := env.Compile(rule.Rule)
			require.NoError(t, issues.Err())
			prg, err := env.Program(ast)
			require.NoError(t, err)
			allowed := func(value string) bool {
				out, _, err := prg.Eval(map[string]any{"self": value})
				require.NoError(t, err, value)
				return out.Value().(bool)
			}
			for _, v := range []string{"1m", "60s", "15m", "1h30m"} {
				assert.True(t, allowed(v), "%s is allowed", v)
			}
			for _, v := range []string{"1ms", "59s", "0s"} {
				assert.False(t, allowed(v), "%s is refused", v)
			}
		})
	}
}

// TestSpecCIDRsRuleInCRDs verifies the CEL rule on each spec.cidrs entry with the API server's own
// code: the CRDs pass the API server's CRD validation (the rule compiles with the Kubernetes CEL
// libraries and stays within the cost limits), and an object is accepted or refused as the
// controller would use its entries. Surrounding spaces are allowed, as the controller trims them;
// IPv4-mapped IPv6 is refused.
func TestSpecCIDRsRuleInCRDs(t *testing.T) {
	for _, file := range []string{"ipam.adevinta.com_cidrs.yaml", "ipam.adevinta.com_clustercidrs.yaml"} {
		t.Run(file, func(t *testing.T) {
			ctx := context.Background()
			b, err := os.ReadFile("../../../../config/crd/bases/" + file)
			require.NoError(t, err)
			var crd apiextensionsv1.CustomResourceDefinition
			require.NoError(t, yaml.Unmarshal(b, &crd))
			internal := &apiextensions.CustomResourceDefinition{}
			require.NoError(t, apiextensionsv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&crd, internal, nil))
			// A CRD read from a file has no status; the API server sets storedVersions itself.
			internal.Status.StoredVersions = []string{internal.Spec.Versions[0].Name}
			require.Empty(t, apiextensionsvalidation.ValidateCustomResourceDefinition(ctx, internal), "the API server would accept the CRD")

			// The conversion moves the schema of the only version to spec.validation.
			require.NotNil(t, internal.Spec.Validation)
			structural, err := schema.NewStructural(internal.Spec.Validation.OpenAPIV3Schema)
			require.NoError(t, err)
			validator := schemacel.NewValidator(structural, true, celconfig.PerCallLimit)
			errorsFor := func(cidrs ...any) field.ErrorList {
				obj := map[string]any{"apiVersion": "ipam.adevinta.com/v1alpha1", "kind": crd.Spec.Names.Kind,
					"metadata": map[string]any{"name": "x"}, "spec": map[string]any{"cidrs": cidrs}}
				errs, _ := validator.Validate(ctx, field.NewPath("root"), structural, obj, nil, celconfig.RuntimeCELCostBudget)
				return errs
			}

			assert.Empty(t, errorsFor("192.0.2.0/24", "10.1.2.3/8", "198.51.100.7", "2001:db8::/32", "2001:db8::1", " 203.0.113.0/24 "),
				"CIDRs (also with host bits), IPs and surrounding spaces")
			full := make([]any, 0, 10000)
			for i := range 10000 {
				full = append(full, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
			}
			assert.Empty(t, errorsFor(full...), "a full list stays within the runtime cost budget")

			for _, bad := range []string{"10.0.0", "192.0.2.0/33", "::ffff:10.0.0.1", "::ffff:10.0.0.0/104", "fe80::1%eth0", "example.com", ""} {
				errs := errorsFor("192.0.2.0/24", bad)
				if assert.Len(t, errs, 1, "%q is refused", bad) {
					assert.Contains(t, errs[0].Error(), "spec.cidrs[1]")
					assert.Contains(t, errs[0].Error(), "must be a CIDR")
				}
			}
		})
	}
}
