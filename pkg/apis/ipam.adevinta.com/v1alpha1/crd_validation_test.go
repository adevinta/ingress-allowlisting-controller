package v1alpha1_test

import (
	"os"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
