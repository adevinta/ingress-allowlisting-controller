package controllers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

// nestedJSON is a document of n nested objects around a string: {"a":{"a":..."x"...}}.
func nestedJSON(n int) string {
	return strings.Repeat(`{"a":`, n) + `"x"` + strings.Repeat(`}`, n)
}

func TestDocumentNestedDeeperThan(t *testing.T) {
	decode := func(t *testing.T, body string) interface{} {
		t.Helper()
		var data interface{}
		require.NoError(t, yaml.NewDecoder(strings.NewReader(body)).Decode(&data))
		return data
	}

	t.Run("a scalar is level 0, each map or list adds one", func(t *testing.T) {
		assert.False(t, documentNestedDeeperThan("x", 0))
		assert.False(t, documentNestedDeeperThan([]interface{}{"x"}, 1))
		assert.True(t, documentNestedDeeperThan([]interface{}{"x"}, 0))
		assert.False(t, documentNestedDeeperThan(decode(t, `{"a": [{"b": "x"}]}`), 3))
		assert.True(t, documentNestedDeeperThan(decode(t, `{"a": [{"b": "x"}]}`), 2))
	})

	t.Run("the limit is exact, for objects and lists", func(t *testing.T) {
		assert.False(t, documentNestedDeeperThan(decode(t, nestedJSON(maxDocumentDepth)), maxDocumentDepth))
		assert.True(t, documentNestedDeeperThan(decode(t, nestedJSON(maxDocumentDepth+1)), maxDocumentDepth))
		lists := func(n int) string { return strings.Repeat("[", n) + "1" + strings.Repeat("]", n) }
		assert.False(t, documentNestedDeeperThan(decode(t, lists(maxDocumentDepth)), maxDocumentDepth))
		assert.True(t, documentNestedDeeperThan(decode(t, lists(maxDocumentDepth+1)), maxDocumentDepth))
	})

	t.Run("maps with non-string keys are walked too", func(t *testing.T) {
		data := decode(t, "1:\n  2:\n  - 3\n")
		assert.IsType(t, map[interface{}]interface{}{}, data, "integer keys decode to this type")
		assert.False(t, documentNestedDeeperThan(data, 3))
		assert.True(t, documentNestedDeeperThan(data, 2))
		assert.True(t, documentNestedDeeperThan(map[interface{}]interface{}{1: map[interface{}]interface{}{2: "x"}}, 1))
	})

	t.Run("the deepest document the decoder accepts is no stack problem", func(t *testing.T) {
		assert.True(t, documentNestedDeeperThan(decode(t, nestedJSON(9999)), maxDocumentDepth))
	})
}

func TestProcessorRefusesDeepResponses(t *testing.T) {
	for name, processing := range map[string]ipamv1alpha1.Processing{
		"no expression": {},
		"cel":           {CEL: `["10.0.0.0/8"]`},
		"jsonpath":      {JSONPath: `{..a}`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := applyProcessor(strings.NewReader(nestedJSON(maxDocumentDepth+1)), processing)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "nested more than 32 levels")

			_, err = applyProcessor(strings.NewReader(nestedJSON(maxDocumentDepth)), processing)
			if err != nil {
				assert.NotContains(t, err.Error(), "nested more than", "at the limit it is not the depth that fails")
			}
		})
	}

	t.Run("a feed as deep as the real ones is fine", func(t *testing.T) {
		got, err := applyProcessor(strings.NewReader(`{"prefixes": [{"ip_prefix": "10.0.0.0/8", "region": "x"}]}`),
			ipamv1alpha1.Processing{JSONPath: `{.prefixes[*].ip_prefix}`})
		require.NoError(t, err)
		assert.Equal(t, []string{"10.0.0.0/8"}, got)
	})
}

func TestCheckJSONPathCost(t *testing.T) {
	accepted := []string{
		`{.prefixes[*].ip_prefix}`,
		`{.prefixes[?(@.service == 'EC2')].ip_prefix}`,
		`{.ips}`,
		`{..ip_prefix}`,          // one recursive descent: linear in the document
		`{.a[0,1]}`,              // a union of 2
		`{.a['x','y'].b}`,        // field names in a union
		`{[0,1,2,3,4,5,6,7]}`,    // 8 terms: the limit
		`{[0,1][0,1][0,1]}`,      // 2 x 2 x 2 = 8: the limit
		`{.a[1:3]}`,              // a slice is not a union
		`{.a[*].b[*].c}`,         // wildcards don't repeat their matches
		`{..a[?(@.b == 'x')].c}`, // a filter without a second descent
		`{.a}{.b}`,               // several blocks add up, they don't multiply
	}
	for _, expression := range accepted {
		assert.NoError(t, checkJSONPathCost(expression), expression)
	}

	rejected := map[string]string{
		`{..a..a}`:       "recursive descent (..) 2 times",
		`{..a..a..a}`:    "recursive descent (..) 3 times",
		`{..a}{..b}`:     "recursive descent (..) 2 times", // conservative: counted over the whole expression
		`{..a[?(@..b)]}`: "recursive descent (..) 2 times", // a second one inside a filter runs for every element
		// The product stops growing once it is over the limit, so it is reported as "N or more".
		`{[0,0,0][0,0,0][0,0,0]}`:       "multiply the results by 9 or more",
		`{[0,1,2,3,4,5,6,7,8]}`:         "multiply the results by 9 or more",
		`{[0,1][0,1][0,1][0,1]}`:        "multiply the results by 16 or more",
		`{.a[0,1,2].b[0,1,2].c[0,1,2]}`: "multiply the results by 9 or more",
	}
	for expression, want := range rejected {
		err := checkJSONPathCost(expression)
		require.Error(t, err, expression)
		assert.Contains(t, err.Error(), want, expression)
	}

	assert.ErrorContains(t, checkJSONPathCost(`{.a[`), "failed to parse jsonpath", "a syntax error is reported as before")
	assert.ErrorContains(t, checkJSONPathCost(`{.a[?(@.b == 'x' && @.c == 'y')]}`), "failed to parse jsonpath", "&& is not supported by the evaluator")
}

// TestProcessorRefusesExpensiveJSONPath verifies that the expression is refused before it runs, on
// a document within the depth limit: the check, not the evaluator, ends it.
func TestProcessorRefusesExpensiveJSONPath(t *testing.T) {
	body := nestedJSON(maxDocumentDepth - 2)
	for _, expression := range []string{`{..a..a..a}`, `{[0,0,0][0,0,0][0,0,0]}`} {
		_, err := applyProcessor(strings.NewReader(body), ipamv1alpha1.Processing{JSONPath: expression})
		require.Error(t, err, expression)
		assert.Contains(t, err.Error(), "jsonpath:", expression)
	}

	got, err := applyProcessor(strings.NewReader(`{"x": {"ips": ["10.0.0.0/8", "192.0.2.1"]}, "y": {"ips": ["198.51.100.0/24"]}}`),
		ipamv1alpha1.Processing{JSONPath: `{..ips[*]}`})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"10.0.0.0/8", "192.0.2.1", "198.51.100.0/24"}, got, "a single recursive descent keeps working")
}
