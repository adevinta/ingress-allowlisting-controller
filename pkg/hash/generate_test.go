package generate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateCIDRsHash(t *testing.T) {

	var hash string

	// Test Empty
	hash = GenerateCIDRsHash([]any{[]string{""}})
	// python3 -c 'import fnvhash; h = fnvhash.fnv1a_64(b""); print(format(h, "x"))'
	assert.Equal(t, hash, "cbf29ce484222325")

	// Test one CIDR
	hash = GenerateCIDRsHash([]any{[]string{"127.0.0.2/32"}})
	//python3 -c 'import fnvhash; h = fnvhash.fnv1a_64(b"127.0.0.2/32"); print(format(h, "x"))'
	assert.Equal(t, hash, "1636417a7353e02d")

	// Test concatenation of CIDRs
	hash = GenerateCIDRsHash([]any{[]string{"192.168.0.0/16", "172.16.0.0/12", "172.16.0.0/12"}})
	// must be sorted and uniq
	//python3 -c 'import fnvhash; h = fnvhash.fnv1a_64(b"172.16.0.0/12192.168.0.0/16"); print(format(h, "x"))'
	assert.Equal(t, hash, "d4c558c213225d5f")

	// Test concatenation of CIDRs and types
	hash = GenerateCIDRsHash([]any{[]string{"192.168.0.0/16", "172.16.0.0/12", "172.16.0.0/12"}}, []any{[]string{"Ingress", "Egress"}})
	// must be sorted and uniq and last having types
	//python3 -c 'import fnvhash; h = fnvhash.fnv1a_64(b"172.16.0.0/12192.168.0.0/16EgressIngress"); print(format(h, "x"))'
	assert.Equal(t, hash, "483f9f981e7af2c7")

	// Test concatenation of types and CIDRs
	hash = GenerateCIDRsHash([]any{[]string{"Ingress", "Egress"}}, []any{[]string{"192.168.0.0/16", "172.16.0.0/12", "172.16.0.0/12"}})
	// must be sorted and uniq and last having types
	//python3 -c 'import fnvhash; h = fnvhash.fnv1a_64(b"172.16.0.0/12192.168.0.0/16EgressIngress"); print(format(h, "x"))'
	assert.Equal(t, hash, "483f9f981e7af2c7")
}
