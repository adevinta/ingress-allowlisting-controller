package generate

import (
	"fmt"
	"hash/fnv"
	"slices"

	netv1 "k8s.io/api/networking/v1"
)

func GenerateCIDRsHash(allValues ...any) string {
	var combined []string

	// extract items (netpol.PolicyType is not []string)
	for _, val := range allValues {
		items, ok := val.([]any)
		if !ok {
			// we support only []any
			continue
		}

		for _, item := range items {
			switch i := item.(type) {
			case []string:
				combined = append(combined, i...)
			case []netv1.PolicyType:
				for _, pt := range i {
					combined = append(combined, string(pt))
				}
			}
		}
	}

	// sort and compact (remove duplicates)
	slices.Sort(combined)
	combined = slices.Compact(combined)

	// Generate fast hash FNV-1a
	h := fnv.New64a()
	for _, v := range combined {
		h.Write([]byte(v))
	}
	return fmt.Sprintf("%x", h.Sum64())
}
