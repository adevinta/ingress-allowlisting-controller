package util

import "k8s.io/apimachinery/pkg/util/sets"

// DedupSorted returns a sorted, deduplicated copy of the input slice.
func DedupSorted(items []string) []string {
	return sets.List(sets.New[string](items...))
}
