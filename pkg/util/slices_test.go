package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDedupSorted(t *testing.T) {
	t.Run("deduplicates and sorts", func(t *testing.T) {
		assert.Equal(t, []string{"a", "b", "c"}, DedupSorted([]string{"c", "a", "b", "a"}))
	})

	t.Run("empty input returns empty slice", func(t *testing.T) {
		assert.Empty(t, DedupSorted([]string{}))
	})

	t.Run("single element", func(t *testing.T) {
		assert.Equal(t, []string{"x"}, DedupSorted([]string{"x"}))
	})

	t.Run("all duplicates collapses to one", func(t *testing.T) {
		assert.Equal(t, []string{"10.0.0.0/8"}, DedupSorted([]string{"10.0.0.0/8", "10.0.0.0/8", "10.0.0.0/8"}))
	})

	t.Run("no duplicates preserves all elements sorted", func(t *testing.T) {
		assert.Equal(t, []string{"1.1.1.1/32", "10.0.0.0/8", "192.168.0.0/16"}, DedupSorted([]string{"192.168.0.0/16", "10.0.0.0/8", "1.1.1.1/32"}))
	})
}
