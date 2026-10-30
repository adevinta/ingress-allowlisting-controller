package v1alpha1

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestUpsertCondition verifies that the message is always the latest, while LastTransitionTime only
// changes with the status.
func TestUpsertCondition(t *testing.T) {
	past := metav1.NewTime(time.Now().Add(-time.Hour).Truncate(time.Second))
	s := CIDRsStatus{Conditions: []Condition{{
		Type: CIDRsStatusConditionTypeUpToDate, Status: v1.ConditionFalse, Message: "unexpected status code: 403", LastTransitionTime: past,
	}}}

	s.UpsertCondition(Condition{Type: CIDRsStatusConditionTypeUpToDate, Status: v1.ConditionFalse, Message: "unexpected status code: 500"})
	require.Len(t, s.Conditions, 1)
	assert.Equal(t, "unexpected status code: 500", s.Conditions[0].Message, "same status: the message is updated")
	assert.Equal(t, past, s.Conditions[0].LastTransitionTime, "same status: no transition")

	s.UpsertCondition(Condition{Type: CIDRsStatusConditionTypeUpToDate, Status: v1.ConditionTrue, Message: "All CIDRs are up to date"})
	require.Len(t, s.Conditions, 1)
	assert.Equal(t, v1.ConditionTrue, s.Conditions[0].Status)
	assert.True(t, s.Conditions[0].LastTransitionTime.After(past.Time), "status changed: new transition time")
}
