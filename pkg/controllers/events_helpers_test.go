package controllers

import (
	"testing"

	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// newTestCidrResolver returns a resolver whose Events go to a fake recorder, read with
// recordedEvents.
func newTestCidrResolver(c client.Client) resolvers.CidrResolver {
	return resolvers.CidrResolver{Client: c, AnnotationPrefix: resolvers.DefaultPrefix, Recorder: events.NewFakeRecorder(100)}
}

// recordedEvents returns the Events recorded so far by a resolver from newTestCidrResolver, as
// "<type> <reason> <note>".
func recordedEvents(t *testing.T, r resolvers.CidrResolver) []string {
	t.Helper()
	recorder, ok := r.Recorder.(*events.FakeRecorder)
	if !ok {
		t.Fatalf("resolver has no fake recorder, use newTestCidrResolver")
	}
	var recorded []string
	for {
		select {
		case e := <-recorder.Events:
			recorded = append(recorded, e)
		default:
			return recorded
		}
	}
}
