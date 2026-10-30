//go:build functional

package functional

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
)

const (
	// missingSourceURI is a path that doesn't exist on an allowlisted host: the fetch fails with 403.
	missingSourceURI = "https://ip-ranges.amazonaws.com/iac-functional-missing.json"
	// refusedSourceURI is on a host that is not in the controller's --cidr-source-allowlist: the
	// controller refuses it before any request, with its own error.
	refusedSourceURI = "https://not-allowed.iac-functional.invalid/cidrs.json"
	// statusQuietPeriod is how long the object's status must stay unchanged once the condition is
	// settled. A controller reconciling on its own status writes would change it many times a
	// second; a legitimate retry only comes after --cidr-source-retry-interval (5m by default).
	statusQuietPeriod = 20 * time.Second
)

// failedCondition returns the UpToDate condition if it is False.
func failedCondition(obj *ipamv1alpha1.CIDRs) (ipamv1alpha1.Condition, bool) {
	for _, cond := range obj.Status.Conditions {
		if cond.Type == ipamv1alpha1.CIDRsStatusConditionTypeUpToDate {
			return cond, cond.Status == v1.ConditionFalse
		}
	}
	return ipamv1alpha1.Condition{}, false
}

// waitFailedWith waits until the UpToDate condition is False with a message containing want, and
// returns the object.
func waitFailedWith(t *testing.T, ctx context.Context, c client.Client, ns, name, want string) *ipamv1alpha1.CIDRs {
	t.Helper()
	var obj *ipamv1alpha1.CIDRs
	eventually(t, fmt.Sprintf("CIDRs %s/%s failed with %q", ns, name, want), func() (bool, string) {
		got, err := getCIDRs(ctx, c, ns, name)
		if err != nil {
			return false, err.Error()
		}
		obj = got
		cond, failed := failedCondition(got)
		return failed && strings.Contains(cond.Message, want), fmt.Sprintf("UpToDate=%s: %s", cond.Status, cond.Message)
	})
	return obj
}

// runConditionScenario checks that the UpToDate condition follows the latest error, and that the
// controller's own status write doesn't make it reconcile again (no status churn).
func runConditionScenario(t *testing.T, ctx context.Context, c client.Client, ns string, controller controllerInfo) {
	if !controller.allowsOrigin(missingSourceURI) {
		t.Skipf("the controller's --cidr-source-allowlist doesn't allow %s", missingSourceURI)
	}
	if controller.allowsOrigin(refusedSourceURI) {
		t.Skip("the controller's --cidr-source-allowlist is empty, so no source is refused")
	}
	const name = "failing-source"
	spec := ipamv1alpha1.CIDRsSpec{CIDRsSource: ipamv1alpha1.CIDRsSource{
		Location: ipamv1alpha1.CIDRsLocation{URI: missingSourceURI},
	}}
	if err := createCIDRs(ctx, c, ns, name, spec); err != nil {
		t.Fatalf("creating CIDRs %s: %v", name, err)
	}

	t.Run("first-error", func(t *testing.T) {
		waitFailedWith(t, ctx, c, ns, name, "403")
	})

	t.Run("latest-error", func(t *testing.T) {
		// Still failing, for another reason: the condition must show the new error, not keep the 403.
		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			obj, err := getCIDRs(ctx, c, ns, name)
			if err != nil {
				return err
			}
			obj.Spec.CIDRsSource.Location.URI = refusedSourceURI
			return c.Update(ctx, obj)
		})
		if err != nil {
			t.Fatalf("changing the source of %s: %v", name, err)
		}
		obj := waitFailedWith(t, ctx, c, ns, name, "source not in allowlist")
		if cond, _ := failedCondition(obj); strings.Contains(cond.Message, "403") {
			t.Fatalf("the condition still shows the first error: %s", cond.Message)
		}
	})

	t.Run("no-status-churn", func(t *testing.T) {
		before, err := getCIDRs(ctx, c, ns, name)
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(statusQuietPeriod)
		for time.Now().Before(deadline) {
			time.Sleep(pollInterval)
			now, err := getCIDRs(ctx, c, ns, name)
			if err != nil {
				t.Fatal(err)
			}
			if now.ResourceVersion != before.ResourceVersion {
				cond, _ := failedCondition(now)
				t.Fatalf("the status keeps changing although nothing else did (resourceVersion %s -> %s, condition: %s): the controller reconciles on its own status writes",
					before.ResourceVersion, now.ResourceVersion, cond.Message)
			}
		}
	})
}
