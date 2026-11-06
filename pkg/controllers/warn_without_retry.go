package controllers

import (
	"context"
	"errors"

	log "github.com/adevinta/go-log-toolkit"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// warnWithoutRetry handles what a writer can't do for a reason a person has to fix: an object
// that isn't ours (writers.ErrPolicyNotManaged), or a *writers.Warning (a missing reference, a
// setting that overrides the allowlist). It logs a warning and records a Warning Event on obj, and
// returns no error: a retry can't fix it, only a change to the objects can, and the next reconcile
// of obj (it or its CIDRs change) then tries again. Other errors are returned as they are.
func warnWithoutRetry(ctx context.Context, resolver resolvers.CidrResolver, kind string, obj client.Object, err error) error {
	reason := ""
	var warning *writers.Warning
	switch {
	case errors.As(err, &warning):
		reason = warning.Reason
	case errors.Is(err, writers.ErrPolicyNotManaged):
		reason = writers.ReasonAllowlistPolicyConflict
	default:
		return err
	}
	log.DefaultLogger.WithContext(ctx).Warnf("%s %s/%s: %v", kind, obj.GetNamespace(), obj.GetName(), err)
	resolver.WarningEvent(obj, reason, "WritePolicy", err.Error())
	return nil
}
