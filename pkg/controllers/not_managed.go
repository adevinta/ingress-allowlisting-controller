package controllers

import (
	"context"
	"errors"

	log "github.com/adevinta/go-log-toolkit"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/controllers/writers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// policyConflictReason is the reason of the Warning Event when the policy or Middleware an object
// needs already exists and isn't ours.
const policyConflictReason = "AllowlistPolicyConflict"

// notManaged handles a writer refusing to touch an object that isn't ours
// (writers.ErrPolicyNotManaged): a log warning and a Warning Event on obj, and no error. A retry
// can't fix the conflict, only removing or renaming one of the objects can, and the next reconcile
// of obj (it or its CIDRs change) then writes the allowlist. Other errors are returned as they are.
func notManaged(ctx context.Context, resolver resolvers.CidrResolver, kind string, obj client.Object, err error) error {
	if !errors.Is(err, writers.ErrPolicyNotManaged) {
		return err
	}
	log.DefaultLogger.WithContext(ctx).Warnf("%s %s/%s: %v", kind, obj.GetNamespace(), obj.GetName(), err)
	resolver.WarningEvent(obj, policyConflictReason, "WritePolicy", err.Error())
	return nil
}
