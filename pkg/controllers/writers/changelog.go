package writers

import (
	"context"

	log "github.com/adevinta/go-log-toolkit"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// The writers run on every reconcile, and most of those find nothing to change. So they log at info
// only what really changed, an object created, updated or deleted, and the rest stays out of the
// way: an info line means something happened.

// logChange logs a created or updated object at info; an unchanged write is not logged.
func logChange(ctx context.Context, op controllerutil.OperationResult, kind string, obj client.Object, what string) {
	if op == controllerutil.OperationResultNone {
		return
	}
	log.DefaultLogger.WithContext(ctx).Infof("%s %s/%s %s (%s)", kind, obj.GetNamespace(), obj.GetName(), op, what)
}

// deleteLogged deletes obj and logs it at info if it existed. A missing object is not an error.
func deleteLogged(ctx context.Context, c client.Client, obj client.Object, kind, what string, opts ...client.DeleteOption) error {
	err := c.Delete(ctx, obj, opts...)
	if err == nil {
		log.DefaultLogger.WithContext(ctx).Infof("%s %s/%s deleted (%s)", kind, obj.GetNamespace(), obj.GetName(), what)
	}
	return client.IgnoreNotFound(err)
}
