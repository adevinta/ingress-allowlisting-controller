package writers

import (
	"context"
	"errors"
	"fmt"
	"strings"

	log "github.com/adevinta/go-log-toolkit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Every object the writers create (AuthorizationPolicies for Gateways, routes and merge groups,
// Traefik Middlewares) carries the same labels:
//
//	app.kubernetes.io/managed-by: <managed-by>   standard, informational
//	<prefix>/owner-kind:          Gateway, HTTPRoute or Merged
//	<prefix>/owner-namespace:     the owner's namespace ("MERGED" for a merge group)
//	<prefix>/owner-name:          the owner's name (the merge key for a merge group)
//
// <prefix> is --annotation-prefix. The labels under it are what makes an object ours: lists select
// by them, so a second instance with another prefix never sees, or cleans up, our objects.

// The kinds of owner, as in the owner-kind label.
const (
	OwnerKindGateway   = "Gateway"
	OwnerKindHTTPRoute = "HTTPRoute"
	OwnerKindMerged    = "Merged"
)

// mergedOwnerNamespace is the owner-namespace of a merged policy, which has no single owner route.
const mergedOwnerNamespace = "MERGED"

const managedByLabel = "app.kubernetes.io/managed-by"

func ownerKindLabel(prefix string) string      { return prefix + "/owner-kind" }
func ownerNamespaceLabel(prefix string) string { return prefix + "/owner-namespace" }
func ownerNameLabel(prefix string) string      { return prefix + "/owner-name" }

// setOwnerLabels puts the ownership labels on an object a writer creates.
func setOwnerLabels(obj client.Object, prefix, managedBy, kind, ownerNamespace, ownerName string) {
	labels := obj.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	labels[managedByLabel] = managedBy
	labels[ownerKindLabel(prefix)] = kind
	labels[ownerNamespaceLabel(prefix)] = LabelSafe(ownerNamespace)
	labels[ownerNameLabel(prefix)] = LabelSafe(ownerName)
	obj.SetLabels(labels)
}

// ownerKind is the owner-kind of an object of this instance, "" if it isn't one. Objects written
// before owner-kind existed have only owner-namespace and owner-name: a merged policy (namespace
// "MERGED") or a route's. Gateway policies had no labels then.
func ownerKind(obj client.Object, prefix string) string {
	labels := obj.GetLabels()
	if kind := labels[ownerKindLabel(prefix)]; kind != "" {
		return kind
	}
	if _, ok := labels[ownerNameLabel(prefix)]; !ok {
		return ""
	}
	if labels[ownerNamespaceLabel(prefix)] == LabelSafe(mergedOwnerNamespace) {
		return OwnerKindMerged
	}
	return OwnerKindHTTPRoute
}

// managedByUs selects the objects of this instance: managed-by, and an owner-name under our prefix.
func managedByUs(prefix, managedBy string) []client.ListOption {
	return []client.ListOption{client.MatchingLabels{managedByLabel: managedBy}, client.HasLabels{ownerNameLabel(prefix)}}
}

// ownedBy selects the objects of this instance owned by one namespace/name. Callers still check the
// kind (ownerKind): a Gateway and an HTTPRoute can share a namespace and a name.
func ownedBy(prefix, managedBy, ownerNamespace, ownerName string) []client.ListOption {
	return []client.ListOption{client.MatchingLabels{
		managedByLabel:              managedBy,
		ownerNamespaceLabel(prefix): LabelSafe(ownerNamespace),
		ownerNameLabel(prefix):      LabelSafe(ownerName),
	}}
}

// ErrPolicyNotManaged is returned when the object a writer would write already exists and is not
// ours (see isOurs): another instance's, or an admin's. The writer leaves it alone.
var ErrPolicyNotManaged = errors.New("existing policy is not managed by this controller")

// isOurs reports whether obj, found under the name a writer writes or deletes, is ours: our
// ownership labels, with this kind and owner. A writer must not touch it otherwise: names are
// predictable, so another instance, an admin or a tenant can have an object with the same name.
//
// legacyOwner is for the transition of Gateway policies, which had no labels before: one is ours
// when it has no ownership labels of any instance and the Gateway with this UID as controller.
func isOurs(obj client.Object, prefix, managedBy, kind, ownerNamespace, ownerName string, legacyOwner types.UID) bool {
	labels := obj.GetLabels()
	if labels[managedByLabel] == managedBy && ownerKind(obj, prefix) == kind &&
		labels[ownerNamespaceLabel(prefix)] == LabelSafe(ownerNamespace) && labels[ownerNameLabel(prefix)] == LabelSafe(ownerName) {
		return true
	}
	if legacyOwner == "" || hasOwnerLabels(obj) {
		return false
	}
	owner := metav1.GetControllerOf(obj)
	return owner != nil && owner.UID == legacyOwner
}

// hasOwnerLabels reports whether obj has the ownership labels of any instance, whatever its prefix.
func hasOwnerLabels(obj client.Object) bool {
	for key := range obj.GetLabels() {
		if strings.HasSuffix(key, "/owner-name") {
			return true
		}
	}
	return false
}

// notOurs is the error for an object that is not ours, for the Warning Event and the log.
func notOurs(kind string, obj client.Object, owner string) error {
	return fmt.Errorf("%w: %s %s/%s already exists and doesn't belong to %s, left as it is",
		ErrPolicyNotManaged, kind, obj.GetNamespace(), obj.GetName(), owner)
}

// deleteIfOurs deletes the object named like obj if it exists and ours reports it as ours; one
// that isn't ours is left alone. The UID precondition makes sure the object deleted is the one
// checked, not one recreated under the same name in between.
func deleteIfOurs(ctx context.Context, c client.Client, obj client.Object, ours func(client.Object) bool, kind, what string) error {
	if err := c.Get(ctx, client.ObjectKeyFromObject(obj), obj); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !ours(obj) {
		log.DefaultLogger.WithContext(ctx).Debugf("%s %s/%s is not ours, not deleted (%s)", kind, obj.GetNamespace(), obj.GetName(), what)
		return nil
	}
	uid := obj.GetUID()
	return deleteLogged(ctx, c, obj, kind, what, client.Preconditions{UID: &uid})
}

// keepKinds returns the objects whose owner-kind is one of kinds.
func keepKinds[T client.Object](objs []T, prefix string, kinds ...string) []T {
	var kept []T
	for _, obj := range objs {
		k := ownerKind(obj, prefix)
		for _, want := range kinds {
			if k == want {
				kept = append(kept, obj)
				break
			}
		}
	}
	return kept
}
