package writers

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
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

// MergedOwnerNamespace is the owner-namespace of a merged policy, which has no single owner route.
const MergedOwnerNamespace = "MERGED"

const managedByLabel = "app.kubernetes.io/managed-by"

// OwnerKindLabel, OwnerNamespaceLabel and OwnerNameLabel are the keys of the ownership labels
// under prefix. Use them, not the keys typed out: a typo would make the controller read an empty
// label, and treat its own objects as foreign or orphaned.
func OwnerKindLabel(prefix string) string      { return prefix + "/owner-kind" }
func OwnerNamespaceLabel(prefix string) string { return prefix + "/owner-namespace" }
func OwnerNameLabel(prefix string) string      { return prefix + "/owner-name" }

// MergeAnnotation is the key of the HTTPRoute annotation naming its merge group.
func MergeAnnotation(prefix string) string { return prefix + "/merge" }

// GranularityAnnotation is the key of the HTTPRoute annotation choosing one policy rule per route
// ("host") or per route rule (the default).
func GranularityAnnotation(prefix string) string { return prefix + "/granularity" }

// invalidLabelValue matches characters not allowed in k8s label values.
var invalidLabelValue = regexp.MustCompile(`[^-A-Za-z0-9_.]`)

// LabelSafe sanitizes a string for use as a Kubernetes label value.
// Names longer than 63 chars are truncated to 54 chars and suffixed with
// "-{fnv32hex}" to stay collision-resistant (same approach as truncateName).
func LabelSafe(s string) string {
	v := invalidLabelValue.ReplaceAllString(s, "_")
	if len(v) > 63 {
		h := fnv.New32a()
		_, _ = h.Write([]byte(s))
		v = fmt.Sprintf("%s-%08x", v[:54], h.Sum32())
	}
	return v
}

// setOwnerLabels puts the ownership labels on an object a writer creates.
func setOwnerLabels(obj client.Object, prefix, managedBy, kind, ownerNamespace, ownerName string) {
	labels := obj.GetLabels()
	if labels == nil {
		labels = map[string]string{}
	}
	labels[managedByLabel] = managedBy
	labels[OwnerKindLabel(prefix)] = kind
	labels[OwnerNamespaceLabel(prefix)] = LabelSafe(ownerNamespace)
	labels[OwnerNameLabel(prefix)] = LabelSafe(ownerName)
	obj.SetLabels(labels)
}

// ownerKind is the owner-kind of an object of this instance, "" if it isn't one. Objects written
// before owner-kind existed have only owner-namespace and owner-name: a merged policy (namespace
// "MERGED") or a route's. Gateway policies had no labels then.
func ownerKind(obj client.Object, prefix string) string {
	labels := obj.GetLabels()
	if kind := labels[OwnerKindLabel(prefix)]; kind != "" {
		return kind
	}
	if _, ok := labels[OwnerNameLabel(prefix)]; !ok {
		return ""
	}
	if labels[OwnerNamespaceLabel(prefix)] == LabelSafe(MergedOwnerNamespace) {
		return OwnerKindMerged
	}
	return OwnerKindHTTPRoute
}

// managedByUs selects the objects of this instance: managed-by, and an owner-name under our prefix.
func managedByUs(prefix, managedBy string) []client.ListOption {
	return []client.ListOption{client.MatchingLabels{managedByLabel: managedBy}, client.HasLabels{OwnerNameLabel(prefix)}}
}

// ownedBy selects the objects of this instance owned by one namespace/name. Callers still check the
// kind (ownerKind): a Gateway and an HTTPRoute can share a namespace and a name.
func ownedBy(prefix, managedBy, ownerNamespace, ownerName string) []client.ListOption {
	return []client.ListOption{client.MatchingLabels{
		managedByLabel:              managedBy,
		OwnerNamespaceLabel(prefix): LabelSafe(ownerNamespace),
		OwnerNameLabel(prefix):      LabelSafe(ownerName),
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
		labels[OwnerNamespaceLabel(prefix)] == LabelSafe(ownerNamespace) && labels[OwnerNameLabel(prefix)] == LabelSafe(ownerName) {
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
		if strings.HasSuffix(key, OwnerNameLabel("")) {
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
