package writers

import (
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
