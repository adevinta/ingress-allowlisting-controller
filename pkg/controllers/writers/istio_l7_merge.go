package writers

import (
	"context"
	"errors"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/util"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istioApiTypeV1beta1 "istio.io/api/type/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
)

// ErrPolicyNotManaged is returned when an AuthorizationPolicy with the target name already exists
// but was not created by this controller for the same purpose, so it must not be overwritten.
var ErrPolicyNotManaged = errors.New("existing policy is not managed by this controller")

// mergedTuple is a single (cidr-set, host-set, paths) entry emitted per rule during ApplyMerged grouping.
type mergedTuple struct {
	cidrKey string   // sorted joined CIDRs — group key
	hostKey string   // sorted joined hosts — group key
	cidrs   []string // original CIDRs (same order as cidrKey was built from)
	hosts   []string // original hosts (same order as hostKey was built from)
	paths   []string // paths for this rule (nil means host-only granularity)
}

// ApplyMerged creates or updates a merged AuthorizationPolicy for a merge group.
//
// Security model: routes with different CIDR sets must NOT share a `from` block,
// otherwise a CIDR allowed on one host would implicitly gain access to another host.
//
// Algorithm (two-level grouping):
//  1. For each sibling route, collect per-rule tuples: (sorted_cidrs, sorted_hosts, paths).
//     When granularity=host the route contributes one tuple (no paths); otherwise one per rule.
//  2. Group tuples by sorted_cidrs → one Istio Rule per unique CIDR set (one `from` block).
//  3. Within each CIDR group, group by sorted_hosts → one `to` Operation per unique host set.
//  4. Collect all paths from matching tuples into that Operation.
//  5. Compact `to` operations sharing the same path set into one (merging their host lists).
func (w *IstioL7Writer) ApplyMerged(ctx context.Context, gateway *gatewayApiv1.Gateway, siblings []*gatewayApiv1.HTTPRoute, mergeKey string) error {
	granularityAnnotation := w.annotationPrefix + "/granularity"

	cache := resolvers.NewResolutionCache()

	var tuples []mergedTuple
	for _, sibling := range siblings {
		ips, err := w.cidrResolver.GetCidrsFromObjectWithCache(ctx, sibling, cache)
		if err == w.cidrResolver.AnnotationNotFoundError() {
			continue
		}
		if err != nil {
			return err
		}
		if len(ips) == 0 {
			continue
		}

		sortedIPs := util.DedupSorted(ips)
		cidrKey := strings.Join(sortedIPs, ",")

		var rawHosts []string
		for _, h := range sibling.Spec.Hostnames {
			rawHosts = append(rawHosts, string(h))
		}
		hosts := util.DedupSorted(rawHosts)
		hostKey := strings.Join(hosts, ",")

		granularity := sibling.Annotations[granularityAnnotation]
		if granularity == "host" {
			tuples = append(tuples, mergedTuple{
				cidrKey: cidrKey, hostKey: hostKey,
				cidrs: sortedIPs, hosts: hosts,
				paths: nil,
			})
			continue
		}

		// granularity=rule (default): one tuple per HTTPRoute rule.
		if len(sibling.Spec.Rules) == 0 {
			tuples = append(tuples, mergedTuple{
				cidrKey: cidrKey, hostKey: hostKey,
				cidrs: sortedIPs, hosts: hosts,
				paths: nil,
			})
			continue
		}
		for _, rule := range sibling.Spec.Rules {
			paths := util.DedupSorted(w.TranslatePaths(rule.Matches))
			tuples = append(tuples, mergedTuple{
				cidrKey: cidrKey, hostKey: hostKey,
				cidrs: sortedIPs, hosts: hosts,
				paths: paths,
			})
		}
	}

	if len(tuples) == 0 {
		return nil
	}

	// Group by cidrKey preserving first-seen order.
	type hostPathGroup struct {
		paths        []string
		unrestricted bool // true if any route used granularity=host — overrides all path restrictions
	}
	type cidrGroup struct {
		cidrs    []string
		hostKeys []string
		byHost   map[string]*hostPathGroup
	}
	cidrKeys := []string{}
	byCIDR := map[string]*cidrGroup{}

	for _, t := range tuples {
		cg, exists := byCIDR[t.cidrKey]
		if !exists {
			cg = &cidrGroup{cidrs: t.cidrs, byHost: map[string]*hostPathGroup{}}
			byCIDR[t.cidrKey] = cg
			cidrKeys = append(cidrKeys, t.cidrKey)
		}
		hg, exists := cg.byHost[t.hostKey]
		if !exists {
			hg = &hostPathGroup{}
			cg.byHost[t.hostKey] = hg
			cg.hostKeys = append(cg.hostKeys, t.hostKey)
		}
		if t.paths == nil {
			hg.unrestricted = true
		} else {
			hg.paths = append(hg.paths, t.paths...)
		}
	}

	// Build Istio rules: one Rule per unique CIDR set.
	var rules []*istioApiSecurityV1.Rule
	for _, ck := range cidrKeys {
		cg := byCIDR[ck]
		rule := &istioApiSecurityV1.Rule{
			From: []*istioApiSecurityV1.Rule_From{
				{Source: &istioApiSecurityV1.Source{RemoteIpBlocks: cg.cidrs}},
			},
		}
		for _, hk := range cg.hostKeys {
			hg := cg.byHost[hk]
			var hosts []string
			if hk != "" {
				hosts = strings.Split(hk, ",")
			}
			op := &istioApiSecurityV1.Operation{}
			if len(hosts) > 0 {
				op.Hosts = hosts
			}
			if !hg.unrestricted && len(hg.paths) > 0 {
				op.Paths = util.DedupSorted(hg.paths)
			}
			if op.Hosts != nil || op.Paths != nil {
				rule.To = append(rule.To, &istioApiSecurityV1.Rule_To{Operation: op})
			}
		}
		rule.To = mergeTosByPaths(rule.To)
		rules = append(rules, rule)
	}

	// Wrap in RetryOnConflict because sibling HTTPRoutes in the same merge group can reconcile
	// concurrently: both call CreateOrUpdate on the same AuthorizationPolicy, one wins and bumps
	// resourceVersion, the other gets a 409 conflict on Update. Re-creating the policy object
	// inside the retry func ensures each attempt does a fresh Get with the latest resourceVersion.
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		policy := &istiosecurityv1.AuthorizationPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: mergeKey, Namespace: gateway.Namespace},
		}
		_, err := ctrl.CreateOrUpdate(ctx, w.client, policy, func() error {
			// The merge key is user-chosen and doubles as the AP name, so it can point at any
			// AP in the gateway namespace (e.g. an admin-authored DENY). Only the merged AP of
			// this group may be taken over; ResourceVersion is set only when the AP exists.
			if policy.ResourceVersion != "" && !w.isMergedPolicy(policy, mergeKey) {
				return fmt.Errorf("%w: AuthorizationPolicy %s/%s is not the merged policy for merge key %q",
					ErrPolicyNotManaged, policy.Namespace, policy.Name, mergeKey)
			}
			w.applyLabels(policy, "MERGED", mergeKey)
			policy.Spec = istioApiSecurityV1.AuthorizationPolicy{
				Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW,
				Rules:  rules,
				TargetRefs: []*istioApiTypeV1beta1.PolicyTargetReference{
					{Name: gateway.Name, Kind: "Gateway", Group: "gateway.networking.k8s.io"},
				},
			}
			return nil
		})
		return err
	})
}

// DeleteMerged removes the merged AuthorizationPolicy for the given merge key.
// An AP with that name that is not the merged policy of this group is left untouched.
func (w *IstioL7Writer) DeleteMerged(ctx context.Context, namespace, mergeKey string) error {
	policy := &istiosecurityv1.AuthorizationPolicy{}
	if err := w.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: mergeKey}, policy); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !w.isMergedPolicy(policy, mergeKey) {
		return nil
	}
	// The UID precondition makes sure we delete the object we just checked, not one recreated
	// under the same name in between.
	return client.IgnoreNotFound(w.client.Delete(ctx, policy, client.Preconditions{UID: &policy.UID}))
}

// isMergedPolicy reports whether the AP is the merged policy this writer created for mergeKey.
// Merged APs have no single owner route, so ownership is the group: managed by us, owner
// namespace "MERGED", owner name = the merge key (see applyLabels in ApplyMerged).
func (w *IstioL7Writer) isMergedPolicy(policy *istiosecurityv1.AuthorizationPolicy, mergeKey string) bool {
	labels := policy.GetLabels()
	return labels["app.kubernetes.io/managed-by"] == w.managedBy &&
		labels[w.annotationPrefix+"/owner-namespace"] == LabelSafe("MERGED") &&
		labels[w.annotationPrefix+"/owner-name"] == LabelSafe(mergeKey)
}

// mergeTosByPaths compacts `to` operations sharing the same path set into one, merging their host lists.
func mergeTosByPaths(tos []*istioApiSecurityV1.Rule_To) []*istioApiSecurityV1.Rule_To {
	type group struct {
		hosts []string
	}
	keys := []string{}
	byPathKey := map[string]*group{}

	for _, to := range tos {
		if to.Operation == nil {
			continue
		}
		pathKey := strings.Join(util.DedupSorted(to.Operation.Paths), ",")
		g, exists := byPathKey[pathKey]
		if !exists {
			g = &group{}
			byPathKey[pathKey] = g
			keys = append(keys, pathKey)
		}
		g.hosts = append(g.hosts, to.Operation.Hosts...)
	}

	merged := make([]*istioApiSecurityV1.Rule_To, 0, len(keys))
	for _, pathKey := range keys {
		g := byPathKey[pathKey]
		op := &istioApiSecurityV1.Operation{}
		if len(g.hosts) > 0 {
			op.Hosts = util.DedupSorted(g.hosts)
		}
		if pathKey != "" {
			op.Paths = strings.Split(pathKey, ",")
		}
		merged = append(merged, &istioApiSecurityV1.Rule_To{Operation: op})
	}
	return merged
}
