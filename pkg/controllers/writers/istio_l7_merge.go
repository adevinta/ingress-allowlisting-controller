package writers

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	log "github.com/adevinta/go-log-toolkit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayApiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/util"

	istioApiSecurityV1 "istio.io/api/security/v1"
	istioApiTypeV1beta1 "istio.io/api/type/v1beta1"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
)

// validMergeKey matches a valid Kubernetes resource name: lowercase alphanumeric, '-' and '.',
// starting and ending with an alphanumeric, at most 253 chars. The merge key is part of the merged
// policy's name (see MergedPolicyName), and was the whole name before v0.3.0.
var validMergeKey = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$`)

// ValidateMergeKey returns an error if key can't be a merge key. The reconcile and the startup
// cleanup must agree on it: a route with an invalid key is handled as one without a key.
func ValidateMergeKey(key string) error {
	if !validMergeKey.MatchString(key) {
		return fmt.Errorf("merge key %q is not a valid Kubernetes resource name: must match [a-z0-9][a-z0-9-.]*[a-z0-9] and be ≤253 chars", key)
	}
	return nil
}

// inMergeMode reports whether route is in a merge group: it has a valid merge key.
func inMergeMode(route *gatewayApiv1.HTTPRoute, mergeAnnotation string) bool {
	key := route.Annotations[mergeAnnotation]
	return key != "" && ValidateMergeKey(key) == nil
}

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
	skippedNoHostnames := false
	for _, sibling := range siblings {
		// A sibling without hostnames would add a rule with no `to.hosts`, allowing its CIDRs on
		// every host of the gateway. It's left out; the rest of the group still applies.
		if len(sibling.Spec.Hostnames) == 0 {
			log.DefaultLogger.WithContext(ctx).Warnf("HTTPRoute %s/%s has no hostnames: left out of merged AuthorizationPolicy %s/%s, it would allow its CIDRs on every host of the gateway",
				sibling.Namespace, sibling.Name, gateway.Namespace, mergeKey)
			skippedNoHostnames = true
			continue
		}
		ips, err := w.cidrResolver.GetCidrsFromObjectWithCache(ctx, sibling, cache)
		if errors.Is(err, resolvers.ErrAnnotationNotFound) {
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
		// Only hostless siblings were left: an AP from before they were refused may still hold
		// their catch-all rule, so remove it rather than keep it.
		if skippedNoHostnames {
			return w.DeleteMerged(ctx, gateway, mergeKey)
		}
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
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		policy := &istiosecurityv1.AuthorizationPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: MergedPolicyName(w.annotationPrefix, gateway.Name, mergeKey), Namespace: gateway.Namespace},
		}
		op, err := createOrUpdatePolicy(ctx, w.client, policy, func() error {
			// The name is built from user-chosen parts, so an AP of that name can exist (e.g. an
			// admin-authored one). Only the merged AP of this group may be taken over;
			// ResourceVersion is set only when the AP exists.
			if policy.ResourceVersion != "" && !w.isMergedPolicy(policy, mergeKey) {
				return fmt.Errorf("%w: AuthorizationPolicy %s/%s is not the merged policy for merge key %q",
					ErrPolicyNotManaged, policy.Namespace, policy.Name, mergeKey)
			}
			// The Gateway is part of the name, so this only meets a policy named before v0.3.0, when
			// the same key on two Gateways of a namespace gave the same name: taking it over would
			// point it away from the Gateway it serves.
			if policy.ResourceVersion != "" && !servesGateway(policy, gateway) {
				return fmt.Errorf("%w: merged AuthorizationPolicy %s/%s already serves Gateway %s, use another merge key for Gateway %s",
					ErrPolicyNotManaged, policy.Namespace, policy.Name, targetGateways(policy), gateway.Name)
			}
			w.applyLabels(policy, OwnerKindMerged, mergedOwnerNamespace, mergeKey)
			policy.Spec = istioApiSecurityV1.AuthorizationPolicy{
				Action: istioApiSecurityV1.AuthorizationPolicy_ALLOW,
				Rules:  rules,
				TargetRefs: []*istioApiTypeV1beta1.PolicyTargetReference{
					{Name: gateway.Name, Kind: "Gateway", Group: "gateway.networking.k8s.io"},
				},
			}
			return nil
		})
		if err != nil {
			return err
		}
		logChange(ctx, op, "AuthorizationPolicy", policy, "merge group "+mergeKey)
		return nil
	})
	if err != nil {
		return err
	}
	return w.deleteLegacyMerged(ctx, gateway, mergeKey, "merge group "+mergeKey+": renamed to "+MergedPolicyName(w.annotationPrefix, gateway.Name, mergeKey))
}

// deleteLegacyMerged deletes the merged policy of the group under its pre-v0.3.0 name, the bare
// merge key, if it's this group's and serves this Gateway. ApplyMerged calls it once the policy
// under the new name is written, so access has no gap. Remove once no cluster runs an older version.
func (w *IstioL7Writer) deleteLegacyMerged(ctx context.Context, gateway *gatewayApiv1.Gateway, mergeKey, what string) error {
	policy := &istiosecurityv1.AuthorizationPolicy{}
	policy.Name = mergeKey
	policy.Namespace = gateway.Namespace
	ours := func(obj client.Object) bool {
		p, ok := obj.(*istiosecurityv1.AuthorizationPolicy)
		return ok && w.isMergedPolicy(p, mergeKey) && servesGateway(p, gateway)
	}
	return deleteIfOurs(ctx, w.client, policy, ours, "AuthorizationPolicy", what)
}

// DeleteMerged removes the merged AuthorizationPolicy of the gateway for the given merge key.
// An AP with that name that is not the merged policy of this group, or serves another Gateway, is
// left untouched.
func (w *IstioL7Writer) DeleteMerged(ctx context.Context, gateway *gatewayApiv1.Gateway, mergeKey string) error {
	what := "merge group " + mergeKey + " has no routes left"
	policy := &istiosecurityv1.AuthorizationPolicy{}
	policy.Name = MergedPolicyName(w.annotationPrefix, gateway.Name, mergeKey)
	policy.Namespace = gateway.Namespace
	ours := func(obj client.Object) bool {
		p, ok := obj.(*istiosecurityv1.AuthorizationPolicy)
		return ok && w.isMergedPolicy(p, mergeKey) && servesGateway(p, gateway)
	}
	if err := deleteIfOurs(ctx, w.client, policy, ours, "AuthorizationPolicy", what); err != nil {
		return err
	}
	// A group that empties before its policy was ever renamed still has the old one.
	return w.deleteLegacyMerged(ctx, gateway, mergeKey, what)
}

// ServesGateway reports whether obj, a merged AuthorizationPolicy, is the one of gateway: only its
// targetRefs say so for sure. Merged policies are listed by their labels, which name the merge key
// but not the Gateway; and before v0.3.0 a merged policy was named after its key alone, so
// Gateways of one namespace using the same key shared the name.
func (w *IstioL7Writer) ServesGateway(obj client.Object, gateway *gatewayApiv1.Gateway) bool {
	policy, ok := obj.(*istiosecurityv1.AuthorizationPolicy)
	return ok && servesGateway(policy, gateway)
}

func servesGateway(policy *istiosecurityv1.AuthorizationPolicy, gateway *gatewayApiv1.Gateway) bool {
	if policy.Namespace != gateway.Namespace {
		return false
	}
	for _, ref := range policy.Spec.TargetRefs {
		if ref.GetGroup() == gatewayApiv1.GroupName && ref.GetKind() == "Gateway" && ref.GetName() == gateway.Name {
			return true
		}
	}
	return false
}

// targetGateways names the Gateways policy targets, for messages.
func targetGateways(policy *istiosecurityv1.AuthorizationPolicy) string {
	var names []string
	for _, ref := range policy.Spec.TargetRefs {
		names = append(names, ref.GetName())
	}
	return strings.Join(names, ",")
}

// isMergedPolicy reports whether the AP is the merged policy this writer created for mergeKey.
// Merged APs have no single owner route, so ownership is the group: managed by us, owner
// namespace "MERGED", owner name = the merge key (see applyLabels in ApplyMerged).
func (w *IstioL7Writer) isMergedPolicy(policy *istiosecurityv1.AuthorizationPolicy, mergeKey string) bool {
	labels := policy.GetLabels()
	return labels[managedByLabel] == w.managedBy &&
		ownerKind(policy, w.annotationPrefix) == OwnerKindMerged &&
		labels[ownerNameLabel(w.annotationPrefix)] == LabelSafe(mergeKey)
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
