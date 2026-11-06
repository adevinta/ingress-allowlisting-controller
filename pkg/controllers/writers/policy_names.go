package writers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/adevinta/ingress-allowlisting-controller/pkg/util"
)

// The names of the AuthorizationPolicies written for HTTPRoutes:
//
//	{gw}-{route}[-{fnv32(paths)}]      a route's policy in its own namespace, as since the start
//	{routeNS}.{gw}.{route}.{hash8}     a route's policy in the Gateway's namespace (cross-namespace)
//	merge.{gw}.{mergeKey}.{hash8}      a merge group's policy, in the Gateway's namespace
//
// The policies in the Gateway's namespace come from routes of every namespace, and from merge keys
// people choose. Names built only by joining their parts collide: route "x" of namespace "team-a"
// and route "a-x" of namespace "team" both gave {gw}-team-a-x, and a merge key was the whole name,
// so two Gateways of a namespace using the same key shared one policy. So these names end with
// hash8, the first 8 hex digits of a sha256 over what identifies the policy, the parts separated by
// \0: the annotation prefix (two instances with different prefixes keep their policies apart, also
// for the same merge key), the kind ("merge" is a valid namespace, so a route of namespace "merge"
// has the shape of a merged policy), and the identity, with the paths of a route's rule. The
// readable part is cut when the name would exceed 253 characters; hash8 always stays whole.

// maxNameLength is the longest name of a Kubernetes object (a DNS subdomain).
const maxNameLength = 253

// CrossNamespacePolicyName is the name of the policy of a route of namespace routeNS on Gateway gw
// of another namespace, for a rule with the given paths (none for granularity=host).
func CrossNamespacePolicyName(annotationPrefix, routeNS, gw, route string, paths []string) string {
	identity := append([]string{annotationPrefix, "route", routeNS, gw, route}, util.DedupSorted(paths)...)
	return hashedName(routeNS+"."+gw+"."+route, identity...)
}

// MergedPolicyName is the name of the policy of the merge group mergeKey on Gateway gw.
func MergedPolicyName(annotationPrefix, gw, mergeKey string) string {
	return hashedName("merge."+gw+"."+mergeKey, annotationPrefix, "merged", gw, mergeKey)
}

// hashedName is readable + "." + the hash of identity, readable cut to fit a name.
func hashedName(readable string, identity ...string) string {
	h := sha256.New()
	for i, part := range identity {
		if i > 0 {
			_, _ = h.Write([]byte{0})
		}
		_, _ = h.Write([]byte(part))
	}
	suffix := "." + hex.EncodeToString(h.Sum(nil))[:8]
	if len(readable)+len(suffix) > maxNameLength {
		// A name must not end a part with '.' or '-' before the suffix.
		readable = strings.TrimRight(readable[:maxNameLength-len(suffix)], ".-")
	}
	return readable + suffix
}

// sameNamespacePolicyName is the name of the policy of a route on a Gateway of its own namespace,
// unchanged since the start: {gw}-{route}, with -{fnv32(paths)} for a rule with paths.
func sameNamespacePolicyName(gw, route string, paths []string) string {
	return truncateName(gw + "-" + route + policyNameSuffix(paths))
}

// truncateName ensures a Kubernetes resource name stays within the 253-char limit.
// Names that fit are returned unchanged. Names that overflow are truncated to 244 chars
// and suffixed with "-{fnv32hex(fullName)}" (9 chars) to keep them collision-resistant.
func truncateName(name string) string {
	const hashSuffixLen = 9 // "-" + 8 hex chars
	if len(name) <= maxNameLength {
		return name
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	return fmt.Sprintf("%s-%08x", name[:maxNameLength-hashSuffixLen], h.Sum32())
}

// policyNameSuffix is the -{fnv32(paths)} of a same-namespace policy name, "" without paths. The
// sorted paths are joined with \0, so the rules ["/a","/b"] and ["/a/b"] get different names;
// before, the paths were written back to back and both got the same name, so the two rules
// overwrote each other's policy on every reconcile. A single path is hashed as before, so a rule
// with one path (Exact /x, PathPrefix /) keeps its name. A rule with several (PathPrefix /x gives
// /x and /x/*) gets a new name; the route's stale cleanup deletes the old one after the new one is
// written.
func policyNameSuffix(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(strings.Join(util.DedupSorted(paths), "\x00")))
	return fmt.Sprintf("-%08x", h.Sum32())
}
