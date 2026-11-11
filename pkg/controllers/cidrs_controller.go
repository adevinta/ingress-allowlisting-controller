package controllers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	log "github.com/adevinta/go-log-toolkit"
	ipamv1alpha1 "github.com/adevinta/ingress-allowlisting-controller/pkg/apis/ipam.adevinta.com/v1alpha1"
	"github.com/adevinta/ingress-allowlisting-controller/pkg/resolvers"
)

// normalizeCIDR returns s as a CIDR: a CIDR as written (10.0.0.5/8 stays 10.0.0.5/8), a bare IP as
// a host route (/32 for IPv4, /128 for IPv6). ok is false if s is neither. It uses the same parser
// as the rest of the controller, so what it accepts is exactly what can be enforced.
func normalizeCIDR(s string) (cidr string, ok bool) {
	s = strings.TrimSpace(s)
	if _, _, err := net.ParseCIDR(s); err == nil {
		return s, true
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", true
		}
		return ip.String() + "/128", true
	}
	return "", false
}

// normalizeExternalCIDRs keeps the values from a remote source that are CIDRs or IPs, normalized.
// Anything else is dropped and only counted, never echoed back: status.cidrs is readable by whoever
// can read the object, so it must not become a copy of the response.
func normalizeExternalCIDRs(values []string) (cidrs []string, dropped int) {
	for _, v := range values {
		if c, ok := normalizeCIDR(v); ok {
			cidrs = append(cidrs, c)
		} else {
			dropped++
		}
	}
	return cidrs, dropped
}

// normalizeInlineCIDRs checks spec.cidrs like remote values (CIDRs kept as written, bare IPs as
// host routes) into a new slice, and returns the invalid entries. They come from the object's own
// spec, so unlike remote values they can be named in the condition.
func normalizeInlineCIDRs(values []string) (cidrs, invalid []string) {
	for _, v := range values {
		if c, ok := normalizeCIDR(v); ok {
			cidrs = append(cidrs, c)
		} else {
			invalid = append(invalid, v)
		}
	}
	return cidrs, invalid
}

// fetchFailedMessage is the condition message of a failed fetch. The last good status is kept
// whole, inline entries included, so it says that edits to spec.cidrs wait for the source too.
func fetchFailedMessage(err error, hasInline bool) string {
	message := fmt.Sprintf("Failed to get CIDRs from http source: %v", err)
	if hasInline {
		message += " (spec.cidrs changes apply once the source works again; keep inline entries in their own CIDRs object to change them independently)"
	}
	return message
}

// quoteFirst quotes the first max values, comma-separated, and says how many more there are.
func quoteFirst(values []string, max int) string {
	quoted := make([]string, 0, max)
	for _, v := range values[:min(len(values), max)] {
		quoted = append(quoted, strconv.Quote(v))
	}
	if more := len(values) - max; more > 0 {
		quoted = append(quoted, fmt.Sprintf("and %d more", more))
	}
	return strings.Join(quoted, ", ")
}

type CIDRReconciler struct {
	client.Client
	CIDRs              ipamv1alpha1.CIDRsGetter
	CIDRsList          ipamv1alpha1.CIDRsGetterList
	HTTPHeadersEnabled bool
	// SourceOptions are the guardrails applied to CIDRs fetched from a remote source: breadth
	// (minimum mask), fetch timeout, response size and CEL cost. Unset fields fall back to the
	// defaults (see cidr_fetch_limits.go). Inline spec.cidrs authored by an admin is never checked.
	SourceOptions CIDRSourceOptions
	// now is the clock for status.lastUpdate; time.Now when unset.
	now func() time.Time
}

// +kubebuilder:rbac:groups="",resources=secrets;configmaps,verbs=get;list;watch
// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs;clustercidrs,verbs=get;list;watch

// The controller writes only the status of CIDRs and ClusterCIDRs.
// +kubebuilder:rbac:groups=ipam.adevinta.com,resources=cidrs/status;clustercidrs/status,verbs=update

func (r *CIDRReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	cidrs := r.CIDRs.DeepCopyCIDRs()
	if err := r.Get(ctx, req.NamespacedName, cidrs); err != nil {
		if apierrors.IsNotFound(err) {
			forgetPending(r.kind(), req.Namespace, req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	status := cidrs.GetStatus()
	specs := cidrs.GetSpec()

	// A new slice: sorting and compacting below must not change the spec.
	var invalidInline []string
	status.CIDRs, invalidInline = normalizeInlineCIDRs(specs.CIDRsSource.CIDRs)
	requeue, raised := effectiveRequeueAfter(specs.RequeueAfter)

	opts := r.SourceOptions.withDefaults()
	remote, dropped, fetchErr := r.addHTTPSource(ctx, cidrs)
	// next is how soon a CIDR held for --cidr-source-apply-delay is due.
	var next time.Duration
	if fetchErr == nil {
		old, location := cidrs.GetStatus(), specs.CIDRsSource.Location
		held := holdAdditions(remote, status.CIDRs, old.CIDRs, old.Pending, opts.ApplyDelay, r.clock(), sourceChangedInSpec(old, location))
		logHeld(ctx, map[string]interface{}{
			"cidrs":     cidrs.GetName(),
			"namespace": cidrs.GetNamespace(),
			"uri":       redactURI(specs.CIDRsSource.Location.URI),
		}, held, opts.ApplyDelay)
		status.CIDRs = append(status.CIDRs, held.use...)
		status.Pending = held.pending
		status.SourceHash = sourceHash(location)
		next = held.next
	}
	// retry is set when a remote source did not produce a usable list, so it is fetched again soon
	// instead of waiting for the next watch event or resync.
	retry := fetchErr != nil

	if fetchErr != nil {
		status = cidrs.GetStatus()
		status.State = ipamv1alpha1.CIDRsStateUpdateFailed
		status.UpsertCondition(ipamv1alpha1.Condition{
			Type:    ipamv1alpha1.CIDRsStatusConditionTypeUpToDate,
			Status:  v1.ConditionFalse,
			Message: fetchFailedMessage(fetchErr, len(specs.CIDRsSource.CIDRs) > 0),
		})
	} else {
		// Like the condition, state says how this reconcile went: an earlier failure must not stick.
		status.State = ipamv1alpha1.CIDRsStateReady
		message := "All CIDRs are up to date"
		if specs.CIDRsSource.Location.URI == "" && len(status.CIDRs) == 0 {
			// No source and no valid inline entry: whoever wrote it means nothing is allowed. An
			// empty status would be refused below as removing all CIDRs, and the old list would
			// stay allowed, so the status says it with the deny-all address. Only the status: the
			// spec stays as written, and the next reconcile rebuilds the status from it.
			status.CIDRs = []string{resolvers.DenyAllCIDR}
			message = "spec.cidrs has no valid entry and there is no source: nothing is allowed (" + resolvers.DenyAllCIDR + ")"
		}
		if len(status.Pending) > 0 {
			message = fmt.Sprintf("%s (%s)", message, pendingMessage(status.Pending, opts.ApplyDelay))
		}
		if dropped > 0 {
			// A count, never the values: a misconfigured CEL expression stays visible without
			// echoing the response.
			message = fmt.Sprintf("%s (%d invalid entries ignored)", message, dropped)
		}
		if len(invalidInline) > 0 {
			message = fmt.Sprintf("%s (invalid entries in spec.cidrs ignored: %s)", message, quoteFirst(invalidInline, 5))
		}
		if raised {
			message = fmt.Sprintf("%s (requeueAfter %s is below the minimum, refetched every %s)", message, specs.RequeueAfter.Duration, minRequeueAfter)
		}
		status.UpsertCondition(ipamv1alpha1.Condition{
			Type:    ipamv1alpha1.CIDRsStatusConditionTypeUpToDate,
			Status:  v1.ConditionTrue,
			Message: message,
		})
	}

	sort.Strings(status.CIDRs)
	status.CIDRs = slices.Compact(status.CIDRs)

	if len(cidrs.GetStatus().CIDRs) > 0 && len(status.CIDRs) == 0 {
		// If the update consists of removing all CIDRs, we refuse to update: the last CIDRs stay
		// until the source is fixed or an admin changes the object. A feed that suddenly returns
		// nothing must not lock out the traffic it allows.
		pending, hash := status.Pending, status.SourceHash
		status = cidrs.GetStatus()
		message := "Refusing to update removing all CIDRs"
		if len(pending) > 0 {
			// The source returned only CIDRs new to it, which wait for the delay. That too can be a
			// bad response, so the last CIDRs stay as for an empty one. The new ones stay pending
			// with their clocks running: once one is due, it is used and the old ones go.
			status.Pending, status.SourceHash = pending, hash
			message = fmt.Sprintf("Refusing to update removing all CIDRs: every CIDR from the source is new, the last CIDRs are kept until then (%s)", pendingMessage(pending, opts.ApplyDelay))
		}
		status.State = ipamv1alpha1.CIDRsStateUpdateFailed
		status.UpsertCondition(ipamv1alpha1.Condition{
			Type:    ipamv1alpha1.CIDRsStatusConditionTypeUpToDate,
			Status:  v1.ConditionFalse,
			Message: message,
		})
		// A feed that briefly returns an empty list is as much a failed fetch as an error. Inline
		// spec.cidrs needs no retry: editing the object triggers a reconcile anyway.
		retry = retry || specs.CIDRsSource.Location.URI != ""
	}

	// lastUpdate is when status.cidrs last changed, not when it was last fetched (the UpToDate
	// condition says how the last fetch went): an unchanged list doesn't change the status, so it
	// isn't written again on every fetch. An object with CIDRs but no time yet (written before it
	// was set) gets the time of this reconcile.
	if old := cidrs.GetStatus(); !slices.Equal(old.CIDRs, status.CIDRs) || (status.LastUpdate.IsZero() && len(status.CIDRs) > 0) {
		status.LastUpdate = metav1.NewTime(r.clock())
	}

	cidrs.SetStatus(status)

	if err := r.Status().Update(ctx, cidrs); err != nil {
		return ctrl.Result{}, err
	}
	recordPending(r.kind(), cidrs.GetNamespace(), cidrs.GetName(), specs.CIDRsSource.Location.URI != "", status.Pending)

	after := requeue
	if retry {
		// A failed fetch would otherwise wait for the next watch event or resync (hours), so retry
		// it on a fixed interval: quick enough to recover from a short outage, slow enough not to
		// hammer a broken feed. A shorter spec.requeueAfter wins.
		after = opts.RetryInterval
		if requeue > 0 && requeue < after {
			after = requeue
		}
	}
	// A held CIDR is used by the first fetch after it is due: without spec.requeueAfter, or with a
	// longer one, that fetch would only come with the next watch event or resync.
	if next > 0 && (after == 0 || next < after) {
		after = next
	}
	return ctrl.Result{RequeueAfter: after}, nil
}

// kind is the kind of the reconciled objects, for the metric: CIDRs or ClusterCIDRs.
func (r *CIDRReconciler) kind() string {
	if _, ok := r.CIDRs.(*ipamv1alpha1.ClusterCIDRs); ok {
		return "ClusterCIDRs"
	}
	return "CIDRs"
}

func (r *CIDRReconciler) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// minRequeueAfter is the shortest spec.requeueAfter the controller honours. One worker fetches
// every remote source of a kind in turn, so an object asking for, say, 1ms would refetch its
// source (up to 5 MiB) nonstop and delay every other object's update. The CRD refuses smaller
// values too; this also covers objects created before that check, or with it not enforced.
const minRequeueAfter = time.Minute

// effectiveRequeueAfter returns how soon an object is reconciled again: spec.requeueAfter, raised
// to minRequeueAfter, or 0 when it is unset. raised says the value was raised.
func effectiveRequeueAfter(requeueAfter *metav1.Duration) (after time.Duration, raised bool) {
	if requeueAfter == nil || requeueAfter.Duration <= 0 {
		return 0, false
	}
	if requeueAfter.Duration < minRequeueAfter {
		return minRequeueAfter, true
	}
	return requeueAfter.Duration, false
}

// addHTTPSource fetches the remote source of cidrs, if it has one, and returns its CIDRs.
func (r *CIDRReconciler) addHTTPSource(ctx context.Context, cidrs ipamv1alpha1.CIDRsGetter) (remote []string, dropped int, err error) {
	spec := cidrs.GetSpec()
	if spec.CIDRsSource.Location.URI == "" {
		return nil, 0, nil
	}
	// One deadline covers the whole fetch: connect, headers, reading the body and processing it
	// (the request context also bounds body reads). Without it a slow or stalled server would hold
	// the single reconcile worker, and with it every allowlist update, indefinitely.
	opts := r.SourceOptions.withDefaults()
	logCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, opts.FetchTimeout)
	defer cancel()

	// Failures caused by a guardrail or access control are logged by the files that own them (see
	// reportPolicyDenial and reportLimitTripped), so an operator sees which control refused the
	// source and what it was set to without opening the object. The error itself still goes to the
	// caller, which records it in the condition and keeps the last-known-good status.
	start := time.Now()
	logFields := map[string]interface{}{
		"cidrs":     cidrs.GetName(),
		"namespace": cidrs.GetNamespace(),
		"uri":       redactURI(spec.CIDRsSource.Location.URI),
	}
	defer func() {
		if err == nil {
			return
		}
		if !reportPolicyDenial(logCtx, err, logFields) {
			reportLimitTripped(logCtx, ctx, err, opts, logFields)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, "GET", spec.CIDRsSource.Location.URI, nil)
	if err != nil {
		return nil, 0, redactFetchError(err) // a parse error repeats the raw URI
	}
	// Refuse a source that is not allowed before anything else happens — in particular before any
	// Secret is read for headersFrom. Redirects are checked again by the client.
	origins, err := parseAllowlist(opts.Allowlist)
	if err != nil {
		return nil, 0, err
	}
	if err := checkAllowed(origins, req.URL); err != nil {
		return nil, 0, err
	}
	// The headers read from Secrets and ConfigMaps, kept apart so that a redirect to another
	// origin can drop them.
	refHeaders := http.Header{}
	if r.HTTPHeadersEnabled {
		err = r.updateClientHeaders(ctx, cidrs.GetNamespace(), refHeaders, spec.CIDRsSource.Location.HeadersFrom)
		if err != nil {
			return nil, 0, err
		}
		for k, v := range refHeaders {
			req.Header[k] = append(req.Header[k], v...)
		}
	}
	resp, err := newSourceHTTPClient(opts, origins, slices.Collect(maps.Keys(refHeaders))).Do(req)
	if err != nil {
		return nil, 0, redactFetchError(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Cap the body before any parser sees it. The overflow is checked after processing whatever the
	// parser returned, so a truncated document can never be accepted as a complete one.
	capped := newCappedBody(resp.Body, opts.MaxResponseBytes)
	resp.Body = capped

	body, err := getHTTPResponseBody(resp)
	if err != nil {
		if overflow := capped.exceeded(); overflow != nil {
			return nil, 0, overflow
		}
		return nil, 0, err
	}

	cidrValues, err := applyProcessorWithCostLimit(body, spec.CIDRsSource.Location.Processing, opts.CELCostLimit)
	if overflow := capped.exceeded(); overflow != nil {
		return nil, 0, overflow
	}
	if err != nil {
		return nil, 0, err
	}

	// Only CIDRs and IPs reach the status; see normalizeExternalCIDRs.
	cidrValues, dropped = normalizeExternalCIDRs(cidrValues)
	if dropped > 0 {
		log.DefaultLogger.WithContext(logCtx).WithFields(logFields).
			Warnf("ignored %d entries from the CIDR source that are not CIDRs or IP addresses", dropped)
	}

	// Breadth guard against human mistakes. We trust the source itself (AWS,
	// Akamai, ...), so this is not an attacker defence — a tailor-made /32 from a
	// trusted feed is allowed by design. It runs on the CEL/JSONPath output, so it
	// only sees what the processor already selected, and rejects the fetch if a
	// misconfiguration produced a prefix wider than the minimum mask (e.g. a
	// stray 0.0.0.0/0). An admin may still allow 0.0.0.0/0 inline. Returning an
	// error here preserves the last-known-good status.
	if err := guardExternalBreadth(cidrValues, opts); err != nil {
		log.DefaultLogger.WithContext(ctx).
			WithField("cidrs", cidrs.GetName()).
			WithField("uri", redactURI(spec.CIDRsSource.Location.URI)).
			Error(err, "rejecting external CIDR source: coverage too broad, keeping last-known-good allowlist")
		return nil, 0, err
	}

	logFetchCompleted(logCtx, logFields, capped, time.Since(start), len(cidrValues))

	return cidrValues, dropped, nil
}

// resolveNamespace returns the namespace a headersFrom reference reads from: a CIDRs object's own
// namespace, or for a ClusterCIDRs (no namespace) the one --cluster-cidrs-headers-namespace allows.
// Otherwise whoever can create a ClusterCIDRs could send any Secret of the cluster as headers.
func (r *CIDRReconciler) resolveNamespace(objectNamespace string, objectRef ipamv1alpha1.ObjectRef) (string, error) {
	if objectNamespace == "" {
		allowed := r.SourceOptions.ClusterHeadersNamespace
		if allowed == "" {
			return "", fmt.Errorf("headersFrom %s: a ClusterCIDRs can't read Secrets or ConfigMaps, no --cluster-cidrs-headers-namespace is set", objectRef.Name)
		}
		if objectRef.Namespace != "" && objectRef.Namespace != allowed {
			return "", fmt.Errorf("headersFrom %s: a ClusterCIDRs may only read from namespace %s (--cluster-cidrs-headers-namespace), not %s", objectRef.Name, allowed, objectRef.Namespace)
		}
		return allowed, nil
	}
	if objectRef.Namespace != "" && objectNamespace != objectRef.Namespace {
		return "", fmt.Errorf("namespace mismatch: %s != %s", objectNamespace, objectRef.Namespace)
	}
	return objectNamespace, nil
}

func (r *CIDRReconciler) getObjectFromRef(ctx context.Context, namespace string, objectRef ipamv1alpha1.ObjectRef, dest client.Object) error {
	ns, err := r.resolveNamespace(namespace, objectRef)
	if err != nil {
		return fmt.Errorf("failed to resolve secret namespace: %w", err)
	}
	dest.SetName(objectRef.Name)
	dest.SetNamespace(ns)
	return r.Get(ctx, client.ObjectKeyFromObject(dest), dest)
}

// updateClientHeaders adds the keys of the referenced Secrets and ConfigMaps as headers: every key,
// or only an entry's keys when it lists them, so a Secret holding other credentials too sends only
// what the source needs. A listed key found in none of the entry's objects fails the fetch, rather
// than fetching without it; the error names the key and the objects, never a value. Values are
// trimmed: one stored with kubectl --from-file usually ends in a newline, and Go refuses to send a
// header value containing one, so the whole fetch would fail. A key in both the ConfigMap and the
// Secret of an entry is sent once, with the Secret's value: two values of one header (e.g.
// Authorization) are refused by many sources.
func (r *CIDRReconciler) updateClientHeaders(ctx context.Context, namespace string, headers http.Header, headersRef []ipamv1alpha1.HeadersFrom) error {
	for _, source := range headersRef {
		values := map[string]string{}
		var objects []string
		if source.ConfigMapRef.Name != "" {
			cm := &v1.ConfigMap{}
			if err := r.getObjectFromRef(ctx, namespace, source.ConfigMapRef, cm); err != nil {
				return err
			}
			for k, v := range cm.Data {
				values[k] = v
			}
			objects = append(objects, "ConfigMap "+cm.Namespace+"/"+cm.Name)
		}
		if source.SecretRef.Name != "" {
			secret := &v1.Secret{}
			if err := r.getObjectFromRef(ctx, namespace, source.SecretRef, secret); err != nil {
				return err
			}
			// After the ConfigMap: the Secret's value wins.
			for k, v := range secret.Data {
				values[k] = string(v)
			}
			objects = append(objects, "Secret "+secret.Namespace+"/"+secret.Name)
		}
		if len(source.Keys) == 0 {
			for k, v := range values {
				headers.Add(k, strings.TrimSpace(v))
			}
			continue
		}
		for _, key := range source.Keys {
			v, ok := values[key]
			if !ok {
				return fmt.Errorf("headersFrom: key %q not found in %s", key, strings.Join(objects, " or "))
			}
			headers.Add(key, strings.TrimSpace(v))
		}
	}
	return nil
}

// ignoreStatusOnlyUpdates drops updates of a CIDRs object that only changed its status. The
// controller writes that status itself, so reconciling on it would only fetch the source again, and
// with a changing condition message (e.g. a different error each time) it would loop without the
// retry interval. Spec, label and annotation changes, creates, deletes and the periodic resync
// (same resourceVersion) still reconcile.
var ignoreStatusOnlyUpdates = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		oldObj, newObj := e.ObjectOld, e.ObjectNew
		if oldObj.GetResourceVersion() == newObj.GetResourceVersion() {
			return true // periodic resync
		}
		return oldObj.GetGeneration() != newObj.GetGeneration() ||
			!maps.Equal(oldObj.GetLabels(), newObj.GetLabels()) ||
			!maps.Equal(oldObj.GetAnnotations(), newObj.GetAnnotations())
	},
}

func (r *CIDRReconciler) SetupWithManager(mgr ctrl.Manager, namePrefix string) error {
	build := ctrl.NewControllerManagedBy(mgr)
	if namePrefix != "" {
		build = build.Named(fmt.Sprintf("%s-%T", namePrefix, r.CIDRs))
	} else {
		build = build.Named(fmt.Sprintf("%T", r.CIDRs))
	}
	build = build.For(r.CIDRs, builder.WithPredicates(ignoreStatusOnlyUpdates))
	if r.HTTPHeadersEnabled {
		build = build.Watches(
			&v1.Secret{},
			handler.EnqueueRequestsFromMapFunc(
				newObjectRefToCIDRsFuncMap(
					r.Client,
					r.CIDRsList,
					secretSource,
					r.resolveNamespace,
				),
			),
		)
		build = build.Watches(
			&v1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(
				newObjectRefToCIDRsFuncMap(
					r.Client,
					r.CIDRsList,
					configMapSource,
					r.resolveNamespace,
				),
			),
		)
	}
	return build.Complete(r)
}

// getHTTPResponseBody returns the body to process. GitHub's Contents API wraps the file in a JSON
// object, with the file in "content" (base64 or plain): that is unwrapped. Every other response,
// from GitHub (e.g. /meta, list endpoints) or elsewhere, is returned unchanged. GitHub sends
// x-github-media-type: github.v3 on all of them, so the header alone doesn't tell them apart.
func getHTTPResponseBody(resp *http.Response) (io.Reader, error) {
	mediaType := strings.TrimSpace(strings.Split(resp.Header.Get("x-github-media-type"), ";")[0])
	if mediaType != "github.v3" {
		return resp.Body, nil
	}
	// The body is already capped (see addHTTPSource), so reading it into memory is bounded.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return bytes.NewReader(body), nil // not a JSON object (e.g. a list): nothing to unwrap
	}
	content, ok := response["content"]
	if !ok {
		return bytes.NewReader(body), nil
	}
	contentString, ok := content.(string)
	if !ok {
		return nil, fmt.Errorf("failed to decode github response, unexpected content type %T for message", content)
	}
	switch response["encoding"] {
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(contentString)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 content: %w", err)
		}
		return bytes.NewReader(decoded), nil
	case "", nil:
		return strings.NewReader(contentString), nil
	default:
		return nil, errors.New("unexpected encoding")
	}
}

func secretSource(headerFrom ipamv1alpha1.HeadersFrom) ipamv1alpha1.ObjectRef {
	return headerFrom.SecretRef
}

func configMapSource(headerFrom ipamv1alpha1.HeadersFrom) ipamv1alpha1.ObjectRef {
	return headerFrom.ConfigMapRef
}

// newObjectRefToCIDRsFuncMap maps a changed Secret or ConfigMap to the CIDRs objects whose
// headersFrom read it. resolve is the reconciler's resolveNamespace, so the match follows the same
// rules as the fetch (a ClusterCIDRs reads from --cluster-cidrs-headers-namespace).
func newObjectRefToCIDRsFuncMap(c client.Client, cidrsKind ipamv1alpha1.CIDRsGetterList, findRef func(headerFrom ipamv1alpha1.HeadersFrom) ipamv1alpha1.ObjectRef, resolve func(objectNamespace string, objectRef ipamv1alpha1.ObjectRef) (string, error)) handler.MapFunc {
	return func(ctx context.Context, object client.Object) []reconcile.Request {
		cidrsList := cidrsKind.DeepCopyCIDRs()
		err := c.List(ctx, cidrsList)
		if err != nil {
			// The CIDRs objects using this header source aren't refetched until their next change
			// or the resync.
			log.DefaultLogger.WithContext(ctx).Errorf("dropped change of header source %s: listing %T failed, CIDRs objects using it are not refetched until their next change or the resync: %v",
				client.ObjectKeyFromObject(object), cidrsList, err)
			return nil
		}
		var requests []reconcile.Request
		for _, cidrs := range cidrsList.GetCIDRsItems() {
			for _, source := range cidrs.GetSpec().CIDRsSource.Location.HeadersFrom {
				objectRef := findRef(source)
				namespace, err := resolve(cidrs.GetNamespace(), objectRef)
				if err != nil || namespace != object.GetNamespace() {
					continue
				}
				if object.GetName() == objectRef.Name {
					requests = append(requests, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(cidrs)})
				}
			}
		}
		return requests
	}
}
