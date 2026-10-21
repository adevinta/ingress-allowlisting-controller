package controllers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	log "github.com/adevinta/go-log-toolkit"
	"github.com/google/cel-go/interpreter"
)

// Guardrails for EXTERNAL (HTTP-fetched) CIDR sources.
//
// The fetch and the processing of its result run inside the single reconcile worker, so one
// source that is slow, enormous, or paired with an expensive CEL expression would otherwise stall
// every allowlist update in the cluster (and a large enough body would OOM the pod). These limits
// turn each of those into an ordinary failed fetch: the object keeps its last-known-good status
// and the reason is reported in its condition. Together with the breadth guard (cidr_breadth.go)
// they are configured through CIDRSourceOptions.
//
// They are robustness guardrails against broken or misbehaving feeds, not a defence against a
// hostile endpoint. The defaults sit above what real feeds need (AWS ip-ranges.json is ~2.7 MB;
// Google's and GitHub's are ~0.1-0.2 MB).
const (
	// defaultFetchTimeout bounds the whole fetch: connect, headers, reading the body and
	// processing it.
	defaultFetchTimeout = 30 * time.Second

	// defaultMaxResponseBytes caps how much of a response body is read. A larger body is an error
	// — never silently truncated, because a truncated list would quietly drop CIDRs from the
	// allowlist.
	//
	// The cap is what bounds memory: decoding (yaml.v3) and CEL take roughly 25-30x the body size
	// at peak (measured: 2.7 MB AWS feed ~50 MiB heap, 5 MiB body ~200 MiB RSS, 10 MiB ~315 MiB).
	// 5 MiB leaves ~2x headroom over the AWS feed and fits the chart's 256Mi limit. Raising it
	// needs a matching raise of the pod memory limit.
	defaultMaxResponseBytes int64 = 5 << 20 // 5 MiB

	// defaultRetryInterval is how soon a failed fetch is retried. Without it a failed fetch is only
	// retried on the next watch event or resync (~10h by default), so a short outage of the feed
	// would leave the allowlist stale for hours. One attempt per object every few minutes recovers
	// quickly without hammering a broken feed or the single reconcile worker.
	defaultRetryInterval = 5 * time.Minute

	// defaultCELCostLimit caps the estimated cost of one CEL evaluation (roughly: operations
	// performed). The documented AWS filter+map over a ~10,000-prefix feed costs about 130,000, so
	// this leaves ~7x headroom. An adversarial nested comprehension is aborted after well under a
	// second; at 10x this value the same expression ran for ~8s before being stopped.
	defaultCELCostLimit uint64 = 1_000_000
)

// CIDRSourceOptions configures the guardrails applied to CIDRs fetched from a remote source
// (spec.cidrsSource.location.uri). None of them apply to inline spec.cidrs.
//
// In a CIDRReconciler a zero field means "use the default", so the zero value is valid. Values
// coming from user input (flags) should go through Validate, which rejects zero and negative
// values instead of silently replacing them.
type CIDRSourceOptions struct {
	// MinMaskIPv4 / MinMaskIPv6 are the widest mask an externally-fetched prefix may use.
	MinMaskIPv4 int
	MinMaskIPv6 int
	// FetchTimeout bounds the whole fetch, including reading and processing the body.
	FetchTimeout time.Duration
	// MaxResponseBytes caps the response body; a larger body fails the fetch.
	MaxResponseBytes int64
	// CELCostLimit caps the estimated cost of one CEL evaluation.
	CELCostLimit uint64
	// RetryInterval is how soon a failed fetch is retried. An object whose spec.requeueAfter is
	// shorter is retried at that interval instead.
	RetryInterval time.Duration
	// Allowlist restricts which origins a remote source may be fetched from. Entries are
	// `scheme://host[:port]` (bare `host[:port]` means https), matched exactly after parsing.
	// Empty means any host is allowed. See cidr_source_access.go.
	Allowlist []string
	// AllowPrivateDestinations permits connections to loopback, link-local (incl. cloud metadata),
	// private and other non-public addresses. The zero value (false) keeps the guard ON.
	AllowPrivateDestinations bool
}

// DefaultCIDRSourceOptions returns the defaults used when nothing is configured.
func DefaultCIDRSourceOptions() CIDRSourceOptions {
	return CIDRSourceOptions{
		MinMaskIPv4:      defaultMinMaskIPv4,
		MinMaskIPv6:      defaultMinMaskIPv6,
		FetchTimeout:     defaultFetchTimeout,
		MaxResponseBytes: defaultMaxResponseBytes,
		CELCostLimit:     defaultCELCostLimit,
		RetryInterval:    defaultRetryInterval,
	}
}

// withDefaults replaces every unset (zero) field with its default.
func (o CIDRSourceOptions) withDefaults() CIDRSourceOptions {
	d := DefaultCIDRSourceOptions()
	if o.MinMaskIPv4 == 0 {
		o.MinMaskIPv4 = d.MinMaskIPv4
	}
	if o.MinMaskIPv6 == 0 {
		o.MinMaskIPv6 = d.MinMaskIPv6
	}
	if o.FetchTimeout == 0 {
		o.FetchTimeout = d.FetchTimeout
	}
	if o.MaxResponseBytes == 0 {
		o.MaxResponseBytes = d.MaxResponseBytes
	}
	if o.CELCostLimit == 0 {
		o.CELCostLimit = d.CELCostLimit
	}
	if o.RetryInterval == 0 {
		o.RetryInterval = d.RetryInterval
	}
	return o
}

// Validate rejects values that are out of range. Zero is rejected too: it is not a way to switch
// a protection off, and silently treating it as "default" would hide a typo from the operator.
func (o CIDRSourceOptions) Validate() error {
	var errs []error
	if o.MinMaskIPv4 < 1 || o.MinMaskIPv4 > 32 {
		errs = append(errs, fmt.Errorf("min-mask-ipv4 must be between 1 and 32, got %d", o.MinMaskIPv4))
	}
	if o.MinMaskIPv6 < 1 || o.MinMaskIPv6 > 128 {
		errs = append(errs, fmt.Errorf("min-mask-ipv6 must be between 1 and 128, got %d", o.MinMaskIPv6))
	}
	if o.FetchTimeout <= 0 {
		errs = append(errs, fmt.Errorf("fetch-timeout must be positive, got %s", o.FetchTimeout))
	}
	if o.MaxResponseBytes <= 0 {
		errs = append(errs, fmt.Errorf("max-response-bytes must be positive, got %d", o.MaxResponseBytes))
	}
	if o.CELCostLimit == 0 {
		errs = append(errs, errors.New("cel-cost-limit must be positive, got 0"))
	}
	if o.RetryInterval <= 0 {
		errs = append(errs, fmt.Errorf("retry-interval must be positive, got %s", o.RetryInterval))
	}
	if _, err := parseAllowlist(o.Allowlist); err != nil {
		errs = append(errs, fmt.Errorf("allowlist: %w", err))
	}
	return errors.Join(errs...)
}

var errResponseTooLarge = errors.New("response body too large")

// cappedBody reads from an HTTP response body but fails once more than limit bytes are seen.
//
// It records the overflow in a flag instead of relying on the error propagating through the
// parser: some decoders (yaml.v3) flatten read errors into plain strings, and a decoder could in
// principle stop early with a partial document. Callers must check exceeded() after processing,
// whatever the parser returned, so a truncated input can never be accepted as a complete one.
type cappedBody struct {
	rc        io.ReadCloser
	limit     int64
	remaining int64
	read      int64
	over      bool
}

func newCappedBody(rc io.ReadCloser, limit int64) *cappedBody {
	return &cappedBody{rc: rc, limit: limit, remaining: limit}
}

func (c *cappedBody) Read(p []byte) (int, error) {
	if c.over {
		return 0, errResponseTooLarge
	}
	if len(p) == 0 {
		return 0, nil
	}
	// Read at most one byte past the limit: that extra byte is what proves the body is too large.
	if int64(len(p)) > c.remaining+1 {
		p = p[:c.remaining+1]
	}
	n, err := c.rc.Read(p)
	c.remaining -= int64(n)
	if c.remaining < 0 {
		c.over = true
		c.read = c.limit
		return n - 1, errResponseTooLarge // hand back only the bytes within the limit
	}
	c.read += int64(n)
	return n, err
}

func (c *cappedBody) Close() error { return c.rc.Close() }

// bytesRead is how much of the body was handed to the parser.
func (c *cappedBody) bytesRead() int64 { return c.read }

// exceeded returns an error if the body was larger than the limit.
func (c *cappedBody) exceeded() error {
	if !c.over {
		return nil
	}
	return fmt.Errorf("%w: more than %d bytes", errResponseTooLarge, c.limit)
}

// fetchLimitTripped reports which guardrail, if any, made a fetch fail, together with the
// configured value that was exceeded, so operators can see both in the log.
//
// fetchCtx must be the context carrying the fetch deadline. Each limit is recognised by its own
// typed signal rather than by message text, because the parsers wrap and sometimes flatten errors.
func fetchLimitTripped(fetchCtx context.Context, err error, opts CIDRSourceOptions) (limit string, configured any, ok bool) {
	var cancelled interpreter.EvalCancelledError
	switch {
	case errors.Is(err, errResponseTooLarge):
		return "max-response-bytes", opts.MaxResponseBytes, true
	case errors.As(err, &cancelled) && cancelled.Cause == interpreter.CostLimitExceeded:
		return "cel-cost-limit", opts.CELCostLimit, true
	case errors.Is(fetchCtx.Err(), context.DeadlineExceeded):
		return "fetch-timeout", opts.FetchTimeout.String(), true
	}
	return "", nil, false
}

// LogEffective logs the guardrails in force, and warns about the permissive settings. Call it once
// at startup, so an operator can always see what a running controller is enforcing.
func (o CIDRSourceOptions) LogEffective() {
	setupLog.WithFields(map[string]interface{}{
		"minMaskIPv4":              o.MinMaskIPv4,
		"minMaskIPv6":              o.MinMaskIPv6,
		"fetchTimeout":             o.FetchTimeout.String(),
		"maxResponseBytes":         o.MaxResponseBytes,
		"celCostLimit":             o.CELCostLimit,
		"retryInterval":            o.RetryInterval.String(),
		"allowlist":                o.Allowlist,
		"allowPrivateDestinations": o.AllowPrivateDestinations,
	}).Info("remote CIDR source guardrails")
	o.warnIfPermissive()
}

// reportLimitTripped logs a failed fetch that was caused by one of the limits, naming the limit
// and the value that was exceeded, and reports whether it was one. fields identify the source.
// The error itself is still returned to the caller, which records it in the object's condition.
func reportLimitTripped(logCtx, fetchCtx context.Context, err error, opts CIDRSourceOptions, fields map[string]interface{}) bool {
	limit, configured, tripped := fetchLimitTripped(fetchCtx, err, opts)
	if !tripped {
		return false
	}
	log.DefaultLogger.WithContext(logCtx).
		WithFields(fields).
		WithField("limit", limit).
		WithField("configured", configured).
		Error(err, "; rejecting external CIDR source: limit exceeded, keeping last-known-good allowlist")
	return true
}

// logFetchCompleted records, at debug level, what one successful fetch cost.
func logFetchCompleted(logCtx context.Context, fields map[string]interface{}, body *cappedBody, elapsed time.Duration, entries int) {
	log.DefaultLogger.WithContext(logCtx).
		WithFields(fields).
		WithField("bytes", body.bytesRead()).
		WithField("elapsed", elapsed.String()).
		WithField("entries", entries).
		Debug("fetched external CIDR source")
}
