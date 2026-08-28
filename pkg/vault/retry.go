package vault

import (
	"context"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"syscall"
	"time"
)

const (
	// retryAttempts caps the wire requests one throttled read may cost.
	retryAttempts = 3
	// retryBackoffBase is the first backoff; each retry doubles it, and
	// jitter spreads a fan-out's retries so they do not re-arrive as the
	// same burst that drew the 429.
	retryBackoffBase = 100 * time.Millisecond
	// retryAfterCap clamps the wait actually slept once it has already
	// been checked against the request's own deadline (see
	// fitsBeforeDeadline): a value comfortably below the client timeout,
	// so honoring a header never itself risks the timeout.
	retryAfterCap = 5 * time.Second
	// retryMinHeadroom is how much time a wait must leave on the request's
	// deadline, after the sleep, for one more wire attempt to be worth
	// dispatching. Below that, retrying only trades an honest 429 for an
	// opaque "context deadline exceeded".
	retryMinHeadroom = 2 * time.Second
)

// retryTransport retries throttled reads against the tuned transport it
// wraps. Its scope is deliberately narrow:
//
//   - GET requests only. vaultkv lists with a GET and a `list=true` query
//     parameter, which this arm already covers; there is no separate LIST
//     method to admit. Writes are never retried here: replaying a PUT
//     would surface check-and-set conflicts from the wrong layer, and
//     POST/DELETE are not idempotent.
//   - On HTTP 429, and on connection-refused/connection-reset transport
//     errors, which fail before Vault processes anything.
//   - Never on 503: a sealed or unavailable Vault must surface
//     immediately, not hide behind sleeps.
type retryTransport struct {
	next http.RoundTripper
	// sleep waits out one backoff; a seam so tests assert requested waits
	// instead of serving them.
	sleep func(ctx context.Context, d time.Duration) error
}

func newRetryTransport(next http.RoundTripper) *retryTransport {
	return &retryTransport{next: next, sleep: sleepBackoff}
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// The body guard is belt-and-braces: vaultkv's GETs carry no body, and
	// a consumed body could not be replayed anyway.
	if req.Method != http.MethodGet || req.Body != nil {
		return t.next.RoundTrip(req)
	}
	for attempt := 1; ; attempt++ {
		resp, err := t.next.RoundTrip(req)
		if attempt == retryAttempts || !retryableFailure(resp, err) {
			return resp, err
		}
		wait := jitteredBackoff(attempt)
		if resp != nil {
			if after, ok := parseRetryAfter(resp.Header.Get("Retry-After")); ok {
				wait = after
			}
		}
		// Checked against the uncapped wait, and before the body is
		// touched: a Retry-After that will not fit before the deadline is
		// not made to fit by shrinking it -- honoring a fraction of what
		// Vault asked for would likely just draw the same 429 again. Give
		// up now, with the response untouched, rather than let the
		// caller see a deadline timeout two attempts later.
		if !fitsBeforeDeadline(req.Context(), wait) {
			return resp, err
		}
		if resp != nil {
			// Drain before closing so the keep-alive connection goes back
			// to the pool instead of being torn down; the limit keeps an
			// absurd error body from stalling the retry.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
		}
		if serr := t.sleep(req.Context(), min(wait, retryAfterCap)); serr != nil {
			return nil, serr
		}
	}
}

// fitsBeforeDeadline reports whether wait leaves at least retryMinHeadroom
// on ctx's deadline for one more wire attempt after the sleep. A context
// with no deadline always fits, since nothing bounds it.
func fitsBeforeDeadline(ctx context.Context, wait time.Duration) bool {
	deadline, ok := ctx.Deadline()
	if !ok {
		return true
	}
	return wait <= time.Until(deadline)-retryMinHeadroom
}

// retryableFailure reports whether one attempt's outcome is worth another
// wire request: a 429, or a transport-level refusal/reset that failed
// before a response existed. Any other response -- 503 sealed-Vault
// semantics included -- or error surfaces as-is.
func retryableFailure(resp *http.Response, err error) bool {
	if err != nil {
		return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
	}
	return resp.StatusCode == http.StatusTooManyRequests
}

// jitteredBackoff computes the wait before retry number attempt: the
// doubling base plus up to 100% jitter, so attempt 1 waits within
// [100 ms, 200 ms) and attempt 2 within [200 ms, 400 ms).
func jitteredBackoff(attempt int) time.Duration {
	d := retryBackoffBase << (attempt - 1)
	return d + rand.N(d)
}

// maxRetryAfterSeconds is the largest delay-seconds value that survives
// the seconds-to-Duration conversion below without overflowing the
// int64 nanoseconds a Duration holds.
const maxRetryAfterSeconds = int64(math.MaxInt64) / int64(time.Second)

// parseRetryAfter reads a Retry-After header in either of its RFC 9110
// forms, delay seconds or an HTTP date, and returns the raw requested
// wait uncapped: RoundTrip weighs that against the request's own deadline
// before ever clamping it for sleep. The second return is false when the
// header is absent, unparseable, or -- for the seconds form -- too large
// to represent as a Duration.
func parseRetryAfter(h string) (time.Duration, bool) {
	if h == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(h); err == nil && secs >= 0 {
		if int64(secs) > maxRetryAfterSeconds {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if when, err := http.ParseTime(h); err == nil {
		return max(time.Until(when), 0), true
	}
	return 0, false
}

// sleepBackoff waits d out, or returns early with the context's error.
// req.Context() is not context.Background(): http.Client.Do installs a
// deadline context derived from the client's 30 s Timeout on every
// request it sends, so ctx.Done() fires there if d runs past it. That is
// also why RoundTrip checks fitsBeforeDeadline before ever calling this
// with a Retry-After-driven wait -- letting the deadline win the race is
// what turns an honest 429 into an opaque "context deadline exceeded".
func sleepBackoff(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
