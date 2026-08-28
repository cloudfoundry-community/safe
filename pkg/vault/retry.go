package vault

import (
	"context"
	"errors"
	"io"
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
	// retryAfterCap bounds an honored Retry-After header. The client's
	// 30 s timeout would kill the request before a longer wait paid off,
	// and the backoff sleep cannot see that timeout fire (see sleep).
	retryAfterCap = 30 * time.Second
)

// retryTransport retries throttled reads against the tuned transport it
// wraps. Its scope is deliberately narrow:
//
//   - GET and LIST requests only. Writes are never retried here: replaying
//     a PUT would surface check-and-set conflicts from the wrong layer,
//     and POST/DELETE are not idempotent.
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
	// The body guard is belt-and-braces: vaultkv's GETs and LISTs carry no
	// body, and a consumed body could not be replayed anyway.
	if (req.Method != http.MethodGet && req.Method != "LIST") || req.Body != nil {
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
			// Drain before closing so the keep-alive connection goes back
			// to the pool instead of being torn down; the limit keeps an
			// absurd error body from stalling the retry.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
		}
		if serr := t.sleep(req.Context(), wait); serr != nil {
			return nil, serr
		}
	}
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

// parseRetryAfter reads a Retry-After header in either of its RFC 9110
// forms, delay seconds or an HTTP date, capped at retryAfterCap. The
// second return is false when the header is absent or unparseable.
func parseRetryAfter(h string) (time.Duration, bool) {
	if h == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(h); err == nil && secs >= 0 {
		return min(time.Duration(secs)*time.Second, retryAfterCap), true
	}
	if when, err := http.ParseTime(h); err == nil {
		return min(max(time.Until(when), 0), retryAfterCap), true
	}
	return 0, false
}

// sleepBackoff waits d out, or returns early with the context's error.
// The context branch is inert today: vaultkv issues requests without
// contexts, so req.Context() is context.Background() and the client's
// 30 s timeout is the only live bound (it cancels the next attempt's
// dial, not this sleep). Written against the context anyway so
// cancellation goes live the moment vaultkv plumbs request contexts.
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
