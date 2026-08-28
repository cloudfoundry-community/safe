// Package parallel provides the bounded fail-fast parallel map used by
// safe's multi-path commands. It is internal so the concurrency helper
// never becomes public Vault-client API.
package parallel

import (
	"context"
	"strings"
	"sync"
)

// Errors collects every failure one EachLimit fan-out saw: the first
// arrival plus any in-flight siblings that failed before they could be
// cancelled. Error enumerates them all -- on a write command each one may
// name a partial write -- while Unwrap returns only the first, so
// errors.Is and errors.As classify a multi-failure run exactly as they
// classify its first failure alone.
type Errors struct {
	errs []error
}

// NewErrors folds collected failures into what EachLimit returns: nil for
// none, the bare error for one -- byte-identical output to a sequential
// loop -- and an *Errors for several. Callers pass only non-nil errors.
func NewErrors(errs ...error) error {
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	}
	return &Errors{errs: errs}
}

func (e *Errors) Error() string {
	msgs := make([]string, len(e.errs))
	for i, err := range e.errs {
		msgs[i] = err.Error()
	}
	return strings.Join(msgs, "\n")
}

// Unwrap returns the first failure only, never the whole slice: sibling
// failures are reported, not classified.
func (e *Errors) Unwrap() error {
	return e.errs[0]
}

// All reports whether pred holds for every collected failure. Suppression
// decisions (--force swallowing not-found errors) must consult every
// sibling: whichever error wins the arrival race says nothing about the
// others.
func (e *Errors) All(pred func(error) bool) bool {
	for _, err := range e.errs {
		if !pred(err) {
			return false
		}
	}
	return true
}

// EachLimit runs fn over items with at most limit concurrent calls.
// Fail-fast: after the first non-nil error no new item is dispatched,
// in-flight calls see their context cancelled, and the fan-out returns
// once they complete. Every failure is collected; a single failure is
// returned unwrapped so errors.As/Is classification behaves as in a
// sequential loop, and several come back as an *Errors that classifies by
// the first arrival only. A ctx the caller cancels stops dispatch the
// same way and is returned when no call failed on its own.
//
// Cancellation bounds what fn lets it bound: an exec.CommandContext child
// is killed, but vaultkv requests carry no context (the client's 30 s
// timeout is their only cap) and rsa.GenerateKey cannot be interrupted
// mid-search, so those in-flight calls still run to completion.
func EachLimit[T any](ctx context.Context, items []T, limit int, fn func(ctx context.Context, i int, item T) error) error {
	if limit < 1 {
		limit = 1
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	sem := make(chan struct{}, limit)
dispatch:
	for i := range items {
		// The explicit Err check comes first: with ctx already done, the
		// select below could still win its sem case at random.
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break dispatch
		}
		mu.Lock()
		stop := len(errs) > 0
		mu.Unlock()
		if stop {
			<-sem
			break
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := fn(ctx, i, items[i]); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
				cancel()
			}
		}(i)
	}
	wg.Wait()
	if len(errs) == 0 {
		// Dispatch can only have stopped early via the caller's own
		// context here: the internal cancel fires on failure alone, and
		// failures land in errs before it does.
		return ctx.Err()
	}
	return NewErrors(errs...)
}
