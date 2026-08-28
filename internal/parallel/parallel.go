// Package parallel provides the bounded fail-fast parallel map used by
// safe's multi-path commands. It is internal so the concurrency helper
// never becomes public Vault-client API.
package parallel

import "sync"

// EachLimit runs fn over items with at most limit concurrent calls.
// Fail-fast: after the first non-nil error no new item is dispatched,
// in-flight calls complete, and the first error is returned unwrapped so
// errors.As/Is classification behaves as in a sequential loop.
func EachLimit[T any](items []T, limit int, fn func(i int, item T) error) error {
	if limit < 1 {
		limit = 1
	}
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	sem := make(chan struct{}, limit)
	for i := range items {
		sem <- struct{}{}
		mu.Lock()
		stop := firstErr != nil
		mu.Unlock()
		if stop {
			<-sem
			break
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := fn(i, items[i]); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	return firstErr
}
