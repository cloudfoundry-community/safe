package parallel

// After one call fails, its in-flight siblings see a cancelled context, so
// work that can be interrupted -- an openssl child, a future
// context-carrying request -- stops instead of running to completion, and
// a caller-cancelled context stops dispatch before new items start.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEachLimitCancelsSiblingsAfterFirstFailure(t *testing.T) {
	boom := errors.New("boom")

	// The barrier holds both calls in flight together, so the failure
	// cannot resolve before the sibling is parked on the context.
	var barrier sync.WaitGroup
	barrier.Add(2)
	var observed atomic.Bool
	err := EachLimit(context.Background(), []int{0, 1}, 2, func(ctx context.Context, i, _ int) error {
		barrier.Done()
		barrier.Wait()
		if i == 0 {
			return boom
		}
		select {
		case <-ctx.Done():
			observed.Store(true)
			return nil
		case <-time.After(5 * time.Second):
			return errors.New("sibling never saw cancellation")
		}
	})

	if err != boom {
		t.Errorf("err = %v, want boom unwrapped", err)
	}
	if !observed.Load() {
		t.Error("in-flight sibling never observed cancellation after the failure")
	}
}

func TestEachLimitStopsDispatchOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var attempted atomic.Int64
	err := EachLimit(ctx, make([]struct{}, 8), 2, func(context.Context, int, struct{}) error {
		attempted.Add(1)
		return nil
	})

	if got := attempted.Load(); got != 0 {
		t.Errorf("attempted %d items under a cancelled context, want 0", got)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
