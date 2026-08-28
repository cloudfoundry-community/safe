package parallel

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEachLimitVisitsEveryItem(t *testing.T) {
	items := []int{10, 20, 30, 40, 50}
	var mu sync.Mutex
	got := map[int]int{}
	err := EachLimit(items, 3, func(i, item int) error {
		mu.Lock()
		got[i] = item
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("EachLimit: %v", err)
	}
	for i, want := range items {
		if got[i] != want {
			t.Errorf("index %d = %d, want %d", i, got[i], want)
		}
	}
}

func TestEachLimitBoundsConcurrency(t *testing.T) {
	var inFlight, peak atomic.Int64
	err := EachLimit(make([]struct{}, 32), 4, func(int, struct{}) error {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("EachLimit: %v", err)
	}
	if peak.Load() > 4 {
		t.Errorf("peak concurrency %d, want <= 4", peak.Load())
	}
}

// A sequential implementation must fail this test: four items with limit
// four all park on one barrier that only releases when all four are in
// flight together.
func TestEachLimitActuallyRunsConcurrently(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(4)
	done := make(chan error, 1)
	go func() {
		done <- EachLimit(make([]struct{}, 4), 4, func(int, struct{}) error {
			wg.Done()
			wg.Wait()
			return nil
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("EachLimit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("items never ran concurrently")
	}
}

// Fail-fast: the first error stops new dispatch and comes back unwrapped.
func TestEachLimitFailsFast(t *testing.T) {
	boom := errors.New("boom")
	var attempted atomic.Int64
	err := EachLimit(make([]struct{}, 100), 1, func(i int, _ struct{}) error {
		attempted.Add(1)
		if i == 2 {
			return boom
		}
		return nil
	})
	if err != boom {
		t.Errorf("err = %v, want boom unwrapped", err)
	}
	if got := attempted.Load(); got != 3 {
		t.Errorf("attempted %d items, want 3 (fail-fast at limit 1)", got)
	}
}
