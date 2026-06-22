package vault

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestWorkQueueFIFO confirms Pop returns orders in the order they were pushed.
func TestWorkQueueFIFO(t *testing.T) {
	q := newWorkQueue(1)
	want := []uint16{1, 2, 3}
	for _, op := range want {
		q.Push(&workOrder{operation: op})
	}

	for i, op := range want {
		got, done := q.Pop()
		if done {
			t.Fatalf("Pop %d returned done early", i)
		}
		if got.operation != op {
			t.Fatalf("Pop %d = %d, want %d", i, got.operation, op)
		}
	}
}

// TestWorkQueueAutoClose verifies that a sole worker waiting on an empty queue
// closes it and observes done, since no other worker can enqueue more work.
func TestWorkQueueAutoClose(t *testing.T) {
	q := newWorkQueue(1)

	if _, done := q.Pop(); !done {
		t.Fatal("expected Pop on an empty single-worker queue to report done")
	}
}

// TestWorkQueueExplicitClose verifies Close unblocks Pop and that Push after
// Close is a no-op.
func TestWorkQueueExplicitClose(t *testing.T) {
	q := newWorkQueue(2)
	q.Close()

	if _, done := q.Pop(); !done {
		t.Fatal("expected Pop after Close to report done")
	}

	q.Push(&workOrder{operation: 9})
	if order, done := q.Pop(); !done || order != nil {
		t.Fatalf("Push after Close should be dropped; got order=%v done=%v", order, done)
	}
}

// TestWorkQueueConcurrentDrain runs several workers that drain a pre-seeded
// queue and re-enqueue child orders, mirroring the tree-walk usage. It proves
// every order is consumed exactly once and that the queue terminates when all
// workers are simultaneously idle.
func TestWorkQueueConcurrentDrain(t *testing.T) {
	const workers = 4
	const seed = 50

	q := newWorkQueue(workers)

	for range seed {
		// Each seed order spawns exactly one child, so the total is fixed.
		q.Push(&workOrder{operation: 1})
	}

	var consumed atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for {
				order, done := q.Pop()
				if done {
					return
				}
				consumed.Add(1)
				if order.operation == 1 {
					// Spawn exactly one child for each seed order.
					q.Push(&workOrder{operation: 2})
				}
			}
		})
	}
	wg.Wait()

	if got := consumed.Load(); got != seed*2 {
		t.Fatalf("consumed %d orders, want %d", got, seed*2)
	}
}
