package parallel

// EachLimit's contract when several in-flight calls fail: every failure is
// reported, classification (errors.Is / errors.As through Unwrap) keys off
// the first arrival only, and a lone failure comes back as the bare error
// so single-failure output is byte-identical to what it was.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestEachLimitCollectsConcurrentSiblingErrors(t *testing.T) {
	e0 := errors.New("first failure")
	e1 := errors.New("second failure")
	fails := []error{e0, e1}

	// A barrier guarantees both calls are in flight together, so neither
	// failure can be dodged by fail-fast dispatch.
	var barrier sync.WaitGroup
	barrier.Add(2)
	err := EachLimit(context.Background(), []int{0, 1}, 2, func(_ context.Context, i, _ int) error {
		barrier.Done()
		barrier.Wait()
		return fails[i]
	})

	var errs *Errors
	if !errors.As(err, &errs) {
		t.Fatalf("err = %T (%v), want *Errors", err, err)
	}
	for _, want := range []string{"first failure", "second failure"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Error() = %q, does not mention %q", err.Error(), want)
		}
	}

	// Arrival order decides which failure is "first"; either may win the
	// race, but classification must follow exactly the winner.
	first := errors.Unwrap(err)
	if first != e0 && first != e1 {
		t.Fatalf("Unwrap() = %v, want one of the two failures", first)
	}
	other := e0
	if first == e0 {
		other = e1
	}
	if !errors.Is(err, first) {
		t.Errorf("errors.Is does not match the first failure %v", first)
	}
	if errors.Is(err, other) {
		t.Errorf("errors.Is matches the sibling %v; classification must key off the first failure only", other)
	}
}

func TestNewErrorsClassifiesByFirstOnly(t *testing.T) {
	e0 := errors.New("lost the write")
	e1 := errors.New("lost the sibling write")

	if err := NewErrors(); err != nil {
		t.Errorf("NewErrors() = %v, want nil", err)
	}
	if err := NewErrors(e0); err != e0 {
		t.Errorf("NewErrors(e0) = %v, want the bare error back", err)
	}

	err := NewErrors(e0, e1)
	if got := errors.Unwrap(err); got != e0 {
		t.Errorf("Unwrap() = %v, want the first error", got)
	}
	if !errors.Is(err, e0) {
		t.Error("errors.Is does not match the first error")
	}
	if errors.Is(err, e1) {
		t.Error("errors.Is matches the second error; it must match the first only")
	}

	// The same two failures in the opposite arrival order classify by the
	// new first, and never by the now-second.
	err = NewErrors(e1, e0)
	if !errors.Is(err, e1) || errors.Is(err, e0) {
		t.Error("reversed arrival order does not classify by its own first error")
	}
}

func TestErrorsAll(t *testing.T) {
	kind := errors.New("not found")
	isKind := func(err error) bool { return errors.Is(err, kind) }

	var errs *Errors
	if !errors.As(NewErrors(kind, kind), &errs) {
		t.Fatal("NewErrors(kind, kind) is not an *Errors")
	}
	if !errs.All(isKind) {
		t.Error("All = false with every error matching, want true")
	}

	if !errors.As(NewErrors(kind, errors.New("permission denied")), &errs) {
		t.Fatal("NewErrors(kind, other) is not an *Errors")
	}
	if errs.All(isKind) {
		t.Error("All = true with a non-matching sibling, want false")
	}
	if !errors.As(NewErrors(errors.New("permission denied"), kind), &errs) {
		t.Fatal("NewErrors(other, kind) is not an *Errors")
	}
	if errs.All(isKind) {
		t.Error("All = true with a non-matching first error, want false")
	}
}
