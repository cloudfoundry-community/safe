package vault_test

// Update and UpdateSteps back off between check-and-set retry passes so a
// burst of concurrent writers scatters across a widening window instead of
// re-arriving in the same instant on every pass -- the thundering herd a
// bare retry loop invites. The backoff must cost the uncontended path
// nothing: no sleep before the first attempt, and none after a pass that
// succeeds or gives up for the last time.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// The common path -- no conflict at all -- must never sleep: a seam that
// fails the test if called proves it.
func TestUpdateUncontendedPathNeverSleeps(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")

	restore := vault.SetCASSleepForTest(v, func(ctx context.Context, d time.Duration) error {
		t.Errorf("casSleep called with d=%s on an uncontended write", d)
		return nil
	})
	t.Cleanup(restore)

	_, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if err := s.Set("gen", "ours", false); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
}

// Same for UpdateSteps.
func TestUpdateStepsUncontendedPathNeverSleeps(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")

	restore := vault.SetCASSleepForTest(v, func(ctx context.Context, d time.Duration) error {
		t.Errorf("casSleep called with d=%s on an uncontended chain", d)
		return nil
	})
	t.Cleanup(restore)

	err := v.UpdateSteps(updDataPath, 2, func(step int, s *vault.Secret, exists bool) (bool, error) {
		if err := s.Set(fmt.Sprintf("k%d", step), "v", false); err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("UpdateSteps: %v", err)
	}
}

// Sustained conflict sleeps once between each of the five passes -- four
// waits, never a fifth after the final, failed attempt -- and every wait
// stays within the schedule's bound for its position.
func TestUpdateExhaustionBacksOffBetweenPassesNotAfterTheLast(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"n": "0"})

	fv.afterRequest(updDataGet, 0, func() {
		fv.setV2(updDataPath, map[string]string{"n": "bumped"})
	})

	var waits []time.Duration
	restore := vault.SetCASSleepForTest(v, func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	})
	t.Cleanup(restore)

	_, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if err := s.Set("gen", "ours", false); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	})
	if err == nil {
		t.Fatal("Update under sustained conflict = nil, want an error")
	}

	if len(waits) != 4 {
		t.Fatalf("sleep calls = %d, want 4 (one between each of the five passes, none after the last)", len(waits))
	}
	for i, d := range waits {
		if d < 0 || d > vault.CASBackoffCeilingForTest(i+1) {
			t.Errorf("wait %d = %s, want within [0, %s]", i+1, d, vault.CASBackoffCeilingForTest(i+1))
		}
	}
}

// UpdateSteps backs off the same way across its shared attempt budget.
func TestUpdateStepsExhaustionBacksOffBetweenPassesNotAfterTheLast(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"n": "0"})

	fv.afterRequest(updDataGet, 0, func() {
		fv.setV2(updDataPath, map[string]string{"n": "bumped"})
	})

	var waits []time.Duration
	restore := vault.SetCASSleepForTest(v, func(ctx context.Context, d time.Duration) error {
		waits = append(waits, d)
		return nil
	})
	t.Cleanup(restore)

	err := v.UpdateSteps(updDataPath, 1, func(step int, s *vault.Secret, exists bool) (bool, error) {
		if err := s.Set("k", "v", false); err != nil {
			return false, err
		}
		return true, nil
	})
	if err == nil {
		t.Fatal("UpdateSteps under sustained conflict = nil, want an error")
	}
	if len(waits) != 4 {
		t.Fatalf("sleep calls = %d, want 4 (one between each of the five passes, none after the last)", len(waits))
	}
}

// A cancellation surfaced by the sleep seam aborts the retry immediately
// instead of being swallowed, and no further request follows it.
func TestUpdateAbortsWhenCASSleepErrors(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"n": "0"})

	fv.afterRequest(updDataGet, 0, func() {
		fv.setV2(updDataPath, map[string]string{"n": "bumped"})
	})

	sentinel := errors.New("sleep aborted")
	restore := vault.SetCASSleepForTest(v, func(ctx context.Context, d time.Duration) error {
		return sentinel
	})
	t.Cleanup(restore)

	_, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if err := s.Set("gen", "ours", false); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("Update error = %v, want it to wrap the sleep's own error", err)
	}
	if gets := fv.requestCount(updDataGet); gets != 1 {
		t.Errorf("data reads = %d, want exactly 1 (aborted before a second attempt)", gets)
	}
}
