package rc

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
)

// shortenLockWaits makes lock-contention tests fast. The real values wait 10s
// for a holder to finish; a test that proves the timeout path cannot sit
// through that.
func shortenLockWaits(t *testing.T) {
	prevTimeout, prevDelay := lockTimeout, lockRetryDelay
	lockTimeout = 100 * time.Millisecond
	lockRetryDelay = 5 * time.Millisecond
	t.Cleanup(func() {
		lockTimeout, lockRetryDelay = prevTimeout, prevDelay
	})
}

func TestWithLockRunsFn(t *testing.T) {
	setHome(t)

	ran := false
	if err := withLock(func() error {
		ran = true
		return nil
	}); err != nil {
		t.Fatalf("withLock: %s", err)
	}
	if !ran {
		t.Fatalf("withLock returned without running fn")
	}

	// The sidecar must exist afterward and must not be world-readable: it
	// sits next to a file of root tokens and shares its directory perms.
	fi, err := os.Stat(lockPath())
	if err != nil {
		t.Fatalf("lock file after withLock: %s", err)
	}
	if got := fi.Mode().Perm(); got != 0600 {
		t.Errorf("lock file mode = %04o, want 0600", got)
	}
}

func TestWithLockPropagatesFnError(t *testing.T) {
	setHome(t)

	sentinel := errors.New("mutation failed")
	if err := withLock(func() error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("withLock error = %v, want %v", err, sentinel)
	}

	// The failure must have released the lock: a second writer proceeds.
	if err := withLock(func() error { return nil }); err != nil {
		t.Fatalf("withLock after failed fn: %s", err)
	}
}

func TestWithLockExcludesConcurrentWriters(t *testing.T) {
	setHome(t)

	var inside, total int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := withLock(func() error {
				mu.Lock()
				inside++
				if inside > 1 {
					t.Errorf("%d writers inside the critical section", inside)
				}
				mu.Unlock()

				time.Sleep(2 * time.Millisecond)

				mu.Lock()
				inside--
				total++
				mu.Unlock()
				return nil
			})
			if err != nil {
				t.Errorf("withLock: %s", err)
			}
		}()
	}
	wg.Wait()

	if total != 8 {
		t.Errorf("%d of 8 writers ran", total)
	}
}

func TestWithLockTimesOutWhenHeld(t *testing.T) {
	setHome(t)
	shortenLockWaits(t)

	// Hold the file lock through a separate open file description, the way
	// another process would. flock(2) locks are per open file description,
	// so this conflicts with withLock's own even within one test binary.
	holder := flock.New(lockPath(), flock.SetPermissions(0600))
	locked, err := holder.TryLock()
	if err != nil || !locked {
		t.Fatalf("could not pre-acquire lock (locked=%v): %v", locked, err)
	}
	defer func() { _ = holder.Unlock() }()

	err = withLock(func() error {
		t.Error("fn ran while the lock was held elsewhere")
		return nil
	})
	if err == nil {
		t.Fatalf("withLock succeeded against a held lock")
	}
	if !strings.Contains(err.Error(), lockPath()) {
		t.Errorf("timeout error %q does not name the lock file", err)
	}
}
