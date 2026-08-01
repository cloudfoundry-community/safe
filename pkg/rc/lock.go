package rc

import (
	"context"
	"sync"
	"time"

	"github.com/gofrs/flock"
	fmt "github.com/jhunt/go-ansi"
)

// configMutex serializes writers within one process. flock(2) locks are held
// per open file description, not per process, so without it two goroutines
// taking the file lock through separate opens would not conflict -- and two
// through a shared one would silently succeed together.
var configMutex sync.Mutex

// How long a writer waits for whoever holds the lock, and how often it asks
// again. The lock only ever covers milliseconds of file I/O, so a holder that
// keeps another writer waiting anywhere near this long is gone or wedged --
// give up with an error rather than write unlocked. Variables so tests can
// prove the timeout path without sitting through it.
var (
	lockTimeout    = 10 * time.Second
	lockRetryDelay = 50 * time.Millisecond
)

func lockPath() string {
	return fmt.Sprintf("%s/.saferc.lock", userHomeDir())
}

// withLock runs fn while holding an exclusive lock over the config files
// (.saferc, .svtoken, .vault-token, written together as one transaction).
//
// The lock lives on a sidecar file, ~/.saferc.lock, not on .saferc itself:
// writes replace .saferc by rename, which swaps the inode, and a lock on a
// replaced inode excludes nobody. The sidecar is created once and never
// removed -- unlinking a lock file reintroduces the same inode race.
//
// flock locks die with the process, so a writer killed mid-transaction --
// including safe local's own die(), which calls os.Exit -- cannot leave the
// lock stuck. No staleness handling is needed or present.
//
// Caveat: on filesystems where flock is advisory-only per client (NFS before
// v4, some network mounts), concurrent safes on *different hosts* sharing a
// $HOME are not serialized. The atomic rename still makes corruption
// impossible there; the exposure degrades to a lost update.
func withLock(fn func() error) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	fl := flock.New(lockPath(), flock.SetPermissions(0600))
	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()

	locked, err := fl.TryLockContext(ctx, lockRetryDelay)
	if err != nil && !locked {
		if ctx.Err() != nil {
			return fmt.Errorf("timed out after %s waiting to lock %s (another safe is holding it -- find it with `lsof %s`; the lock releases on its own when that process exits, do not remove the lock file)", lockTimeout, lockPath(), lockPath())
		}
		return fmt.Errorf("could not lock %s: %w", lockPath(), err)
	}
	if !locked {
		return fmt.Errorf("could not lock %s", lockPath())
	}
	defer func() { _ = fl.Unlock() }()

	return fn()
}
