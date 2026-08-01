package cli

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/term"
)

// localTeardownMu guards localTeardownFn, the hook a running `safe local`
// installs so SIGTERM/SIGQUIT reach its own cleanup -- killing the child
// engine, removing its temp config, and restoring the previous target --
// instead of Signals()'s bare terminal-restore-and-exit. Only one command
// runs at a time in this process, so a single package-level slot is enough.
var (
	localTeardownMu sync.Mutex
	localTeardownFn func(os.Signal)
)

// setLocalTeardown installs fn as the signal-driven teardown for a running
// `safe local`. Pass nil to clear it once the command is done -- after that
// point there is nothing left for a signal to tear down, and Signals() must
// go back to exiting bare for every other command.
func setLocalTeardown(fn func(os.Signal)) {
	localTeardownMu.Lock()
	defer localTeardownMu.Unlock()
	localTeardownFn = fn
}

func localTeardown() func(os.Signal) {
	localTeardownMu.Lock()
	defer localTeardownMu.Unlock()
	return localTeardownFn
}

func Signals() {
	//When stdin is not a terminal there is no state to put back, and prev is
	// nil. Restore dereferences the state it is handed, so restoring nil
	// turned the clean exit below into a panic: a piped safe that caught
	// Ctrl-C died of a nil pointer instead of leaving with status 1.
	prev, err := term.GetState(int(os.Stdin.Fd()))
	if err != nil {
		prev = nil
	}

	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	for sig := range s {
		// A running `safe local` owns its own teardown -- its child engine,
		// temp config, and registered target need cleaning up in a way this
		// generic handler knows nothing about. SIGINT never reaches here for
		// it (ignored deliberately, see cmdLocal), so this only fires for
		// SIGTERM/SIGQUIT while one is active.
		if fn := localTeardown(); fn != nil {
			fn(sig)
			// fn is contracted to end the process itself, the same way
			// die() already does for every other `safe local` failure path.
			// Falling through to the bare exit below is the safety net for
			// a hook that does not, not the expected route.
		}
		if prev != nil {
			_ = term.Restore(int(os.Stdin.Fd()), prev)
		}
		os.Exit(1)
	}
}
