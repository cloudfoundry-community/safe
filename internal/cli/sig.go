package cli

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

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
	for range s {
		if prev != nil {
			_ = term.Restore(int(os.Stdin.Fd()), prev)
		}
		os.Exit(1)
	}
}
