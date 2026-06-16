package vault

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
	"github.com/cloudfoundry-community/vaultkv"
	"github.com/jhunt/go-ansi"
	"golang.org/x/term"
)

func (v *Vault) cancelRekey(termState *term.State) {
	if termState != nil {
		_ = term.Restore(int(os.Stdin.Fd()), termState)
	}
	err := v.client.Client.RekeyCancel()
	if err != nil {
		_, _ = ansi.Fprintf(os.Stderr, "Failed to cancel rekey process: %s\n", err.Error())
		return
	}

	_, _ = ansi.Fprintf(os.Stderr, "@y{Vault rekey canceled successfully}\n")
}

func (v *Vault) ReKey(unsealKeyCount, numToUnseal int, pgpKeys []string) ([]string, error) {
	err := v.client.Client.RekeyCancel()
	if err != nil {
		return nil, fmt.Errorf("an error occurred when trying to cancel potentially preexisting rekey: %w", err)
	}

	backup := len(pgpKeys) > 0
	rekey, err := v.client.Client.NewRekey(vaultkv.RekeyConfig{
		Shares:    unsealKeyCount,
		Threshold: numToUnseal,
		PGPKeys:   pgpKeys,
		Backup:    backup,
	})
	if err != nil {
		return nil, fmt.Errorf("an error occurred when starting a new rekey operation: %w", err)
	}

	var termState *term.State

	// we successfully started a rekey, we should now cancel on failure, unless we finish rekeying
	var shouldCancelRekey = true
	defer func() {
		if shouldCancelRekey {
			v.cancelRekey(termState)
		}
	}()
	// Catch interrupts during the interactive unseal-key prompts: cancel the
	// in-flight rekey on the Vault server, then terminate. prompt.Secure blocks
	// on stdin in this goroutine, so a signal-driven os.Exit is the only way to
	// abort the operation cleanly without leaving a half-started rekey.
	sighandler := make(chan os.Signal, 4)
	signal.Notify(sighandler, os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		if _, ok := <-sighandler; ok {
			v.cancelRekey(termState)
			os.Exit(1)
		}
	}()

	if term.IsTerminal(int(os.Stdin.Fd())) {
		termState, err = term.GetState(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
	}

	givenKeys := make([]string, rekey.Remaining())

	for i := 0; i < len(givenKeys); i++ {
		givenKeys[i] = prompt.Secure("Unseal Key %d: ", i+1)
	}

	rekeyDone, err := rekey.Submit(givenKeys...)
	if err != nil {
		return nil, fmt.Errorf("key submission failed: %w", err)
	}
	if !rekeyDone {
		return nil, fmt.Errorf("the rekey did not finish (is somebody else trying to rekey at the same time?)")
	}

	// vault should be rekeyed by here, as our progress met the requirement
	shouldCancelRekey = false
	signal.Stop(sighandler)
	close(sighandler)

	return rekey.Keys(), nil
}
