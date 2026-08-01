package cli

// `safe option' reads and writes the options block of ~/.saferc. With no
// arguments it lists every option and its value; given option=value pairs it
// flips them and persists the result. These tests run the handler in-process
// against an isolated home, so nothing they read or write is the developer's
// own ~/.saferc.
//
// captureStdout mutates the process-global os.Stdout — do NOT add t.Parallel
// to any test in this file.

import (
	"strings"
	"testing"
)

func TestOptionWithNoArgsListsEveryOption(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)

	var err error
	out := captureStdout(t, func() {
		err = c.cmdOption("option")
	})
	if err != nil {
		t.Fatalf("cmdOption: %v", err)
	}
	if !strings.Contains(out, "manage_vault_token") {
		t.Errorf("the listing does not name manage_vault_token:\n%s", out)
	}
	if !strings.Contains(out, "false") {
		t.Errorf("an unset option should list as false:\n%s", out)
	}
}

func TestOptionListingReflectsTheStoredValue(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, `version: 1
current: ""
vaults: {}
options:
  manage_vault_token: true
`)
	c := newTestCLI(t)

	out := captureStdout(t, func() {
		if err := c.cmdOption("option"); err != nil {
			t.Fatalf("cmdOption: %v", err)
		}
	})
	if !strings.Contains(out, "true") {
		t.Errorf("manage_vault_token is stored true but lists as:\n%s", out)
	}
}

func TestOptionSetsAndPersistsAValue(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)

	out := captureStdout(t, func() {
		if err := c.cmdOption("option", "manage_vault_token=true"); err != nil {
			t.Fatalf("cmdOption: %v", err)
		}
	})
	if !strings.Contains(out, "updated") || !strings.Contains(out, "manage_vault_token") {
		t.Errorf("setting an option should say which one was updated:\n%s", out)
	}

	cfg := readConfig(t)
	if !cfg.Options.ManageVaultToken {
		t.Error("manage_vault_token=true was not persisted to ~/.saferc")
	}
}

func TestOptionTurnsAValueBackOff(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, `version: 1
current: ""
vaults: {}
options:
  manage_vault_token: true
`)
	c := newTestCLI(t)

	captureStdout(t, func() {
		if err := c.cmdOption("option", "manage_vault_token=off"); err != nil {
			t.Fatalf("cmdOption: %v", err)
		}
	})

	if readConfig(t).Options.ManageVaultToken {
		t.Error("manage_vault_token=off left the option on in ~/.saferc")
	}
}

// The option is stored with underscores, but hyphens are how flags are
// usually spelled, so both spellings name the same option.
func TestOptionAcceptsHyphensForUnderscores(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)

	captureStdout(t, func() {
		if err := c.cmdOption("option", "manage-vault-token=yes"); err != nil {
			t.Fatalf("cmdOption: %v", err)
		}
	})

	if !readConfig(t).Options.ManageVaultToken {
		t.Error("manage-vault-token=yes was not persisted to ~/.saferc")
	}
}

func TestOptionRejectsAnArgWithoutAValue(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)

	err := c.cmdOption("option", "manage_vault_token")
	if err == nil {
		t.Fatal("an arg with no = should be an error")
	}
	if !strings.Contains(err.Error(), "option=value") {
		t.Errorf("the error should show the expected syntax, got: %v", err)
	}
}

func TestOptionRejectsAValueThatIsNotBoolean(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)

	err := c.cmdOption("option", "manage_vault_token=maybe")
	if err == nil {
		t.Fatal("a value that is not true/false should be an error")
	}
	if !strings.Contains(err.Error(), "true|on|yes|false|off|no") {
		t.Errorf("the error should list the accepted values, got: %v", err)
	}
}

func TestOptionRejectsAnOptionSafeDoesNotHave(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)

	err := c.cmdOption("option", "no_such_option=true")
	if err == nil {
		t.Fatal("an unknown option should be an error")
	}
	if !strings.Contains(err.Error(), "no_such_option") {
		t.Errorf("the error should name the unknown option, got: %v", err)
	}
}

// A bad pair must not take effect: an unknown option or a value that does not
// parse leaves ~/.saferc as it was, even when an earlier pair on the same
// command line was good.
func TestOptionDoesNotPersistWhenALaterArgIsBad(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)

	var err error
	captureStdout(t, func() {
		err = c.cmdOption("option", "manage_vault_token=true", "bogus=true")
	})
	if err == nil {
		t.Fatal("a bad pair should fail the command")
	}

	if readConfig(t).Options.ManageVaultToken {
		t.Error("a failed command wrote the earlier pair to ~/.saferc")
	}
}
