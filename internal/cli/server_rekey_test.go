package cli

// Tests for cmdRekey's validation paths (server.go): everything that fails
// before a Vault connection is attempted. GPG key material comes from a fake
// `gpg` executable prepended to PATH (installFakeBin lives in
// server_vault_cmd_test.go).

import (
	"strings"
	"testing"
)

// installFakeGPG installs a fake `gpg` whose behavior is chosen by
// $FAKE_GPG_MODE: "fail" exits nonzero, "empty" exits zero with no output
// (how real gpg reports an unknown key), and anything else prints fixed key
// bytes. fakeGPGKeyBytes is what the default mode emits.
const fakeGPGKeyBytes = "FAKE-PGP-KEY"

func installFakeGPG(t *testing.T) {
	t.Helper()
	installFakeBin(t, "gpg", `#!/bin/sh
case "${FAKE_GPG_MODE:-ok}" in
  fail)  exit 2 ;;
  empty) exit 0 ;;
  *)     printf '`+fakeGPGKeyBytes+`' ;;
esac
`)
}

func rekeyCLI(t *testing.T) *CLI {
	t.Helper()
	return &CLI{opt: &Options{}, r: NewRunner()}
}

func TestCmdRekey_UnknownTargetErrors(t *testing.T) {
	isolateHome(t)
	c := rekeyCLI(t)
	c.opt.UseTarget = "no-such-target"

	err := c.cmdRekey("rekey")
	if err == nil {
		t.Fatal("expected an error for an unknown target, got nil")
	}
	if !strings.Contains(err.Error(), "no-such-target") {
		t.Errorf("error does not name the unknown target: %v", err)
	}
}

func TestCmdRekey_GPGExportFailureErrors(t *testing.T) {
	isolateHome(t)
	installFakeGPG(t)
	t.Setenv("FAKE_GPG_MODE", "fail")
	c := rekeyCLI(t)
	c.opt.Rekey.GPG = []string{"alice@example.com"}

	err := c.cmdRekey("rekey")
	if err == nil {
		t.Fatal("expected an error when gpg --export fails, got nil")
	}
	if !strings.Contains(err.Error(), "Failed to retrieve GPG key for alice@example.com") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdRekey_GPGKeyNotFoundErrors(t *testing.T) {
	isolateHome(t)
	installFakeGPG(t)
	t.Setenv("FAKE_GPG_MODE", "empty")
	c := rekeyCLI(t)
	c.opt.Rekey.GPG = []string{"bob@example.com"}

	err := c.cmdRekey("rekey")
	if err == nil {
		t.Fatal("expected an error when gpg finds no key, got nil")
	}
	if !strings.Contains(err.Error(), "No GPG key found for bob@example.com") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdRekey_GPGAndKeyCountMismatchErrors(t *testing.T) {
	isolateHome(t)
	installFakeGPG(t)
	c := rekeyCLI(t)
	c.opt.Rekey.GPG = []string{"alice@example.com"}
	c.opt.Rekey.NKeys = 2

	err := c.cmdRekey("rekey")
	if err == nil {
		t.Fatal("expected an error for mismatched --gpg and --keys counts, got nil")
	}
	if !strings.Contains(err.Error(), "counts did not match") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdRekey_ThresholdAboveKeyCountErrors(t *testing.T) {
	isolateHome(t)
	c := rekeyCLI(t)
	c.opt.Rekey.NKeys = 2
	c.opt.Rekey.Threshold = 3

	err := c.cmdRekey("rekey")
	if err == nil {
		t.Fatal("expected an error for a threshold above the key count, got nil")
	}
	if !strings.Contains(err.Error(), "only 2 unseal keys") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdRekey_ThresholdOfOneWithManyKeysErrors(t *testing.T) {
	isolateHome(t)
	c := rekeyCLI(t)
	c.opt.Rekey.NKeys = 3
	c.opt.Rekey.Threshold = 1

	err := c.cmdRekey("rekey")
	if err == nil {
		t.Fatal("expected an error for a threshold of 1 with several keys, got nil")
	}
	if !strings.Contains(err.Error(), "more than one key required to unseal") {
		t.Errorf("unexpected error wording: %v", err)
	}
}
