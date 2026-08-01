package cli

// Tests for cmdLocal's validation paths (server.go): everything that fails
// before a Vault server process is spawned. Where a `vault` binary is needed
// for version probing, a fake that only answers `vault version` is placed on
// PATH (installFakeBin lives in server_vault_cmd_test.go).

import (
	"path/filepath"
	"strings"
	"testing"
)

// installFakeVaultVersionOnly installs a fake `vault` that answers `vault
// version` with the given string and rejects any other invocation, so a test
// that must not reach `vault server` fails loudly if it does.
func installFakeVaultVersionOnly(t *testing.T, version string) {
	t.Helper()
	installFakeBin(t, "vault", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "`+version+`"
  exit 0
fi
echo "unexpected invocation: vault $*" >&2
exit 42
`)
}

func localCLI(t *testing.T) *CLI {
	t.Helper()
	return &CLI{opt: &Options{}, r: NewRunner()}
}

func TestCmdLocal_NeitherMemoryNorFileErrors(t *testing.T) {
	isolateHome(t)
	c := localCLI(t)

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error when neither --memory nor --file is given, got nil")
	}
	if !strings.Contains(err.Error(), "--memory or --file") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdLocal_BothMemoryAndFileErrors(t *testing.T) {
	isolateHome(t)
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.File = filepath.Join(t.TempDir(), "vault.db")

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error when both --memory and --file are given, got nil")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdLocal_MissingVaultBinaryErrors(t *testing.T) {
	isolateHome(t)
	// PATH holds only an empty directory, so there is no vault to run.
	t.Setenv("PATH", t.TempDir())
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.Port = 8219

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error when vault is not installed, got nil")
	}
	if !strings.Contains(err.Error(), "neither vault nor bao") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdLocal_MalformedConfigPairErrors(t *testing.T) {
	isolateHome(t)
	installFakeVaultVersionOnly(t, "Vault v1.15.4")
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.Port = 8219
	c.opt.Local.Config = []string{"not-a-pair"}

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error for a malformed --config pair, got nil")
	}
	if !strings.Contains(err.Error(), "expected key=value") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdLocal_MalformedListenerPairErrorsWithOldVault(t *testing.T) {
	isolateHome(t)
	// A pre-0.8 Vault takes the legacy "backend" storage-key branch before
	// the listener pair is rejected.
	installFakeVaultVersionOnly(t, "Vault v0.7.3")
	c := localCLI(t)
	c.opt.Local.File = filepath.Join(t.TempDir(), "does-not-exist.db")
	c.opt.Local.Port = 8219
	c.opt.Local.Listener = []string{"=no-key"}

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error for a malformed --listener pair, got nil")
	}
	if !strings.Contains(err.Error(), "empty key") {
		t.Errorf("unexpected error wording: %v", err)
	}
}
