package cli

// End-to-end coverage for safe revert against a colon-bearing path, driven
// through the fake Vault in vault_fake_test.go.
//
// The fake serves KV v1, which reports exactly one version per secret, so these
// exercise the version lookup and its error paths rather than a rollback to an
// older version.

import (
	"strings"
	"testing"
)

// Reverting a colon-bearing path to its current version is a no-op that has to
// find the secret first. Versions takes a literal path, so handing it the
// escaped argument the user typed looks like a missing secret.
func TestCmdRevertColonBearingPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/we:ird", map[string]string{"k": "v"})

	c := newTestCLI(t)
	if err := c.cmdRevert("revert", `secret/we\:ird`, "1"); err != nil {
		t.Fatalf("cmdRevert: %v", err)
	}
	if kv := fv.get("secret/we:ird"); kv["k"] != "v" {
		t.Errorf("secret/we:ird = %v, want map[k:v]", kv)
	}
}

// Asking for a version the colon-bearing secret does not have reports that
// version as missing, not the secret: the lookup did reach the right secret.
func TestCmdRevertColonBearingPathMissingVersion(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/we:ird", map[string]string{"k": "v"})

	c := newTestCLI(t)
	err := c.cmdRevert("revert", `secret/we\:ird`, "2")
	if err == nil {
		t.Fatal("expected an error reverting to a version that does not exist")
	}
	if !strings.Contains(err.Error(), "Version 2") {
		t.Errorf("error %q should report version 2 as missing", err)
	}
}

// The colon-free control: an ordinary revert to the current version still
// succeeds and leaves the secret alone.
func TestCmdRevertPlainPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/plain", map[string]string{"k": "v"})

	c := newTestCLI(t)
	if err := c.cmdRevert("revert", "secret/plain", "1"); err != nil {
		t.Fatalf("cmdRevert: %v", err)
	}
	if kv := fv.get("secret/plain"); kv["k"] != "v" {
		t.Errorf("secret/plain = %v, want map[k:v]", kv)
	}
}
