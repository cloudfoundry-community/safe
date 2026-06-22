// TV-03: verifySecretState / verifySecretExists / errIfFolder behavior.
// These unexported helpers are exercised through public methods (Delete, Copy)
// that call them. Key case: folder collision is NOT downgraded to SecretNotFound
// even under -f; verified by checking the error is non-nil and not IsNotFound.
package vault_test

import (
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// TestErrIfFolderNotDowngraded verifies that when a path points to a folder
// (has children) rather than a secret, the error returned by operations that
// call errIfFolder is NOT a SecretNotFound error. This pins the intentional
// exception documented in vault.go:220-221.
func TestErrIfFolderNotDowngraded(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	// Create a child so "secret/folder" is a folder path, not a leaf.
	fv.set("secret/folder/child", map[string]string{"k": "v"})

	// Attempting to Copy FROM a folder path triggers verifySecretExists, which
	// calls errIfFolder. The error must be non-nil and must NOT be IsNotFound.
	err := v.Copy("secret/folder", "secret/dst", vault.MoveCopyOpts{Quiet: true})
	if err == nil {
		t.Fatal("expected error when source is a folder, got nil")
	}
	// errIfFolder explicitly does NOT use NewSecretNotFoundError; verify.
	if vault.IsSecretNotFound(err) {
		t.Errorf("folder error should NOT be a SecretNotFound error, but IsSecretNotFound = true; err = %v", err)
	}
}

// TestVerifySecretExistsMissing verifies that Delete on a nonexistent path
// returns an IsNotFound error (exercises verifySecretState → missing branch).
func TestVerifySecretExistsMissing(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	err := v.Delete("secret/no-such-secret", vault.DeleteOpts{})
	if err == nil {
		t.Fatal("expected error deleting nonexistent secret, got nil")
	}
	if !vault.IsNotFound(err) {
		t.Errorf("expected IsNotFound error, got: %v", err)
	}
}

// TestVerifySecretExistsPresent verifies that Delete on an existing secret
// succeeds (verifySecretExists path — alive state).
func TestVerifySecretExistsPresent(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/present", map[string]string{"k": "v"})

	err := v.Delete("secret/present", vault.DeleteOpts{})
	if err != nil {
		t.Fatalf("Delete existing: %v", err)
	}
	secretAbsent(t, fv, "secret/present")
}

// TestDeleteSpecificKeyLeaveOthers verifies that deleting a specific key
// (path:key) removes only that key and leaves sibling keys intact.
func TestDeleteSpecificKeyLeaveOthers(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/multi", map[string]string{"a": "1", "b": "2"})

	err := v.Delete("secret/multi:a", vault.DeleteOpts{})
	if err != nil {
		t.Fatalf("Delete key: %v", err)
	}

	kv := mustGetSecret(t, fv, "secret/multi")
	if _, ok := kv["a"]; ok {
		t.Error("key 'a' should have been deleted")
	}
	if kv["b"] != "2" {
		t.Errorf("key 'b' = %q, want %q", kv["b"], "2")
	}
}

// TestDeleteSpecificKeyMissing verifies deleting a nonexistent key returns
// KeyNotFound.
func TestDeleteSpecificKeyMissing(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/one", map[string]string{"k": "v"})

	err := v.Delete("secret/one:no-such-key", vault.DeleteOpts{})
	if err == nil {
		t.Fatal("expected KeyNotFound error, got nil")
	}
	assertKeyNotFound(t, err)
}

// TestDeleteAllKeysDeletesSecret verifies that deleting the last key from a
// secret removes the secret entirely (deleteSpecificKey → deleteEntireSecret path).
func TestDeleteAllKeysDeletesSecret(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/single", map[string]string{"only": "val"})

	err := v.Delete("secret/single:only", vault.DeleteOpts{})
	if err != nil {
		t.Fatalf("Delete last key: %v", err)
	}
	secretAbsent(t, fv, "secret/single")
}
