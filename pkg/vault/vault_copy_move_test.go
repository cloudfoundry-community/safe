// TV-02: Copy / Move guard branches.
// Covers clobber-refusal (SkipIfExists), DeletedVersions-requires-Deep,
// specific-destination-version-not-supported, and Move = Copy + Delete
// leaving source absent and destination present.
package vault_test

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// TestCopyBasic verifies that Copy moves the value from src to dst.
func TestCopyBasic(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/src", map[string]string{"key": "value"})

	err := v.Copy("secret/src", "secret/dst", vault.MoveCopyOpts{Quiet: true})
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}

	kv := mustGetSecret(t, fv, "secret/dst")
	if kv["key"] != "value" {
		t.Errorf("dst key = %q, want %q", kv["key"], "value")
	}
	// src still present after copy.
	if fv.get("secret/src") == nil {
		t.Error("src should still exist after copy")
	}
}

// TestCopySkipIfExists verifies the "Cowardly refusing" clobber-refusal branch:
// when SkipIfExists is set and the destination already contains data, Copy
// returns nil without overwriting.
func TestCopySkipIfExists(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/src", map[string]string{"k": "new"})
	fv.set("secret/dst", map[string]string{"k": "original"})

	err := v.Copy("secret/src", "secret/dst", vault.MoveCopyOpts{
		SkipIfExists: true,
		Quiet:        true,
	})
	if err != nil {
		t.Fatalf("Copy with SkipIfExists: %v", err)
	}

	// Destination must retain original value.
	kv := mustGetSecret(t, fv, "secret/dst")
	if kv["k"] != "original" {
		t.Errorf("dst was overwritten: got %q, want %q", kv["k"], "original")
	}
}

// TestCopyDeletedVersionsRequiresDeep verifies that specifying DeletedVersions
// without Deep returns an error mentioning the constraint.
func TestCopyDeletedVersionsRequiresDeep(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/src", map[string]string{"k": "v"})

	err := v.Copy("secret/src", "secret/dst", vault.MoveCopyOpts{
		DeletedVersions: true,
		Deep:            false,
		Quiet:           true,
	})
	if err == nil {
		t.Fatal("expected error for DeletedVersions without Deep, got nil")
	}
	if !strings.Contains(err.Error(), "Deep") && !strings.Contains(err.Error(), "DeletedVersions") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestCopyToVersionNotSupported verifies that specifying a destination version
// (path^N syntax) returns the appropriate error.
func TestCopyToVersionNotSupported(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/src", map[string]string{"k": "v"})

	err := v.Copy("secret/src", "secret/dst^1", vault.MoveCopyOpts{Quiet: true})
	if err == nil {
		t.Fatal("expected error for destination version, got nil")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestMoveLeavesSrcAbsentAndDstPresent verifies that Move copies the value to
// the destination and removes the source.
func TestMoveLeavesSrcAbsentAndDstPresent(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/movesrc", map[string]string{"val": "data"})

	err := v.Move("secret/movesrc", "secret/movedst", vault.MoveCopyOpts{Quiet: true})
	if err != nil {
		t.Fatalf("Move: %v", err)
	}

	// Source must be absent.
	secretAbsent(t, fv, "secret/movesrc")

	// Destination must contain the value.
	kv := mustGetSecret(t, fv, "secret/movedst")
	if kv["val"] != "data" {
		t.Errorf("dst val = %q, want %q", kv["val"], "data")
	}
}

// TestCopySingleKeyToExistingDest verifies that copying a single key (path:key)
// to an existing secret merges the key without destroying other keys.
func TestCopySingleKeyToExistingDest(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/src", map[string]string{"username": "admin", "password": "secret"})
	fv.set("secret/dst", map[string]string{"other": "keep"})

	err := v.Copy("secret/src:username", "secret/dst", vault.MoveCopyOpts{Quiet: true})
	if err != nil {
		t.Fatalf("Copy key: %v", err)
	}

	// Verify dst has both the original key and the copied key.
	kv := mustGetSecret(t, fv, "secret/dst")
	if kv["username"] != "admin" {
		t.Errorf("dst username = %q, want %q", kv["username"], "admin")
	}
	if kv["other"] != "keep" {
		t.Errorf("dst other = %q, want %q", kv["other"], "keep")
	}
}

// TestCopySrcNotFound verifies that copying from a nonexistent source returns
// a SecretNotFound error.
func TestCopySrcNotFound(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	err := v.Copy("secret/nonexistent", "secret/dst", vault.MoveCopyOpts{Quiet: true})
	if err == nil {
		t.Fatal("expected error copying from nonexistent src, got nil")
	}
	if !vault.IsNotFound(err) {
		t.Errorf("expected IsNotFound error, got: %v", err)
	}
}

// TestMoveCopyTreeClobberRefusal verifies that MoveCopyTree with SkipIfExists
// refuses to overwrite when a destination path already exists.
func TestMoveCopyTreeClobberRefusal(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/from/a", map[string]string{"k": "from"})
	fv.set("secret/to/a", map[string]string{"k": "original"})

	err := v.MoveCopyTree(
		"secret/from",
		"secret/to",
		false,
		vault.MoveCopyOpts{SkipIfExists: true, Quiet: true},
	)
	if err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}

	// Destination value must be unchanged.
	kv := mustGetSecret(t, fv, "secret/to/a")
	if kv["k"] != "original" {
		t.Errorf("dst was overwritten: got %q, want %q", kv["k"], "original")
	}
}
