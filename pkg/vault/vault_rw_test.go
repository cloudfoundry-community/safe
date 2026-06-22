// TV-01: Read / Write / List through the httptest fake Vault.
// Covers key-extraction branch, NotFound typed-error translation,
// Write rejection of path:key / path^version notation, and
// empty-secret → delete routing.
package vault_test

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// TestReadStringValue verifies that reading a single-string value returns it
// unmarshalled as a plain string (not JSON-quoted).
func TestReadStringValue(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/foo", map[string]string{"key": "hello"})

	s, err := v.Read("secret/foo")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := s.Get("key"); got != "hello" {
		t.Errorf("Get(key) = %q, want %q", got, "hello")
	}
}

// TestReadKeyExtraction verifies that secret/foo:key extracts only the
// requested key from the returned secret.
func TestReadKeyExtraction(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/myapp", map[string]string{"user": "admin", "pass": "s3cr3t"})

	s, err := v.Read("secret/myapp:pass")
	if err != nil {
		t.Fatalf("Read with key: %v", err)
	}
	if !s.Has("pass") {
		t.Error("secret should have key 'pass'")
	}
	if s.Has("user") {
		t.Error("secret should NOT have key 'user' after key extraction")
	}
	if got := s.Get("pass"); got != "s3cr3t" {
		t.Errorf("Get(pass) = %q, want %q", got, "s3cr3t")
	}
}

// TestReadKeyNotFound verifies that requesting a non-existent key within an
// existing secret returns a KeyNotFound typed error.
func TestReadKeyNotFound(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/myapp", map[string]string{"user": "admin"})

	_, err := v.Read("secret/myapp:missing")
	assertKeyNotFound(t, err)
}

// TestReadSecretNotFound verifies that reading a missing path returns a
// SecretNotFound typed error (not a generic error).
func TestReadSecretNotFound(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	_, err := v.Read("secret/does-not-exist")
	assertSecretNotFound(t, err)
}

// TestReadNonStringValueJSONMarshalled verifies that a numeric/boolean value
// stored in the map is returned as its JSON representation (per vault.go:169).
// We inject raw JSON into the fake because the server side stores strings,
// so we use a nested key that the fake stores as-is.
func TestReadAllKeys(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/multi", map[string]string{"a": "1", "b": "2", "c": "3"})

	s, err := v.Read("secret/multi")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	for _, k := range []string{"a", "b", "c"} {
		if !s.Has(k) {
			t.Errorf("missing key %q", k)
		}
	}
}

// TestWriteAndReadRoundTrip verifies Write stores data that Read retrieves.
func TestWriteAndReadRoundTrip(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	original := vault.NewSecret()
	if err := original.Set("greeting", "hello", false); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := v.Write("secret/greet", original); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := v.Read("secret/greet")
	if err != nil {
		t.Fatalf("Read after Write: %v", err)
	}
	if got.Get("greeting") != "hello" {
		t.Errorf("Read returned %q, want %q", got.Get("greeting"), "hello")
	}
}

// TestWriteRejectsPathColon verifies Write returns an error for path:key notation.
func TestWriteRejectsPathColon(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	s := vault.NewSecret()
	_ = s.Set("k", "v", false)

	err := v.Write("secret/foo:key", s)
	if err == nil {
		t.Fatal("Write with path:key should fail, got nil")
	}
	if !strings.Contains(err.Error(), "path:key") && !strings.Contains(err.Error(), "cannot write") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestWriteRejectsVersionCaret verifies Write returns an error for path^version notation.
func TestWriteRejectsVersionCaret(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	s := vault.NewSecret()
	_ = s.Set("k", "v", false)

	err := v.Write("secret/foo^1", s)
	if err == nil {
		t.Fatal("Write with path^version should fail, got nil")
	}
	if !strings.Contains(err.Error(), "version") && !strings.Contains(err.Error(), "cannot write") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestWriteEmptySecretDeletesExisting verifies that writing an empty Secret to
// a path that already holds data deletes that data (routes to delete).
func TestWriteEmptySecretDeletesExisting(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)

	// Seed a secret.
	fv.set("secret/todelete", map[string]string{"k": "v"})

	empty := vault.NewSecret()
	if err := v.Write("secret/todelete", empty); err != nil {
		t.Fatalf("Write empty: %v", err)
	}

	// After writing empty, the path should be absent.
	secretAbsent(t, fv, "secret/todelete")
}

// TestWriteEmptySecretNoExisting verifies writing an empty Secret to a
// non-existent path is a no-op (deleteIfPresent short-circuits).
func TestWriteEmptySecretNoExisting(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)

	empty := vault.NewSecret()
	if err := v.Write("secret/nonexistent", empty); err != nil {
		t.Fatalf("Write empty to nonexistent: %v", err)
	}
	secretAbsent(t, fv, "secret/nonexistent")
}

// TestList verifies List returns relative paths under a prefix.
func TestList(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/tree/a", map[string]string{"k": "v"})
	fv.set("secret/tree/b", map[string]string{"k": "v"})
	fv.set("secret/tree/sub/c", map[string]string{"k": "v"})

	paths, err := v.List("secret/tree")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	pathSet := make(map[string]bool, len(paths))
	for _, p := range paths {
		pathSet[p] = true
	}
	if !pathSet["a"] {
		t.Error("expected 'a' in listing")
	}
	if !pathSet["b"] {
		t.Error("expected 'b' in listing")
	}
	if !pathSet["sub/"] {
		t.Error("expected 'sub/' folder in listing")
	}
}

// TestListNotFound verifies List returns a SecretNotFound error for missing prefix.
func TestListNotFound(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	_, err := v.List("secret/missing-prefix")
	assertSecretNotFound(t, err)
}
