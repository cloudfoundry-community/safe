// Regression coverage for keys containing colons (and carets). The tree walk
// joins path and key with ":" to name key nodes; without escaping that join,
// Basename truncates "odd:key" to "key", silently renaming keys in every
// consumer of the walk: copy, move, export, and paths/tree --keys.
package vault_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// The tree walk must hand back key names exactly as stored, colons included.
func TestConstructSecrets_PreservesColonKeys(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/odd", map[string]string{
		"odd:key": "colon value",
		"od^d":    "caret value",
		"plain":   "plain value",
	})

	s, err := v.ConstructSecrets("secret/odd", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}
	if len(s) != 1 || len(s[0].Versions) == 0 {
		t.Fatalf("expected one secret with versions, got %+v", s)
	}

	got := s[0].Versions[len(s[0].Versions)-1].Data
	wantKeys := []string{"od^d", "odd:key", "plain"}
	if keys := got.Keys(); !slices.Equal(keys, wantKeys) {
		t.Fatalf("Keys() = %v, want %v", keys, wantKeys)
	}
	if val := got.Get("odd:key"); val != "colon value" {
		t.Errorf("Get(odd:key) = %q, want %q", val, "colon value")
	}
	if val := got.Get("od^d"); val != "caret value" {
		t.Errorf("Get(od^d) = %q, want %q", val, "caret value")
	}
}

// Copying a whole secret must not rename its colon-bearing keys.
func TestCopyPreservesColonKeys(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/src", map[string]string{"odd:key": "value", "plain": "x"})

	if err := v.Copy("secret/src", "secret/dst", vault.MoveCopyOpts{Quiet: true}); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	kv := mustGetSecret(t, fv, "secret/dst")
	if kv["odd:key"] != "value" {
		t.Errorf("dst[odd:key] = %q, want %q (keys: %v)", kv["odd:key"], "value", kv)
	}
	if _, renamed := kv["key"]; renamed {
		t.Error("dst contains truncated key \"key\"; colon key was renamed")
	}
}

// Tree-form copy (what safe cp -R does per path) must preserve colon keys in
// every secret of the subtree.
func TestMoveCopyTreePreservesColonKeys(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/sub/a", map[string]string{"odd:key": "va"})
	fv.set("secret/sub/b/c", map[string]string{"other:key": "vc"})

	err := v.MoveCopyTree("secret/sub", "secret/dst", v.Copy, vault.MoveCopyOpts{Quiet: true})
	if err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}

	if kv := mustGetSecret(t, fv, "secret/dst/a"); kv["odd:key"] != "va" {
		t.Errorf("dst/a[odd:key] = %q, want %q (keys: %v)", kv["odd:key"], "va", kv)
	}
	if kv := mustGetSecret(t, fv, "secret/dst/b/c"); kv["other:key"] != "vc" {
		t.Errorf("dst/b/c[other:key] = %q, want %q (keys: %v)", kv["other:key"], "vc", kv)
	}
}

// paths --keys output escapes colons and carets in the key segment so the
// printed path:key round-trips through ParsePath.
func TestSecretsPathsEscapesColonKeys(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/odd", map[string]string{"odd:key": "v", "od^d": "w"})

	s, err := v.ConstructSecrets("secret/odd", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	want := []string{`secret/odd:od\^d`, `secret/odd:odd\:key`}
	if got := s.Paths(); !slices.Equal(got, want) {
		t.Errorf("Paths() = %v, want %v", got, want)
	}

	// The escaped form must parse back to the original secret and key.
	secret, key, _ := vault.ParsePath(`secret/odd:odd\:key`)
	if secret != "secret/odd" || key != "odd:key" {
		t.Errorf("ParsePath round-trip = (%q, %q), want (secret/odd, odd:key)", secret, key)
	}
}

// tree --keys renders key names escaped, so the display is unambiguous.
func TestDrawEscapesColonKeys(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/odd", map[string]string{"odd:key": "v"})

	s, err := v.ConstructSecrets("secret/odd", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	out := s.Draw("secret/odd", false, true)
	if !strings.Contains(out, `:odd\:key`) {
		t.Errorf("Draw output %q should contain escaped key %q", out, `:odd\:key`)
	}
}

// ---------------------------------------------------------------------------
// Recursive roots that name a key or a version
// ---------------------------------------------------------------------------

// A recursive delete whose root names a key or a version is a user mistake.
// It must be refused, not silently widened to the whole subtree.
func TestDeleteTreeRejectsKeyOrVersionRoot(t *testing.T) {
	t.Parallel()
	for _, root := range []string{"secret/foo:key^2", "secret/foo:key", "secret/foo^2"} {
		t.Run(root, func(t *testing.T) {
			t.Parallel()
			v, fv := newTestVault(t)
			fv.set("secret/foo", map[string]string{"key": "v", "other": "keep"})
			fv.set("secret/foo/a", map[string]string{"k": "1"})

			err := v.DeleteTree(root, vault.DeleteOpts{})
			if err == nil || !strings.Contains(err.Error(), "specific key or version") {
				t.Fatalf("DeleteTree(%q) = %v, want a specific-key-or-version refusal", root, err)
			}
			if kv := mustGetSecret(t, fv, "secret/foo"); kv["other"] != "keep" {
				t.Errorf("secret/foo was modified: %v", kv)
			}
			if kv := mustGetSecret(t, fv, "secret/foo/a"); kv["k"] != "1" {
				t.Errorf("secret/foo/a was deleted: %v", kv)
			}
		})
	}
}

// The same for a recursive copy or move: a versioned or keyed root silently
// drops the version, so refuse it instead of relocating the whole subtree.
func TestMoveCopyTreeRejectsKeyOrVersionRoot(t *testing.T) {
	t.Parallel()
	for _, root := range []string{"secret/src^2", "secret/src:k"} {
		t.Run(root, func(t *testing.T) {
			t.Parallel()
			v, fv := newTestVault(t)
			fv.set("secret/src/a", map[string]string{"k": "1"})

			err := v.MoveCopyTree(root, "secret/dst", v.Copy, vault.MoveCopyOpts{Quiet: true})
			if err == nil || !strings.Contains(err.Error(), "specific key or version") {
				t.Fatalf("MoveCopyTree(%q) = %v, want a specific-key-or-version refusal", root, err)
			}
			secretAbsent(t, fv, "secret/dst/a")
		})
	}
}
