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

// ---------------------------------------------------------------------------
// Colons and carets in the secret PATH (as opposed to the key)
// ---------------------------------------------------------------------------

// Paths() must escape the path it emits for keyless entries, so that what the
// tree walk hands to callers parses back to the path it came from.
func TestSecretsPathsEscapesColonPaths(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/tree/od:d", map[string]string{"k": "v"})

	s, err := v.ConstructSecrets("secret/tree", vault.TreeOpts{
		FetchKeys: false, SkipVersionInfo: true,
	})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	want := []string{`secret/tree/od\:d`}
	if got := s.Paths(); !slices.Equal(got, want) {
		t.Errorf("Paths() = %v, want %v", got, want)
	}
	secret, key, _ := vault.ParsePath(`secret/tree/od\:d`)
	if secret != "secret/tree/od:d" || key != "" {
		t.Errorf("ParsePath round-trip = (%q, %q), want (secret/tree/od:d, \"\")", secret, key)
	}
}

// safe rm -r must delete the colon-bearing secret it walked, not the sibling
// whose name is that path truncated at the colon.
func TestDeleteTreePreservesColonPaths(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/tree/od:d", map[string]string{"k": "v"})
	fv.set("secret/tree/od", map[string]string{"k2": "v2"})

	if err := v.DeleteTree("secret/tree", vault.DeleteOpts{}); err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	secretAbsent(t, fv, "secret/tree/od:d")
	secretAbsent(t, fv, "secret/tree/od")
}

// The caret twin: a walked path ending in ^<digits> must not be read back as a
// version of its prefix.
func TestDeleteTreePreservesCaretPaths(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/tree/od^2", map[string]string{"k": "v"})
	fv.set("secret/tree/od", map[string]string{"k2": "v2"})

	if err := v.DeleteTree("secret/tree", vault.DeleteOpts{}); err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	secretAbsent(t, fv, "secret/tree/od^2")
	secretAbsent(t, fv, "secret/tree/od")
}

// safe cp -R must relocate a colon-bearing secret whole, and must not mistake
// it for a key of its truncated sibling.
func TestMoveCopyTreePreservesColonPaths(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/sub/od:d", map[string]string{"k": "v"})
	fv.set("secret/sub/od", map[string]string{"k2": "v2"})

	err := v.MoveCopyTree("secret/sub", "secret/dst", v.Copy, vault.MoveCopyOpts{Quiet: true})
	if err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}
	if kv := mustGetSecret(t, fv, "secret/dst/od:d"); kv["k"] != "v" {
		t.Errorf("dst/od:d = %v, want map[k:v]", kv)
	}
	if kv := mustGetSecret(t, fv, "secret/dst/od"); kv["k2"] != "v2" {
		t.Errorf("dst/od = %v, want map[k2:v2]", kv)
	}
}

// A user who escapes a literal colon must get a walk rooted at the real path.
func TestDeleteTreeAcceptsEscapedRoot(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/od:d/leaf", map[string]string{"k": "v"})
	fv.set("secret/od/other", map[string]string{"k": "v"})

	if err := v.DeleteTree(`secret/od\:d`, vault.DeleteOpts{}); err != nil {
		t.Fatalf("DeleteTree: %v", err)
	}
	secretAbsent(t, fv, "secret/od:d/leaf")
	if kv := mustGetSecret(t, fv, "secret/od/other"); kv["k"] != "v" {
		t.Errorf("unrelated secret/od/other was disturbed: %v", kv)
	}
}

// The same at both ends of a recursive copy: source and destination roots may
// each carry an escaped colon.
func TestMoveCopyTreeAcceptsEscapedRoots(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/od:d/leaf", map[string]string{"k": "v"})

	err := v.MoveCopyTree(`secret/od\:d`, `secret/ne\:w`, v.Copy, vault.MoveCopyOpts{Quiet: true})
	if err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}
	if kv := mustGetSecret(t, fv, "secret/ne:w/leaf"); kv["k"] != "v" {
		t.Errorf("secret/ne:w/leaf = %v, want map[k:v]", kv)
	}
}

// The prefix replace in MoveCopyTree rewrites a walked path against the root.
// Both must be in the same vocabulary, or a colon inside the replaced prefix
// stops matching and the subtree lands somewhere else.
func TestMoveCopyTreeReplacesColonBearingPrefix(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/o:d/a/b", map[string]string{"k": "v"})

	err := v.MoveCopyTree(`secret/o\:d`, "secret/plain", v.Copy, vault.MoveCopyOpts{Quiet: true})
	if err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}
	if kv := mustGetSecret(t, fv, "secret/plain/a/b"); kv["k"] != "v" {
		t.Errorf("secret/plain/a/b = %v, want map[k:v]", kv)
	}
}

// Clobber detection compares walked paths against walked paths. Both sides must
// move to the escaped vocabulary together, or an existing colon-bearing secret
// becomes invisible to the check and gets overwritten. This holds before and
// after the root change; it must not flip.
func TestMoveCopyTreeSkipIfExistsWithColonPaths(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/sub/o:d", map[string]string{"k": "new"})
	fv.set("secret/dst/o:d", map[string]string{"k": "old"})

	err := v.MoveCopyTree("secret/sub", "secret/dst", v.Copy,
		vault.MoveCopyOpts{Quiet: true, SkipIfExists: true})
	if err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}
	if kv := mustGetSecret(t, fv, "secret/dst/o:d"); kv["k"] != "old" {
		t.Errorf("dst/o:d = %v, want map[k:old] (copy should have been refused)", kv)
	}
}

// tree display escapes path segments and the printed root, not just keys, so
// what is on screen is what a user can paste back into another command.
func TestDrawEscapesColonPaths(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/o:d/leaf", map[string]string{"k": "v"})

	s, err := v.ConstructSecrets("secret/o:d", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}
	out := s.Draw("secret/o:d", false, true)
	if !strings.Contains(out, `o\:d`) {
		t.Errorf("Draw output %q should escape the colon in the path root", out)
	}
	if strings.Contains(out, "o:d/") && !strings.Contains(out, `o\:d/`) {
		t.Errorf("Draw output %q printed an unescaped path segment", out)
	}
}

// The tree walk names key nodes "<raw path>:<escaped key>". Basename splits at
// the last colon not preceded by a backslash, which is always the join colon,
// so a colon or caret in the path half cannot steal the key. This locks that
// reasoning in; it holds before and after the Paths() change.
func TestBasenameRecoversKeyFromColonPath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, leaf, key string }{
		{"colon in path", "od:d", "k"},
		{"colon in path and key", "od:d", "o:k"},
		{"caret in path", "od^2", "k"},
		{"caret-digits path, colon key", "a^9", "o:k"},
		{"backslash-colon in path", `od\:d`, "k"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, fv := newTestVault(t)
			fv.set("secret/tree/"+tc.leaf, map[string]string{tc.key: "v"})

			s, err := v.ConstructSecrets("secret/tree", vault.TreeOpts{FetchKeys: true})
			if err != nil {
				t.Fatalf("ConstructSecrets: %v", err)
			}
			if len(s) != 1 || len(s[0].Versions) == 0 {
				t.Fatalf("walk returned %+v", s)
			}
			keys := s[0].Versions[len(s[0].Versions)-1].Data.Keys()
			if !slices.Equal(keys, []string{tc.key}) {
				t.Errorf("keys = %q, want [%q]", keys, tc.key)
			}
		})
	}
}
