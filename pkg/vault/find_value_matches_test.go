// Coverage for FindValueMatches: exact-value matching across a subtree, the
// --keys vs path-only output shapes, multi-value and multi-path searches,
// partial failure, overlapping walks, sort order, output escaping, and the
// forbidden-skip counter.
package vault_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// seedValueTree populates a small tree in which "secret123" appears in three
// different secrets, under three differently-named keys.
func seedValueTree(fv *fakeVault) {
	fv.set("secret/test1", map[string]string{
		"username": "admin",
		"password": "secret123",
		"api_key":  "abc123",
	})
	fv.set("secret/test2", map[string]string{
		"token":    "secret123",
		"username": "user",
		"code":     "xyz789",
	})
	fv.set("secret/nested/path", map[string]string{
		"password": "secret123",
		"apikey":   "different",
	})
}

func TestFindValueMatchesShowKeys(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	seedValueTree(fv)

	got, skipped, err := v.FindValueMatches([]string{"secret"}, []string{"secret123"}, true)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0", skipped)
	}

	want := []string{
		"secret/nested/path:password",
		"secret/test1:password",
		"secret/test2:token",
	}
	if !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(--keys) = %v, want %v", got, want)
	}
}

func TestFindValueMatchesPathsOnly(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	seedValueTree(fv)

	got, _, err := v.FindValueMatches([]string{"secret"}, []string{"secret123"}, false)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}

	want := []string{"secret/nested/path", "secret/test1", "secret/test2"}
	if !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(paths) = %v, want %v", got, want)
	}
}

// A secret with two matching keys must be reported exactly once when keys are
// not being shown.
func TestFindValueMatchesDeduplicatesPaths(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	seedValueTree(fv)

	got, _, err := v.FindValueMatches([]string{"secret"}, []string{"admin", "secret123"}, false)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}

	want := []string{"secret/nested/path", "secret/test1", "secret/test2"}
	if !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(paths) = %v, want %v", got, want)
	}
}

func TestFindValueMatchesMultipleValues(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	seedValueTree(fv)

	got, _, err := v.FindValueMatches([]string{"secret"}, []string{"secret123", "abc123"}, true)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}

	want := []string{
		"secret/nested/path:password",
		"secret/test1:api_key",
		"secret/test1:password",
		"secret/test2:token",
	}
	if !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(multi-value) = %v, want %v", got, want)
	}
}

// Searching several explicit leaf paths must union their results, and must not
// pick up secrets outside those paths.
func TestFindValueMatchesMultiplePaths(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	seedValueTree(fv)

	got, _, err := v.FindValueMatches(
		[]string{"secret/test1", "secret/test2"}, []string{"admin", "user"}, true)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}

	want := []string{"secret/test1:username", "secret/test2:username"}
	if !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(multi-path) = %v, want %v", got, want)
	}
}

func TestFindValueMatchesNoMatches(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	seedValueTree(fv)

	got, _, err := v.FindValueMatches([]string{"secret"}, []string{"nonexistent"}, true)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("FindValueMatches(no match) = %v, want empty", got)
	}
}

// Matching is on the whole value, not a substring of it.
func TestFindValueMatchesIsExactNotSubstring(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/app", map[string]string{"password": "secret123456"})

	got, _, err := v.FindValueMatches([]string{"secret"}, []string{"secret123"}, true)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("FindValueMatches(substring) = %v, want empty", got)
	}
}

// A value containing a colon is matched literally; only the emitted path and
// key segments are escaped.
func TestFindValueMatchesValueWithColon(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/app", map[string]string{"url": "https://example.com:8443"})

	got, _, err := v.FindValueMatches(
		[]string{"secret"}, []string{"https://example.com:8443"}, true)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}

	want := []string{"secret/app:url"}
	if !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(colon value) = %v, want %v", got, want)
	}
}

func TestFindValueMatchesNonexistentPathErrors(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	if _, _, err := v.FindValueMatches(
		[]string{"nonexistent/path"}, []string{"value"}, true); err == nil {
		t.Error("FindValueMatches on a missing path should return an error")
	}
}

// An empty target-value list must match nothing, rather than matching every
// secret via a zero-value lookup.
func TestFindValueMatchesEmptyTargets(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	seedValueTree(fv)

	got, _, err := v.FindValueMatches([]string{"secret"}, nil, false)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("FindValueMatches(no targets) = %v, want empty", got)
	}
}

// Vault stores no empty secrets, but a key whose value is "" must only match an
// explicit empty target.
func TestFindValueMatchesEmptyStringValue(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/app", map[string]string{"blank": "", "other": "x"})

	got, _, err := v.FindValueMatches([]string{"secret"}, []string{""}, true)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}

	want := []string{"secret/app:blank"}
	if !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(empty value) = %v, want %v", got, want)
	}
}

// A failing path must not discard matches already gathered from the paths
// that succeeded: partial results come back alongside the error naming the
// path that failed.
func TestFindValueMatchesPartialFailure(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	seedValueTree(fv)

	got, _, err := v.FindValueMatches(
		[]string{"secret", "nonexistent/x"}, []string{"secret123"}, false)
	if err == nil {
		t.Fatal("expected an error for the unwalkable path, got nil")
	}
	if !strings.Contains(err.Error(), "nonexistent/x") {
		t.Errorf("error %q should name the failing path nonexistent/x", err)
	}

	want := []string{"secret/nested/path", "secret/test1", "secret/test2"}
	if !slices.Equal(got, want) {
		t.Errorf("partial results = %v, want %v", got, want)
	}
}

// Overlapping search paths walk some secrets twice; each match must still be
// reported once.
func TestFindValueMatchesOverlappingPaths(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	seedValueTree(fv)

	got, _, err := v.FindValueMatches(
		[]string{"secret", "secret/nested"}, []string{"secret123"}, true)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}

	want := []string{
		"secret/nested/path:password",
		"secret/test1:password",
		"secret/test2:token",
	}
	if !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(overlapping) = %v, want %v", got, want)
	}
}

// Results sort by PathLessThan, which orders path segments hierarchically:
// secret/a/x comes before secret/a-b even though a bytewise sort would put
// '-' (0x2d) before '/' (0x2f).
func TestFindValueMatchesSortsByPathLessThan(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/a-b", map[string]string{"k": "match"})
	fv.set("secret/a/x", map[string]string{"k": "match"})

	got, _, err := v.FindValueMatches([]string{"secret"}, []string{"match"}, false)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}

	want := []string{"secret/a/x", "secret/a-b"}
	if !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(order) = %v, want %v", got, want)
	}
}

// Output escaping matches Secrets.Paths(): colons and carets are escaped in
// the path segment and, with --keys, in the key segment too.
func TestFindValueMatchesEscapingMatchesPaths(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/odd:colon", map[string]string{"od^d": "match"})

	got, _, err := v.FindValueMatches([]string{"secret"}, []string{"match"}, true)
	if err != nil {
		t.Fatalf("FindValueMatches(--keys): %v", err)
	}
	want := []string{`secret/odd\:colon:od\^d`}
	if !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(--keys escaping) = %v, want %v", got, want)
	}

	// Same expectation Secrets.Paths() produces for this secret.
	s, err := v.ConstructSecrets("secret", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}
	if paths := s.Paths(); !slices.Equal(paths, want) {
		t.Errorf("Secrets.Paths() = %v, want %v (escaping must stay in lockstep)", paths, want)
	}

	got, _, err = v.FindValueMatches([]string{"secret"}, []string{"match"}, false)
	if err != nil {
		t.Fatalf("FindValueMatches(paths): %v", err)
	}
	if want := []string{`secret/odd\:colon`}; !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(bare path) = %v, want %v", got, want)
	}
}

// Forbidden subtrees are skipped, counted, and do not fail the search.
func TestFindValueMatchesCountsForbiddenSkips(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	seedValueTree(fv)
	fv.set("secret/hidden/deep", map[string]string{"k": "secret123"})
	fv.forbid("secret/hidden")

	got, skipped, err := v.FindValueMatches([]string{"secret"}, []string{"secret123"}, false)
	if err != nil {
		t.Fatalf("FindValueMatches: %v", err)
	}
	if skipped == 0 {
		t.Error("skipped = 0, want > 0 for the forbidden subtree")
	}

	want := []string{"secret/nested/path", "secret/test1", "secret/test2"}
	if !slices.Equal(got, want) {
		t.Errorf("FindValueMatches(forbidden sibling) = %v, want %v", got, want)
	}
}
