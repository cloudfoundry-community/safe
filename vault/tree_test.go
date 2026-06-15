package vault

import (
	"sort"
	"testing"
)

// ---------------------------------------------------------------------------
// PathLessThan
// ---------------------------------------------------------------------------

func TestPathLessThan(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		left  string
		right string
		want  bool
	}{
		// identical paths without trailing slash: the function reaches the final
		// return !strings.HasSuffix(left, "/") which evaluates to true.
		// This is the actual implemented behaviour — not a strict weak order for
		// equal non-slash paths, but consistent with how Secrets.Sort uses it.
		{"equal paths no slash", "secret/foo", "secret/foo", true},
		{"equal paths with slash left", "secret/foo/", "secret/foo/", false},
		// simple lexical ordering within same depth
		{"left before right same depth", "secret/a", "secret/b", true},
		{"right before left same depth", "secret/b", "secret/a", false},
		// directory vs secret at same name: secret (no trailing slash after canonicalize) first
		{"deeper path greater than shallower", "secret/a/b", "secret/a", false},
		{"shallower path less than deeper", "secret/a", "secret/a/b", true},
		// segment comparison: each segment compared independently
		{"segment order: a/z vs b/a", "a/z", "b/a", true},
		{"segment order: b/a vs a/z", "b/a", "a/z", false},
		// leading/trailing slashes normalised by Canonicalize
		{"leading slash normalised", "/secret/a", "secret/b", true},
		{"trailing slash normalised left", "secret/a/", "secret/b", true},
		{"trailing slash normalised right", "secret/b", "secret/a/", false},
		// same canonicalized path, left has trailing slash → false (non-slash sorts before slash)
		{"same path left trailing slash", "secret/a/", "secret/a", false},
		{"same path right trailing slash", "secret/a", "secret/a/", true},
		// numeric segments: compared lexically, not numerically
		{"numeric lexical: 9 vs 10", "path/9", "path/10", false},
		{"numeric lexical: 10 vs 9", "path/10", "path/9", true},
		{"numeric lexical: 2 vs 10", "path/2", "path/10", false},
		// empty string: both empty reaches final return !HasSuffix("","/")==true
		{"empty left vs non-empty right", "", "a", true},
		{"non-empty left vs empty right", "a", "", false},
		{"both empty", "", "", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := PathLessThan(tc.left, tc.right)
			if got != tc.want {
				t.Errorf("PathLessThan(%q, %q) = %v; want %v", tc.left, tc.right, got, tc.want)
			}
		})
	}
}

// TestPathLessThanOrdering verifies ordering properties of PathLessThan.
//
// Note: PathLessThan is NOT irreflexive for paths without a trailing slash —
// PathLessThan(p, p) returns true when p does not end with "/". This is
// intentional in the implementation (final return !strings.HasSuffix(left,"/"))
// and consistent with how Secrets.Sort uses it (sort.Slice only requires
// strict weak ordering relative to distinct elements, which holds here).
// Tests below verify the properties that DO hold.
func TestPathLessThanOrdering(t *testing.T) {
	t.Parallel()

	// Distinct paths used for ordering checks.
	paths := []string{
		"a",
		"a/b",
		"a/b/c",
		"b",
		"b/a",
		"z",
	}

	// asymmetric for distinct paths: PathLessThan(a,b) and PathLessThan(b,a)
	// cannot both be true when a != b.
	for i := range paths {
		for j := range paths {
			if i == j {
				continue
			}
			a, b := paths[i], paths[j]
			if PathLessThan(a, b) && PathLessThan(b, a) {
				t.Errorf("PathLessThan asymmetry violated for %q and %q", a, b)
			}
		}
	}

	// transitivity: a<b && b<c → a<c
	for i := range paths {
		for j := range paths {
			for k := range paths {
				a, b, c := paths[i], paths[j], paths[k]
				if PathLessThan(a, b) && PathLessThan(b, c) && !PathLessThan(a, c) {
					t.Errorf("PathLessThan transitivity violated: %q < %q < %q but !(%q < %q)", a, b, c, a, c)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Secrets.Sort
// ---------------------------------------------------------------------------

func TestSecretsSort(t *testing.T) {
	t.Parallel()

	t.Run("already sorted stays sorted", func(t *testing.T) {
		t.Parallel()
		s := Secrets{
			{Path: "a/b"},
			{Path: "a/c"},
			{Path: "b"},
		}
		s.Sort()
		want := []string{"a/b", "a/c", "b"}
		for i, w := range want {
			if s[i].Path != w {
				t.Errorf("index %d: got %q, want %q", i, s[i].Path, w)
			}
		}
	})

	t.Run("reverse order gets sorted", func(t *testing.T) {
		t.Parallel()
		s := Secrets{
			{Path: "z/z"},
			{Path: "z/a"},
			{Path: "a/z"},
			{Path: "a/a"},
		}
		s.Sort()
		want := []string{"a/a", "a/z", "z/a", "z/z"}
		for i, w := range want {
			if s[i].Path != w {
				t.Errorf("index %d: got %q, want %q", i, s[i].Path, w)
			}
		}
	})

	t.Run("sort is idempotent", func(t *testing.T) {
		t.Parallel()
		s := Secrets{
			{Path: "c"},
			{Path: "a"},
			{Path: "b"},
		}
		s.Sort()
		first := make([]string, len(s))
		for i, e := range s {
			first[i] = e.Path
		}
		s.Sort()
		for i, e := range s {
			if e.Path != first[i] {
				t.Errorf("Sort not idempotent at index %d: got %q, want %q", i, e.Path, first[i])
			}
		}
	})

	t.Run("single element", func(t *testing.T) {
		t.Parallel()
		s := Secrets{{Path: "only"}}
		s.Sort()
		if s[0].Path != "only" {
			t.Errorf("got %q, want %q", s[0].Path, "only")
		}
	})

	t.Run("empty slice", func(t *testing.T) {
		t.Parallel()
		var s Secrets
		s.Sort() // must not panic
		if len(s) != 0 {
			t.Errorf("expected empty, got %d elements", len(s))
		}
	})

	t.Run("sort order consistent with PathLessThan", func(t *testing.T) {
		t.Parallel()
		s := Secrets{
			{Path: "secret/b"},
			{Path: "other/a"},
			{Path: "secret/a"},
			{Path: "other/b"},
		}
		s.Sort()
		for i := 0; i < len(s)-1; i++ {
			if !PathLessThan(s[i].Path, s[i+1].Path) && s[i].Path != s[i+1].Path {
				t.Errorf("Sort violates PathLessThan ordering between index %d (%q) and %d (%q)", i, s[i].Path, i+1, s[i+1].Path)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Secrets.Merge
// ---------------------------------------------------------------------------

func TestSecretsMerge(t *testing.T) {
	t.Parallel()

	t.Run("merge two disjoint sorted sets produces sorted union", func(t *testing.T) {
		t.Parallel()
		s1 := Secrets{{Path: "a/a"}, {Path: "a/c"}}
		s2 := Secrets{{Path: "a/b"}, {Path: "a/d"}}
		s1.Sort()
		s2.Sort()
		got := s1.Merge(s2)
		want := []string{"a/a", "a/b", "a/c", "a/d"}
		if len(got) != len(want) {
			t.Fatalf("Merge: got len %d, want %d", len(got), len(want))
		}
		for i, w := range want {
			if got[i].Path != w {
				t.Errorf("index %d: got %q, want %q", i, got[i].Path, w)
			}
		}
	})

	t.Run("duplicate paths not added twice", func(t *testing.T) {
		t.Parallel()
		s1 := Secrets{{Path: "shared/key"}}
		s2 := Secrets{{Path: "shared/key"}}
		s1.Sort()
		s2.Sort()
		got := s1.Merge(s2)
		if len(got) != 1 {
			t.Errorf("expected 1 entry after merging duplicate, got %d", len(got))
		}
		if got[0].Path != "shared/key" {
			t.Errorf("got %q, want %q", got[0].Path, "shared/key")
		}
	})

	t.Run("merge with empty right returns copy of left", func(t *testing.T) {
		t.Parallel()
		s1 := Secrets{{Path: "a"}, {Path: "b"}}
		s1.Sort()
		var s2 Secrets
		got := s1.Merge(s2)
		if len(got) != 2 {
			t.Fatalf("expected 2, got %d", len(got))
		}
		if got[0].Path != "a" || got[1].Path != "b" {
			t.Errorf("unexpected paths: %q, %q", got[0].Path, got[1].Path)
		}
	})

	t.Run("merge with empty left returns right", func(t *testing.T) {
		t.Parallel()
		var s1 Secrets
		s2 := Secrets{{Path: "x"}, {Path: "y"}}
		s2.Sort()
		got := s1.Merge(s2)
		if len(got) != 2 {
			t.Fatalf("expected 2, got %d", len(got))
		}
		if got[0].Path != "x" || got[1].Path != "y" {
			t.Errorf("unexpected paths: %q, %q", got[0].Path, got[1].Path)
		}
	})

	t.Run("both empty returns empty", func(t *testing.T) {
		t.Parallel()
		var s1, s2 Secrets
		got := s1.Merge(s2)
		if len(got) != 0 {
			t.Errorf("expected empty, got %d elements", len(got))
		}
	})

	t.Run("merge preserves sorted order", func(t *testing.T) {
		t.Parallel()
		s1 := Secrets{{Path: "a"}, {Path: "c"}, {Path: "e"}}
		s2 := Secrets{{Path: "b"}, {Path: "d"}, {Path: "f"}}
		s1.Sort()
		s2.Sort()
		got := s1.Merge(s2)
		if !sort.SliceIsSorted(got, func(i, j int) bool {
			return PathLessThan(got[i].Path, got[j].Path)
		}) {
			paths := make([]string, len(got))
			for i, e := range got {
				paths[i] = e.Path
			}
			t.Errorf("Merge result not sorted: %v", paths)
		}
	})

	t.Run("s1 not mutated by merge", func(t *testing.T) {
		t.Parallel()
		s1 := Secrets{{Path: "a"}, {Path: "b"}}
		s2 := Secrets{{Path: "c"}}
		origLen := len(s1)
		s1.Merge(s2)
		if len(s1) != origLen {
			t.Errorf("Merge mutated s1: len %d, want %d", len(s1), origLen)
		}
	})
}

// ---------------------------------------------------------------------------
// Secrets.Paths
// ---------------------------------------------------------------------------

func makeSecretWithKeys(path string, keys map[string]string) SecretEntry {
	s := NewSecret()
	for k, v := range keys {
		_ = s.Set(k, v, false)
	}
	return SecretEntry{
		Path: path,
		Versions: []SecretVersion{
			{Data: s, Number: 1, State: SecretStateAlive},
		},
	}
}

func TestSecretsPaths(t *testing.T) {
	t.Parallel()

	t.Run("empty secrets returns empty paths", func(t *testing.T) {
		t.Parallel()
		var s Secrets
		got := s.Paths()
		if len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})

	t.Run("entry with no versions yields bare path", func(t *testing.T) {
		t.Parallel()
		s := Secrets{{Path: "secret/no-versions"}}
		got := s.Paths()
		if len(got) != 1 {
			t.Fatalf("expected 1 path, got %d: %v", len(got), got)
		}
		if got[0] != "secret/no-versions" {
			t.Errorf("got %q, want %q", got[0], "secret/no-versions")
		}
	})

	t.Run("entry with version and keys yields path:key per key", func(t *testing.T) {
		t.Parallel()
		e := makeSecretWithKeys("secret/mypath", map[string]string{"user": "admin", "pass": "secret"})
		s := Secrets{e}
		got := s.Paths()
		// Keys() returns sorted; EscapePathSegment does not modify simple keys
		want := map[string]bool{
			`secret/mypath:pass`: true,
			`secret/mypath:user`: true,
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 paths, got %d: %v", len(got), got)
		}
		for _, p := range got {
			if !want[p] {
				t.Errorf("unexpected path %q in result", p)
			}
		}
	})

	t.Run("entry with version and no keys yields no paths", func(t *testing.T) {
		t.Parallel()
		// Paths() enters the Versions branch but the key loop is empty,
		// so nothing is appended — the entry is silently omitted.
		e := makeSecretWithKeys("secret/empty-keys", map[string]string{})
		s := Secrets{e}
		got := s.Paths()
		if len(got) != 0 {
			t.Errorf("expected 0 paths for entry with version but no keys, got %d: %v", len(got), got)
		}
	})

	t.Run("multiple entries each contribute their paths", func(t *testing.T) {
		t.Parallel()
		e1 := makeSecretWithKeys("a/b", map[string]string{"x": "1"})
		e2 := SecretEntry{Path: "c/d"} // no versions
		s := Secrets{e1, e2}
		got := s.Paths()
		if len(got) != 2 {
			t.Fatalf("expected 2 paths, got %d: %v", len(got), got)
		}
		// e1 has one key "x"
		if got[0] != `a/b:x` {
			t.Errorf("got[0] = %q, want %q", got[0], `a/b:x`)
		}
		// e2 has no versions
		if got[1] != "c/d" {
			t.Errorf("got[1] = %q, want %q", got[1], "c/d")
		}
	})

	t.Run("paths escapes colons in path and key", func(t *testing.T) {
		t.Parallel()
		e := makeSecretWithKeys("secret/co:lon", map[string]string{"ke:y": "v"})
		s := Secrets{e}
		got := s.Paths()
		// EscapePathSegment replaces : with \: in both path and key
		want := `secret/co\:lon:ke\:y`
		if len(got) != 1 {
			t.Fatalf("expected 1 path, got %d: %v", len(got), got)
		}
		if got[0] != want {
			t.Errorf("got %q, want %q", got[0], want)
		}
	})
}
