package vault

import (
	"fmt"
	"testing"
)

// A Vault path is an arbitrary string, and any client can create one that ends
// in a backslash. safe's own path syntax has to survive those, because the
// tree walk re-parses paths it built itself: a name that cannot be encoded and
// parsed back breaks every command that walks a subtree, not just the one
// secret.

func TestEscapePathSegmentEscapesBackslash(t *testing.T) {
	cases := []struct {
		segment string
		want    string
	}{
		{`plain`, `plain`},
		{`trailing\`, `trailing\\`},
		{`mid\dle`, `mid\\dle`},
		{`two\\`, `two\\\\`},
		{`colon:`, `colon\:`},
		{`caret^`, `caret\^`},
		{`both\:`, `both\\\:`},
	}

	for _, c := range cases {
		if got := EscapePathSegment(c.segment); got != c.want {
			t.Errorf("EscapePathSegment(%q) = %q, want %q", c.segment, got, c.want)
		}
	}
}

func TestParsePathSplitsAfterEscapedBackslash(t *testing.T) {
	cases := []struct {
		in      string
		secret  string
		key     string
		version uint64
	}{
		// The encoded form of a path ending in a backslash. Before the escape
		// alphabet included the backslash itself, the caret here looked
		// escaped, and the whole string was read as one literal path.
		{`secret/bad\\^1`, `secret/bad\`, ``, 1},
		{`secret/bad\\:key`, `secret/bad\`, `key`, 0},
		{`secret/bad\\:key^2`, `secret/bad\`, `key`, 2},
		// A key ending in a backslash, with a version after it.
		{`secret/a:key\\^3`, `secret/a`, `key\`, 3},
		// A genuinely escaped separator still belongs to the segment.
		{`secret/a\:b`, `secret/a:b`, ``, 0},
		{`secret/a\^b`, `secret/a^b`, ``, 0},
		{`secret/a\:b:key`, `secret/a:b`, `key`, 0},
		// A lone trailing backslash has nothing to escape, so it is literal.
		// This is what a user gets by typing the raw Vault path.
		{`secret/bad\`, `secret/bad\`, ``, 0},
		// A backslash before an ordinary character is not an escape, and both
		// characters survive.
		{`secret/a\b`, `secret/a\b`, ``, 0},
	}

	for _, c := range cases {
		secret, key, version := ParsePath(c.in)
		if secret != c.secret || key != c.key || version != c.version {
			t.Errorf("ParsePath(%q) = (%q, %q, %d), want (%q, %q, %d)",
				c.in, secret, key, version, c.secret, c.key, c.version)
		}
	}
}

// TestEncodeParseRoundTrip sweeps every short combination of the characters
// that matter, so that no encoded path parses back as something else. The
// alphabet is deliberately small and nasty: the separators, the escape
// character, and one ordinary rune.
func TestEncodeParseRoundTrip(t *testing.T) {
	alphabet := []string{`a`, `\`, `:`, `^`}

	var segments []string
	for _, one := range alphabet {
		segments = append(segments, one)
		for _, two := range alphabet {
			segments = append(segments, one+two)
			for _, three := range alphabet {
				segments = append(segments, one+two+three)
			}
		}
	}

	versions := []uint64{0, 1, 42}
	checked := 0

	for _, path := range segments {
		for _, key := range append([]string{""}, segments...) {
			for _, version := range versions {
				encoded := EncodePath(path, key, version)
				gotPath, gotKey, gotVersion := ParsePath(encoded)
				checked++

				// EncodePath canonicalizes on the way back out, so compare
				// against the canonical form of what went in.
				wantPath := Canonicalize(path)
				if gotPath != wantPath || gotKey != key || gotVersion != version {
					t.Errorf("round trip of (%q, %q, %d) encoded to %q, parsed back as (%q, %q, %d)",
						path, key, version, encoded, gotPath, gotKey, gotVersion)
				}
			}
		}
	}

	if checked == 0 {
		t.Fatal("round trip sweep checked nothing")
	}
	t.Logf("checked %d round trips", checked)
}

// TestEncodedVersionAlwaysParses pins the specific shape the tree walk builds:
// a literal Vault path plus a version. This is the exact call at tree.go's
// version fetch, and the one that used to fail for backslash-suffixed names.
func TestEncodedVersionAlwaysParses(t *testing.T) {
	for _, name := range []string{`bad\`, `ok`, `two\\`, `mid\dle`, `co:lon`, `car^et`} {
		path := "secret/good/" + name
		encoded := EncodePath(path, "", 1)
		gotPath, gotKey, gotVersion := ParsePath(encoded)

		if gotPath != path || gotKey != "" || gotVersion != 1 {
			t.Errorf("EncodePath(%q, \"\", 1) = %q, parsed back as (%q, %q, %d)",
				path, encoded, gotPath, gotKey, gotVersion)
		}
	}
}

func ExampleEscapePathSegment() {
	fmt.Println(EncodePath(`secret/ends-in\`, "password", 2))
	// Output: secret/ends-in\\:password^2
}
