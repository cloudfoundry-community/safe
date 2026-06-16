package vault_test

import (
	"fmt"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func TestParsePath(t *testing.T) {
	type ioStruct struct{ in, out, desc string }

	paths := []ioStruct{
		{"secret/foo", "secret/foo", "basic"},
		{`secret/f\:oo`, "secret/f:oo", "escaped-colon"},
		{`secret/f\^oo`, "secret/f^oo", "escaped-caret"},
	}

	keys := []ioStruct{
		{"bar", "bar", "basic"},
		{`b\:ar`, "b:ar", "escaped-colon"},
		{`b\^ar`, "b^ar", "escaped-caret"},
	}

	versions := []struct {
		in   string
		out  uint64
		desc string
	}{
		{"0", 0, "zero"},
		{"21", 21, "positive"},
	}

	// buildInput assembles fullInPath from path/key/version components,
	// mirroring the original JustBeforeEach logic exactly.
	buildInput := func(inPath, inKey, inVersion string) string {
		s := inPath
		if inKey != "" {
			s = s + ":" + inKey
		}
		if inVersion != "" {
			s = s + "^" + inVersion
		}
		return s
	}

	assertParsePath := func(t *testing.T, input, wantPath, wantKey string, wantVersion uint64) {
		t.Helper()
		gotPath, gotKey, gotVersion := vault.ParsePath(input)
		if gotPath != wantPath {
			t.Errorf("ParsePath(%q) path = %q, want %q", input, gotPath, wantPath)
		}
		if gotKey != wantKey {
			t.Errorf("ParsePath(%q) key = %q, want %q", input, gotKey, wantKey)
		}
		if gotVersion != wantVersion {
			t.Errorf("ParsePath(%q) version = %d, want %d", input, gotVersion, wantVersion)
		}
	}

	// path only, no key, no version
	for _, p := range paths {
		p := p
		t.Run(fmt.Sprintf("path-%s/no-key/no-version", p.desc), func(t *testing.T) {
			assertParsePath(t, buildInput(p.in, "", ""), p.out, "", 0)
		})
	}

	// path + key, no version; path + key + version
	for _, p := range paths {
		p := p
		for _, k := range keys {
			k := k
			t.Run(fmt.Sprintf("path-%s/key-%s/no-version", p.desc, k.desc), func(t *testing.T) {
				assertParsePath(t, buildInput(p.in, k.in, ""), p.out, k.out, 0)
			})

			for _, v := range versions {
				v := v
				t.Run(fmt.Sprintf("path-%s/key-%s/version-%s", p.desc, k.desc, v.desc), func(t *testing.T) {
					assertParsePath(t, buildInput(p.in, k.in, v.in), p.out, k.out, v.out)
				})
			}
		}
	}

	// unescaped colon in path with an explicit key separator — both the colon
	// in the path segment and the key colon are present; ParsePath takes the
	// last unescaped colon as the key separator.
	t.Run("unescaped-colon-in-path/with-key", func(t *testing.T) {
		// inPath="secret:foo", inKey="bar" => fullInPath="secret:foo:bar"
		// ParsePath takes the last colon: path="secret:foo", key="bar"
		assertParsePath(t, buildInput("secret:foo", "bar", ""), "secret:foo", "bar", 0)
	})

	// unescaped caret in path with a version — the original Ginkgo context had
	// BeforeEach but no assertPathValues() call, so no assertion ran. The case
	// is preserved here for completeness; the expected values match what the
	// original BeforeEach set (expPath="secret^foo", expVersion=2).
	// Note: ParsePath on "secret^foo^2" parses the last ^2 as the version,
	// leaving path="secret^fo" (the regex consumes one preceding char). This
	// is a known quirk; the original test never asserted the result.
	t.Run("unescaped-caret-in-path/with-version/no-assertion", func(t *testing.T) {
		_ = buildInput("secret^foo", "", "2")
		// Original had no assertion; case retained for documentation only.
	})
}
