package vault_test

import (
	"fmt"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func TestEscapePathSegment(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "plain", input: "secret/foo", want: `secret/foo`},
		{name: "colon", input: "foo:bar", want: `foo\:bar`},
		{name: "caret", input: "foo^bar", want: `foo\^bar`},
		{name: "both", input: "a:b^c", want: `a\:b\^c`},
		{name: "empty", input: "", want: ""},
		{name: "already escaped colon", input: `a\:b`, want: `a\\:b`},
		{name: "multiple colons", input: "a:b:c", want: `a\:b\:c`},
		{name: "multiple carets", input: "a^b^c", want: `a\^b\^c`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := vault.EscapePathSegment(tc.input)
			if got != tc.want {
				t.Errorf("EscapePathSegment(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestEncodePath(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		key     string
		version uint64
		want    string
	}{
		{name: "path only", path: "secret/foo", key: "", version: 0, want: "secret/foo"},
		{name: "path and key", path: "secret/foo", key: "bar", version: 0, want: "secret/foo:bar"},
		{name: "path key version", path: "secret/foo", key: "bar", version: 3, want: "secret/foo:bar^3"},
		{name: "path and version no key", path: "secret/foo", key: "", version: 7, want: "secret/foo^7"},
		{name: "path with colon", path: "secret/f:oo", key: "bar", version: 0, want: `secret/f\:oo:bar`},
		{name: "path with caret", path: "secret/f^oo", key: "bar", version: 0, want: `secret/f\^oo:bar`},
		{name: "key with colon", path: "secret/foo", key: "b:ar", version: 0, want: `secret/foo:b\:ar`},
		{name: "key with caret", path: "secret/foo", key: "b^ar", version: 0, want: `secret/foo:b\^ar`},
		{name: "version zero no key", path: "secret/foo", key: "", version: 0, want: "secret/foo"},
		{name: "empty path", path: "", key: "bar", version: 0, want: ":bar"},
		{name: "empty key empty version", path: "a", key: "", version: 0, want: "a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := vault.EncodePath(tc.path, tc.key, tc.version)
			if got != tc.want {
				t.Errorf("EncodePath(%q, %q, %d) = %q; want %q",
					tc.path, tc.key, tc.version, got, tc.want)
			}
		})
	}
}

func TestEncodePathRoundTrip(t *testing.T) {
	// EncodePath then ParsePath must recover the original components.
	cases := []struct {
		path    string
		key     string
		version uint64
	}{
		{"secret/foo", "bar", 0},
		{"secret/foo", "bar", 5},
		{"secret/foo", "", 0},
		{"secret/foo", "", 9},
		{"secret/f:oo", "b^ar", 2},
		{"a:b", "c^d", 1},
		{"plain", "simple", 0},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s:%s^%d", tc.path, tc.key, tc.version), func(t *testing.T) {
			encoded := vault.EncodePath(tc.path, tc.key, tc.version)
			gotPath, gotKey, gotVersion := vault.ParsePath(encoded)
			if gotPath != tc.path || gotKey != tc.key || gotVersion != tc.version {
				t.Errorf(
					"round-trip EncodePath(%q,%q,%d) => ParsePath(%q) = (%q,%q,%d); want (%q,%q,%d)",
					tc.path, tc.key, tc.version, encoded,
					gotPath, gotKey, gotVersion,
					tc.path, tc.key, tc.version,
				)
			}
		})
	}
}

func TestPathHasKey(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{name: "no key", path: "secret/foo", want: false},
		{name: "with key", path: "secret/foo:bar", want: true},
		{name: "with key and version", path: "secret/foo:bar^3", want: true},
		{name: "with version no key", path: "secret/foo^3", want: false},
		{name: "escaped colon no key", path: `secret/f\:oo`, want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := vault.PathHasKey(tc.path)
			if got != tc.want {
				t.Errorf("PathHasKey(%q) = %v; want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestPathHasVersion(t *testing.T) {
	cases := []struct {
		name string
		path string
		want bool
	}{
		{name: "no version", path: "secret/foo", want: false},
		{name: "with version", path: "secret/foo^3", want: true},
		{name: "with key and version", path: "secret/foo:bar^3", want: true},
		{name: "version zero treated as absent", path: "secret/foo^0", want: false},
		{name: "with key no version", path: "secret/foo:bar", want: false},
		{name: "escaped caret no version", path: `secret/f\^oo`, want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := vault.PathHasVersion(tc.path)
			if got != tc.want {
				t.Errorf("PathHasVersion(%q) = %v; want %v", tc.path, got, tc.want)
			}
		})
	}
}
