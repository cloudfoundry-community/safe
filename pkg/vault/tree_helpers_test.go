package vault

// Secrets.Append and the two Basename methods are the seams between the
// tree walk and everything that renders it: export appends every entry the
// walk yields through Append, and Draw labels each node with its Basename.
// A key node's name carries the key in path:key syntax with the key segment
// escaped (see workGet), so its basename has to come back unescaped -- a
// colon in a key name must survive the round trip.

import (
	"testing"
)

func TestSecretsAppend(t *testing.T) {
	t.Parallel()

	var s Secrets
	s.Append(SecretEntry{Path: "secret/a"})
	s.Append(SecretEntry{Path: "secret/b"})

	if len(s) != 2 {
		t.Fatalf("len = %d, want 2", len(s))
	}
	if s[0].Path != "secret/a" || s[1].Path != "secret/b" {
		t.Errorf("entries out of order: %q, %q", s[0].Path, s[1].Path)
	}
}

func TestSecretEntryBasename(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		path string
		want string
	}{
		{name: "nested", path: "secret/foo/bar", want: "bar"},
		{name: "directly under the mount", path: "secret/foo", want: "foo"},
		{name: "a bare mount", path: "secret", want: "secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SecretEntry{Path: tc.path}.Basename()
			if got != tc.want {
				t.Errorf("Basename(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestSecretTreeBasename(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		tree secretTree
		want string
	}{
		{
			name: "the root of the walk",
			tree: secretTree{Type: treeTypeRoot, Name: "/"},
			want: "/",
		},
		{
			name: "a directory keeps its trailing slash",
			tree: secretTree{Type: treeTypeDir, Name: "secret/sub/"},
			want: "sub/",
		},
		{
			name: "a directory named without one gains it",
			tree: secretTree{Type: treeTypeDir, Name: "secret/sub"},
			want: "sub/",
		},
		{
			name: "a secret",
			tree: secretTree{Type: treeTypeSecret, Name: "secret/foo/bar"},
			want: "bar",
		},
		{
			name: "a secret that is also a directory",
			tree: secretTree{Type: treeTypeDirAndSecret, Name: "secret/foo"},
			want: "foo",
		},
		{
			name: "a key",
			tree: secretTree{Type: treeTypeKey, Name: EncodePath("secret/foo", "pass", 0)},
			want: "pass",
		},
		{
			name: "a key with a colon in its name",
			tree: secretTree{Type: treeTypeKey, Name: EncodePath("secret/foo", "user:pass", 0)},
			want: "user:pass",
		},
		{
			name: "a version node has no name of its own",
			tree: secretTree{Type: treeTypeVersion, Name: "secret/foo", Version: 2},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.tree.Basename()
			if got != tc.want {
				t.Errorf("Basename() of %q = %q, want %q", tc.tree.Name, got, tc.want)
			}
		})
	}
}
