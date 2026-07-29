package cli

// safe prints paths in its own escaped syntax, so its output has to be usable
// as its own input. These tests pin the round trip for the commands that walk
// a subtree, using the fake Vault's verbatim path storage to hold a secret
// whose literal name contains a colon.

import (
	"strings"
	"testing"
)

func TestWalkRoot(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		arg     string
		want    string
		wantErr string
	}{
		{name: "plain path", arg: "secret/foo", want: "secret/foo"},
		{name: "escaped colon is unescaped", arg: `secret/we\:ird`, want: "secret/we:ird"},
		{name: "escaped caret is unescaped", arg: `secret/ca\^ret`, want: "secret/ca^ret"},
		{name: "canonicalized", arg: "/secret//foo/", want: "secret/foo"},
		{name: "key refused", arg: "secret/foo:bar", wantErr: "specific key"},
		{name: "version refused", arg: "secret/foo^2", wantErr: "specific version"},
		{name: "key on an escaped path refused", arg: `secret/we\:ird:bar`, wantErr: "specific key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := walkRoot("tree", tc.arg)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("walkRoot(%q) = %q, want an error", tc.arg, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error %q should mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("walkRoot(%q): %v", tc.arg, err)
			}
			if got != tc.want {
				t.Errorf("walkRoot(%q) = %q, want %q", tc.arg, got, tc.want)
			}
		})
	}
}

// seedColonTree stores a secret under a literal colon-bearing folder, plus a
// name-prefix sibling that must not be swept in by the walk.
func seedColonTree(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := newCLIFake(t)
	fv.set("secret/od:d/leaf", map[string]string{"k": "v"})
	fv.set("secret/od", map[string]string{"other": "untouched"})
	return fv
}

func TestCmdTreeAcceptsEscapedRoot(t *testing.T) {
	isolateHome(t)
	seedColonTree(t)

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdTree("tree", `secret/od\:d`) })
	if err != nil {
		t.Fatalf("cmdTree: %v", err)
	}
	if !strings.Contains(out, "leaf") {
		t.Errorf("tree output should list the leaf, got:\n%s", out)
	}
	// The root is escaped once for display, never twice.
	if strings.Contains(out, `od\\:d`) {
		t.Errorf("tree output double-escaped the root, got:\n%s", out)
	}
	if !strings.Contains(out, `od\:d`) {
		t.Errorf("tree output should show the escaped root, got:\n%s", out)
	}
}

func TestCmdPathsAcceptsEscapedRoot(t *testing.T) {
	isolateHome(t)
	seedColonTree(t)

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdPaths("paths", `secret/od\:d`) })
	if err != nil {
		t.Fatalf("cmdPaths: %v", err)
	}
	if !strings.Contains(out, `secret/od\:d/leaf`) {
		t.Errorf("paths output should list the escaped leaf, got:\n%s", out)
	}
	if strings.Contains(out, "untouched") || strings.Contains(out, "secret/od\n") {
		t.Errorf("the name-prefix sibling should not appear, got:\n%s", out)
	}
}

// What safe prints is what safe accepts: feed the output of `paths` back in.
func TestCmdPathsOutputRoundTrips(t *testing.T) {
	isolateHome(t)
	seedColonTree(t)

	c := newTestCLI(t)
	var err error
	first := captureStdout(t, func() { err = c.cmdPaths("paths", `secret/od\:d`) })
	if err != nil {
		t.Fatalf("cmdPaths: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(first), "\n") {
		if line == "" {
			continue
		}
		if _, err := walkRoot("paths", line); err != nil {
			t.Fatalf("walkRoot rejected safe's own output %q: %v", line, err)
		}
		out := captureStdout(t, func() { err = c.cmdPaths("paths", line) })
		if err != nil {
			t.Fatalf("cmdPaths(%q) rejected safe's own output: %v", line, err)
		}
		if strings.TrimSpace(out) != line {
			t.Errorf("cmdPaths(%q) = %q, want it to echo the same path", line, strings.TrimSpace(out))
		}
	}
}

func TestCmdTreeRejectsKeyInRoot(t *testing.T) {
	isolateHome(t)
	seedColonTree(t)

	c := newTestCLI(t)
	err := c.cmdTree("tree", `secret/od\:d:leaf`)
	if err == nil {
		t.Fatal("expected an error for a root naming a key, got nil")
	}
	if !strings.Contains(err.Error(), "specific key") {
		t.Errorf("error %q should mention a specific key", err)
	}
}
