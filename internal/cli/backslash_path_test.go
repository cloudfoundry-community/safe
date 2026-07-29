package cli

// A Vault path is an arbitrary string, so any client can store a secret whose
// name ends in a backslash. safe has to walk past one: the tree walk re-parses
// the paths it builds, so a name it cannot encode and parse back takes out the
// whole subtree rather than the one secret.

import (
	"encoding/json"
	"strings"
	"testing"
)

// seedBackslashTree stores two ordinary secrets and one whose name ends in a
// backslash, all under the same root.
func seedBackslashTree(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := newCLIFake(t)
	fv.set("secret/good/one", map[string]string{"k": "v"})
	fv.set("secret/good/two", map[string]string{"k": "v"})
	fv.set(`secret/good/bad\`, map[string]string{"k": "v"})
	return fv
}

func TestCmdExportWalksPastBackslashPath(t *testing.T) {
	isolateHome(t)
	seedBackslashTree(t)

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdExport("export", "secret/good") })
	if err != nil {
		t.Fatalf("cmdExport: %v", err)
	}

	var doc map[string]map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("export output is not JSON (%v):\n%s", err, out)
	}

	// The healthy siblings are the point: one unencodable name used to make
	// the entire subtree unexportable.
	for _, want := range []string{"secret/good/one", "secret/good/two"} {
		if _, ok := doc[want]; !ok {
			t.Errorf("export omitted %q; got keys %v", want, mapKeys(doc))
		}
	}

	entry, ok := doc[`secret/good/bad\`]
	if !ok {
		t.Fatalf("export omitted the backslash-suffixed secret; got keys %v", mapKeys(doc))
	}
	if _, ok := entry["k"]; !ok {
		t.Errorf("the backslash-suffixed secret lost its key name; got %v", entry)
	}
}

func TestCmdPathsKeysWalksPastBackslashPath(t *testing.T) {
	isolateHome(t)
	seedBackslashTree(t)

	c := newTestCLI(t)
	c.opt.Paths.ShowKeys = true
	var err error
	out := captureStdout(t, func() { err = c.cmdPaths("paths", "secret/good") })
	if err != nil {
		t.Fatalf("cmdPaths: %v", err)
	}

	for _, want := range []string{"secret/good/one:k", "secret/good/two:k"} {
		if !strings.Contains(out, want) {
			t.Errorf("paths --keys omitted %q, got:\n%s", want, out)
		}
	}
	// The encoded form doubles the backslash so the joining colon cannot be
	// read as escaped when the path is parsed again.
	if !strings.Contains(out, `secret/good/bad\\:k`) {
		t.Errorf("paths --keys should print the escaped backslash path with its key, got:\n%s", out)
	}
}

func TestCmdTreeKeysWalksPastBackslashPath(t *testing.T) {
	isolateHome(t)
	seedBackslashTree(t)

	c := newTestCLI(t)
	c.opt.Tree.ShowKeys = true
	var err error
	out := captureStdout(t, func() { err = c.cmdTree("tree", "secret/good") })
	if err != nil {
		t.Fatalf("cmdTree: %v", err)
	}

	if !strings.Contains(out, "one") || !strings.Contains(out, "two") {
		t.Errorf("tree --keys omitted the healthy siblings, got:\n%s", out)
	}
	// Every secret in the tree has exactly one key, named "k". An empty key
	// name means the path and key were joined without escaping the path.
	if strings.Contains(out, ":\n") || strings.HasSuffix(strings.TrimRight(out, "\n"), ":") {
		t.Errorf("tree --keys printed an empty key name, got:\n%s", out)
	}
}

// mapKeys is a test-only helper for readable failure messages.
func mapKeys(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
