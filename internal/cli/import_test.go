package cli

// End-to-end coverage for safe import replaying a v1 export, driven through
// the fake Vault in vault_fake_test.go.

import (
	"os"
	"testing"
)

// withStdin replaces os.Stdin with a pipe carrying s for the test's duration,
// so a command that reads stdin can be driven from a literal.
func withStdin(t *testing.T, s string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	go func() {
		_, _ = w.WriteString(s)
		_ = w.Close()
	}()
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		_ = r.Close()
	})
}

// The keys of a v1 export are literal Vault paths. Write reads its argument as
// path:key syntax, so a colon-bearing path has to be encoded on the way back
// in. Without that the whole import aborts on the first such path, taking the
// colon-free secrets that follow with it.
func TestCmdImportColonBearingPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	withStdin(t, `{"secret/o:d":{"k":"v"},"secret/plain":{"k":"w"}}`)

	c := newTestCLI(t)
	if err := c.cmdImport("import"); err != nil {
		t.Fatalf("cmdImport: %v", err)
	}
	if kv := fv.get("secret/o:d"); kv["k"] != "v" {
		t.Errorf("secret/o:d = %v, want map[k:v]", kv)
	}
	if kv := fv.get("secret/plain"); kv["k"] != "w" {
		t.Errorf("secret/plain = %v, want map[k:w]", kv)
	}
}
