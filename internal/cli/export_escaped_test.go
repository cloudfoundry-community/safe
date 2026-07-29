package cli

// export walks a subtree, so it takes a root in safe's escaped syntax and
// has to hand the literal path to the walk.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCmdExportAcceptsEscapedRoot(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/od:d/leaf", map[string]string{"k": "v"})
	fv.set("secret/od", map[string]string{"other": "untouched"})

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdExport("export", `secret/od\:d`) })
	if err != nil {
		t.Fatalf("cmdExport: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("export output is not JSON (%v):\n%s", err, out)
	}
	if !strings.Contains(out, "leaf") {
		t.Errorf("export should contain the leaf secret, got:\n%s", out)
	}
	if strings.Contains(out, "untouched") {
		t.Errorf("the name-prefix sibling should not be exported, got:\n%s", out)
	}
}

func TestCmdExportRejectsKeyInRoot(t *testing.T) {
	isolateHome(t)
	newCLIFake(t)

	c := newTestCLI(t)
	err := c.cmdExport("export", `secret/od\:d:leaf`)
	if err == nil {
		t.Fatal("expected an error for a root naming a key, got nil")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("error %q should mention a key", err)
	}
}
