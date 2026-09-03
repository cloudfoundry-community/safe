package cli

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/yamlenc"
)

// A multi-path safe get prints one YAML document. A value that begins with
// "? " or looks like a number must not break the document or change type
// when a consumer parses it.
func TestGetMultiPathOutputParsesWithHostileValues(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/a", map[string]string{"q": "? x", "e": "1e3", "ok": "plain"})
	fv.set("secret/b", map[string]string{"cr": "one\r\ntwo", "t": "a\tb"})

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() {
		err = c.cmdGet("get", "secret/a", "secret/b")
	})
	if err != nil {
		t.Fatalf("cmdGet: %v", err)
	}
	if !strings.HasPrefix(out, "---\n") {
		t.Fatalf("output does not start with a document marker:\n%s", out)
	}

	var doc map[string]map[string]string
	if err := yamlenc.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("safe get output does not parse: %v\n%s", err, out)
	}
	want := map[string]map[string]string{
		"secret/a": {"q": "? x", "e": "1e3", "ok": "plain"},
		"secret/b": {"cr": "one\r\ntwo", "t": "a\tb"},
	}
	for path, kv := range want {
		for k, v := range kv {
			if doc[path][k] != v {
				t.Errorf("%s:%s = %q, want %q", path, k, doc[path][k], v)
			}
		}
	}
}
