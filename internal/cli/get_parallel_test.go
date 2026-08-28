package cli

// cmdGet's multi-path loop now reads each path concurrently; the
// aggregation loop that builds errs/results/missingKeys runs afterward,
// sequentially and unchanged. These pin: the fetch phase actually overlaps
// its Read calls, and the reorder does not disturb the two output surfaces
// that are order-sensitive -- KeysOnly output and the accumulated errors --
// both of which are driven by the sequential aggregation loop over args,
// not by fetch completion order.

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

// Reading several paths in one `get` overlaps the underlying reads, rather
// than issuing them one at a time.
//
// This deliberately does not go through captureStdout: on a genuine miss
// (no overlap within the deadline) the parked request, and so cmdGet, would
// otherwise still be blocked when the test function returns, leaving a
// goroutine that writes to the swapped-out os.Stdout after captureStdout
// has already restored it -- corrupting whatever test runs next. Forcing
// the gate open on the timeout path guarantees cmdGet has finished, and
// stopped touching anything, before this test does.
func TestGetReadsMultiplePathsConcurrently(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	for _, name := range []string{"a", "b", "c", "d"} {
		fv.set("secret/"+name, map[string]string{"k": name})
	}
	pattern := `^GET /v1/secret/[a-z]$`
	release := fv.holdRequests(2, pattern)

	c := newTestCLI(t)
	done := make(chan error, 1)
	go func() {
		done <- c.cmdGet("get", "secret/a", "secret/b", "secret/c", "secret/d")
	}()

	var cmdErr error
	var overlapped bool
	select {
	case <-release:
		overlapped = true
		cmdErr = <-done
	case cmdErr = <-done:
		// finished with no observed overlap
	case <-time.After(5 * time.Second):
		fv.holdRequests(0, pattern) // let the parked request, and cmdGet, finish
		cmdErr = <-done
	}

	if cmdErr != nil {
		t.Fatalf("cmdGet: %v", cmdErr)
	}
	if !overlapped {
		t.Fatal("no overlap observed: reads are serialized")
	}
}

// safe get -K of several paths still prints one dedup'd, arg-ordered YAML
// block per path -- exactly the sequential loop's output, byte for byte --
// even though the underlying reads now race each other to complete.
func TestGetKeysOnlyOutputOrderUnchanged(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/a", map[string]string{"k1": "v1", "k2": "v2"})
	fv.set("secret/b", map[string]string{"k1": "v1"})
	fv.set("secret/c", map[string]string{"z": "9", "a": "1"})

	c := newTestCLI(t)
	c.opt.Get.KeysOnly = true

	var err error
	out := captureStdout(t, func() {
		err = c.cmdGet("get", "secret/a", "secret/b", "secret/c")
	})
	if err != nil {
		t.Fatalf("cmdGet: %v", err)
	}

	want := "---\n" +
		mustKeysYAML(t, "secret/a", []string{"k1", "k2"}) +
		mustKeysYAML(t, "secret/b", []string{"k1"}) +
		mustKeysYAML(t, "secret/c", []string{"a", "z"})
	if out != want {
		t.Errorf("safe get -K output changed:\ngot:\n%q\nwant:\n%q", out, want)
	}
}

// mustKeysYAML renders one safe get -K block exactly as cmdGet's KeysOnly
// branch does, for building an expected multi-path transcript.
func mustKeysYAML(t *testing.T, path string, keys []string) string {
	t.Helper()
	yml, err := yaml.Marshal(map[string][]string{path: keys})
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	return string(yml) + "\n"
}

// A multi-path get naming two missing secrets out of order reports them in
// the order they were given on the command line, not fetch-completion
// order.
func TestGetMultiPathErrorsPreserveArgOrder(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/a", map[string]string{"k": "v"})
	fv.set("secret/d", map[string]string{"k": "v"})

	c := newTestCLI(t)

	err := c.cmdGet("get", "secret/z", "secret/a", "secret/m", "secret/d")
	if err == nil {
		t.Fatal("cmdGet with two missing paths = nil, want an error")
	}

	msg := err.Error()
	zIdx := strings.Index(msg, "secret/z")
	mIdx := strings.Index(msg, "secret/m")
	if zIdx == -1 || mIdx == -1 {
		t.Fatalf("error does not name both missing paths: %q", msg)
	}
	if zIdx > mIdx {
		t.Errorf("errors out of argument order: secret/z (arg 1) should precede secret/m (arg 3): %q", msg)
	}
}
