package cli

// cmdImport's version-1 loop ranged over a map -- whose iteration order Go
// deliberately randomizes -- writing one secret at a time. It now sorts the
// paths first and writes distinct paths concurrently, exactly as the
// version-2 loop does, buffering each `wrote` line until the fan-out is
// done so stderr replays in sorted order rather than completion order.

import (
	"encoding/json"
	"testing"
	"time"
)

// v1Fixture builds a version-1 export document -- a plain JSON map of path
// to key/value pairs -- naming the given paths, each holding key "k" set to
// the path's own name. As with v2Fixture, the argument order is deliberate
// noise: json.Unmarshal reads the document into a map, so only the set of
// paths survives parsing, never their order in the text.
func v1Fixture(t *testing.T, paths ...string) string {
	t.Helper()
	data := map[string]map[string]string{}
	for _, p := range paths {
		data[p] = map[string]string{"k": p}
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("json.Marshal fixture: %v", err)
	}
	return string(b)
}

// Importing several version-1 secrets overlaps their underlying writes, and
// every secret still round-trips with the correct value.
//
// This deliberately does not go through captureStdout, for the same reason
// as TestCmdImportWritesDistinctPathsConcurrently: on a genuine miss the
// parked request would otherwise still be blocked when the test returns.
func TestCmdImportV1WritesDistinctPathsConcurrently(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	withStdin(t, v1Fixture(t, "secret/d", "secret/b", "secret/a", "secret/c"))

	pattern := `^(PUT|POST) /v1/secret/[a-z]$`
	release := fv.holdRequests(2, pattern)

	c := newTestCLI(t)
	done := make(chan error, 1)
	go func() {
		done <- c.cmdImport("import")
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
		fv.holdRequests(0, pattern) // let the parked request, and cmdImport, finish
		cmdErr = <-done
	}

	if cmdErr != nil {
		t.Fatalf("cmdImport: %v", cmdErr)
	}
	if !overlapped {
		t.Fatal("no overlap observed: distinct v1 paths are imported sequentially")
	}

	for _, name := range []string{"a", "b", "c", "d"} {
		path := "secret/" + name
		if got := fv.get(path)["k"]; got != path {
			t.Errorf("%s[k] = %q, want %q", path, got, path)
		}
	}
}

// The `wrote` lines come out in sorted path order, whatever order the
// concurrent writes completed in and whatever order the map would have
// iterated in.
func TestCmdImportV1WroteLinesReplayInSortedOrder(t *testing.T) {
	isolateHome(t)
	newCLIFake(t)
	withStdin(t, v1Fixture(t, "secret/d", "secret/b", "secret/a", "secret/c"))

	c := newTestCLI(t)
	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdImport("import")
	})
	if err != nil {
		t.Fatalf("cmdImport: %v", err)
	}

	want := "wrote secret/a\nwrote secret/b\nwrote secret/c\nwrote secret/d\n"
	if stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}
