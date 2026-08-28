package cli

// cmdImport's version-2 loop now sorts its secrets by path and writes
// distinct paths concurrently, rather than ranging over data.Data -- a Go
// map, whose iteration order is deliberately randomized -- one secret at a
// time. Sorting first means processing order is a function of the input
// alone, never of map internals, before parallel.EachLimit fans the writes
// out.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// v2Fixture builds a version-2 export document (a one-element
// []exportFormat, per v2Import's format check) naming the given paths, each
// with a single alive version holding key "k" set to the path's own name.
// Paths are accepted out of alphabetical order deliberately: json.Unmarshal
// reads exportFormat.Data into a map, discarding whatever order the text
// was in, so the fixture's own order proves nothing by itself -- what
// matters is that every path in it round-trips correctly however cmdImport
// chooses to dispatch them.
func v2Fixture(t *testing.T, paths ...string) string {
	t.Helper()
	data := map[string]exportSecret{}
	for _, p := range paths {
		data[p] = exportSecret{
			FirstVersion: 1,
			Versions: []exportVersion{
				{Value: map[string]string{"k": p}},
			},
		}
	}
	export := exportFormat{
		ExportVersion:      2,
		Data:               data,
		RequiresVersioning: map[string]bool{},
	}
	b, err := json.Marshal([]exportFormat{export})
	if err != nil {
		t.Fatalf("json.Marshal fixture: %v", err)
	}
	return string(b)
}

// Importing several secrets overlaps their underlying writes, rather than
// writing one secret at a time, and every secret still round-trips with the
// correct value and a single alive version.
//
// This deliberately does not go through captureStdout, for the same reason
// as TestCmdGenWritesDistinctPathsConcurrently: on a genuine miss the parked
// request would otherwise still be blocked when the test returns.
func TestCmdImportWritesDistinctPathsConcurrently(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	withStdin(t, v2Fixture(t, "secret/d", "secret/b", "secret/a", "secret/c"))

	pattern := `^(PUT|POST) /v1/secret/data/[a-z]$`
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
		t.Fatal("no overlap observed: distinct paths are imported sequentially")
	}

	for _, name := range []string{"a", "b", "c", "d"} {
		path := "secret/" + name
		if states := fv.versionStates(path); len(states) != 1 || states[0] != "alive" {
			t.Errorf("%s version states = %v, want [alive]", path, states)
		}
		out := captureStdout(t, func() {
			if err := c.cmdGet("get", path+":k"); err != nil {
				t.Errorf("cmdGet(%s): %v", path, err)
			}
		})
		if got := strings.TrimSuffix(out, "\n"); got != path {
			t.Errorf("%s[k] = %q, want %q", path, got, path)
		}
	}
}

// importPairs sorts by path, independent of whatever order Go's randomized
// map iteration would have produced. This is the one test in this file that
// actually observes processing order -- the concurrent write tests below
// observe completeness (every path lands, exactly once), which a run
// dispatched in map-random order would satisfy just as well as a sorted
// one, so they cannot catch a missing sort by themselves.
func TestImportPairsSortsByPath(t *testing.T) {
	data := map[string]exportSecret{
		"secret/d": {FirstVersion: 1},
		"secret/b": {FirstVersion: 1},
		"secret/a": {FirstVersion: 1},
		"secret/c": {FirstVersion: 1},
	}

	pairs := importPairs(data)
	if len(pairs) != len(data) {
		t.Fatalf("importPairs returned %d pairs, want %d", len(pairs), len(data))
	}

	want := []string{"secret/a", "secret/b", "secret/c", "secret/d"}
	for i, p := range want {
		if pairs[i].path != p {
			var got []string
			for _, pair := range pairs {
				got = append(got, pair.path)
			}
			t.Fatalf("importPairs order = %v, want %v", got, want)
		}
	}
}

// Every secret in the import survives, with exactly the right number of
// underlying writes, regardless of what order Go's randomized map iteration
// would have produced -- proof that concurrent dispatch neither drops nor
// duplicates a path. (Sort order itself is TestImportPairsSortsByPath's
// concern, not this test's: dispatch happening out of sorted order would
// still pass the assertions below.)
func TestCmdImportProcessesEveryPathExactlyOnce(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)

	var paths []string
	for i := 0; i < 8; i++ {
		paths = append(paths, fmt.Sprintf("secret/item%d", i))
	}
	withStdin(t, v2Fixture(t, paths...))

	c := newTestCLI(t)
	if err := c.cmdImport("import"); err != nil {
		t.Fatalf("cmdImport: %v", err)
	}

	for _, path := range paths {
		if states := fv.versionStates(path); len(states) != 1 || states[0] != "alive" {
			t.Errorf("%s version states = %v, want [alive]", path, states)
		}
	}

	writes := 0
	for _, r := range fv.requests() {
		if strings.HasPrefix(r, "PUT /v1/secret/data/") || strings.HasPrefix(r, "POST /v1/secret/data/") {
			writes++
		}
	}
	if writes != len(paths) {
		t.Errorf("%d data writes observed, want exactly %d (one per path, no drops or duplicates)", writes, len(paths))
	}
}

// The overflow guard already failed the import before this task -- it
// printed a warning to stderr and then returned a bare error either way, so
// there is no newly-introduced failure here. What changed is what the
// returned error says: it now names the offending secret instead of "version
// number overflow detected" with no path, and the redundant stderr line is
// gone (the caller sees the same information once, in the error, rather than
// twice in two different words).
func TestCmdImportOverflowGuardReturnsErrorNamingPath(t *testing.T) {
	isolateHome(t)
	newCLIFakeV2(t)

	data := map[string]exportSecret{
		"secret/overflow": {
			// FirstVersion at the very top of the uint range leaves no
			// room to add its second version's index (1) without
			// overflowing, even though the first (index 0) still fits.
			FirstVersion: ^uint(0),
			Versions: []exportVersion{
				{Value: map[string]string{"k": "v"}},
				{Value: map[string]string{"k": "v2"}},
			},
		},
	}
	export := exportFormat{ExportVersion: 2, Data: data, RequiresVersioning: map[string]bool{}}
	b, err := json.Marshal([]exportFormat{export})
	if err != nil {
		t.Fatalf("json.Marshal fixture: %v", err)
	}
	withStdin(t, string(b))

	c := newTestCLI(t)
	err = c.cmdImport("import")
	if err == nil {
		t.Fatal("cmdImport: expected an overflow error, got nil")
	}
	if got := err.Error(); got != "version number overflow detected for secret secret/overflow" {
		t.Errorf("cmdImport error = %q, want it to name secret/overflow", got)
	}
}
