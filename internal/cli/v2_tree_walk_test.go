package cli

// The tree walk is the most involved thing safe does, and until now none of it
// was exercised against a KV version 2 mount. The v2 fake could not serve a
// listing of the mount root — the request every walk starts with — so paths,
// tree and export could only be driven against version 1.
//
// Version 2 is where the walk has the most to get wrong: it fetches version
// metadata, decides which versions to take, and drops secrets whose newest
// version cannot be read. These pin that behaviour from the root down.

import (
	"encoding/json"
	"strings"
	"testing"
)

// walkFixture serves a v2 mount with a nested tree, a multi-version secret,
// and one secret whose newest version is deleted.
func walkFixture(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app/db",
		map[string]string{"pw": "one"},
		map[string]string{"pw": "two"})
	fv.setV2("secret/app/api", map[string]string{"tok": "abc"})
	fv.setV2("secret/top", map[string]string{"k": "v"})
	return fv
}

func linesOf(out string) []string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// A walk with no argument starts at the mount root, which is the case that
// could not be reached before.
func TestPathsWalksAVersion2MountFromTheRoot(t *testing.T) {
	isolateHome(t)
	walkFixture(t)
	c := newTestCLI(t)

	out := captureStdout(t, func() {
		if err := c.cmdPaths("paths", "secret"); err != nil {
			t.Fatalf("cmdPaths: %v", err)
		}
	})

	want := []string{"secret/app/api", "secret/app/db", "secret/top"}
	got := linesOf(out)
	if len(got) != len(want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("paths = %v, want %v", got, want)
			break
		}
	}
}

// tree renders the same walk, and has to nest the intermediate directory.
func TestTreeWalksAVersion2MountFromTheRoot(t *testing.T) {
	isolateHome(t)
	walkFixture(t)
	c := newTestCLI(t)

	out := captureStdout(t, func() {
		if err := c.cmdTree("tree", "secret"); err != nil {
			t.Fatalf("cmdTree: %v", err)
		}
	})

	for _, want := range []string{"secret/", "app/", "api", "db", "top"} {
		if !strings.Contains(out, want) {
			t.Errorf("tree output is missing %q:\n%s", want, out)
		}
	}
}

// A default export takes the newest version of each secret.
func TestExportWalksAVersion2MountFromTheRoot(t *testing.T) {
	isolateHome(t)
	walkFixture(t)
	c := newTestCLI(t)

	out := captureStdout(t, func() {
		if err := c.cmdExport("export", "secret"); err != nil {
			t.Fatalf("cmdExport: %v", err)
		}
	})

	var doc map[string]map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &doc); err != nil {
		t.Fatalf("export output is not a v1 export document: %s", out)
	}
	for _, path := range []string{"secret/app/api", "secret/app/db", "secret/top"} {
		if _, present := doc[path]; !present {
			t.Errorf("export is missing %s: %#v", path, doc)
		}
	}
	if doc["secret/app/db"]["pw"] != "two" {
		t.Errorf("secret/app/db = %#v, want the newest version pw=two", doc["secret/app/db"])
	}
}

// A secret whose newest version is deleted drops out of a listing, since there
// is nothing at that path a plain read would return.
func TestPathsOmitsASecretWhoseLatestVersionIsDeleted(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)

	out := captureStdout(t, func() {
		if err := c.cmdPaths("paths", "secret"); err != nil {
			t.Fatalf("cmdPaths: %v", err)
		}
	})

	if strings.Contains(out, "secret/app/db") {
		t.Errorf("paths lists secret/app/db, whose newest version is deleted:\n%s", out)
	}
	for _, want := range []string{"secret/app/api", "secret/top"} {
		if !strings.Contains(out, want) {
			t.Errorf("paths is missing %s:\n%s", want, out)
		}
	}
}

// --quick asks for the listing without the version lookup, so the secret with
// a deleted newest version comes back.
func TestQuickPathsKeepsASecretWhoseLatestVersionIsDeleted(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)
	c.opt.Paths.Quick = true

	out := captureStdout(t, func() {
		if err := c.cmdPaths("paths", "secret"); err != nil {
			t.Fatalf("cmdPaths --quick: %v", err)
		}
	})

	if !strings.Contains(out, "secret/app/db") {
		t.Errorf("--quick should list secret/app/db regardless of version state:\n%s", out)
	}
}

// A recursive copy across a v2 mount carries each secret's newest value.
func TestRecursiveCopyAcrossAVersion2Mount(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	c := newTestCLI(t)
	c.opt.Copy.Recurse = true
	c.opt.Copy.Force = true

	if err := c.cmdCopy("copy", "secret/app", "secret/app2"); err != nil {
		t.Fatalf("cmdCopy -r: %v", err)
	}

	for _, path := range []string{"secret/app2/db", "secret/app2/api"} {
		if states := fv.versionStates(path); len(states) != 1 || states[0] != "alive" {
			t.Errorf("%s states = %v, want one alive version", path, states)
		}
	}
	out := captureStdout(t, func() {
		if err := c.cmdGet("get", "secret/app2/db:pw"); err != nil {
			t.Fatalf("cmdGet: %v", err)
		}
	})
	if strings.TrimSpace(out) != "two" {
		t.Errorf("copied secret/app2/db:pw = %q, want %q", strings.TrimSpace(out), "two")
	}
}

// A recursive delete marks every secret under the root deleted and leaves the
// rest of the mount alone.
func TestRecursiveDeleteAcrossAVersion2Mount(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	c := newTestCLI(t)
	c.opt.Delete.Recurse = true
	c.opt.Delete.Force = true

	if err := c.cmdDelete("delete", "secret/app"); err != nil {
		t.Fatalf("cmdDelete -r: %v", err)
	}

	if states := fv.versionStates("secret/app/api"); states[len(states)-1] != "deleted" {
		t.Errorf("secret/app/api states = %v, want the newest deleted", states)
	}
	if states := fv.versionStates("secret/app/db"); states[len(states)-1] != "deleted" {
		t.Errorf("secret/app/db states = %v, want the newest deleted", states)
	}
	if states := fv.versionStates("secret/top"); states[len(states)-1] != "alive" {
		t.Errorf("secret/top states = %v, want it untouched", states)
	}
}
