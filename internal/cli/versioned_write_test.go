package cli

// Writing to a version 2 mount creates a version rather than replacing a
// value, and the client reads the new version number out of the write
// response. These cover the write side, which the seeding helpers bypass.

import (
	"strings"
	"testing"
)

func TestCmdSetCreatesANewVersion(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app", map[string]string{"password": "one"})

	c := newTestCLI(t)
	captureStdout(t, func() {
		if err := c.cmdSet("set", "secret/app", "password=two"); err != nil {
			t.Fatalf("cmdSet: %v", err)
		}
	})

	if got := fv.versionStates("secret/app"); len(got) != 2 {
		t.Fatalf("expected a second version to be created, states = %v", got)
	}

	// The older version keeps its value; only the newest one changed.
	for _, tc := range []struct{ arg, want string }{
		{"secret/app:password^1", "one"},
		{"secret/app:password^2", "two"},
		{"secret/app:password", "two"},
	} {
		var err error
		out := captureStdout(t, func() { err = c.cmdGet("get", tc.arg) })
		if err != nil {
			t.Errorf("cmdGet(%q): %v", tc.arg, err)
			continue
		}
		if strings.TrimSpace(out) != tc.want {
			t.Errorf("cmdGet(%q) = %q, want %q", tc.arg, strings.TrimSpace(out), tc.want)
		}
	}
}

// A write to a path with no history starts at version 1. The client decodes
// the version number out of the write response body, so a write that answered
// without one would report version zero here.
func TestCmdSetOnANewPathStartsAtVersionOne(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)

	c := newTestCLI(t)
	captureStdout(t, func() {
		if err := c.cmdSet("set", "secret/fresh", "k=v"); err != nil {
			t.Fatalf("cmdSet: %v", err)
		}
	})

	if got := fv.versionStates("secret/fresh"); len(got) != 1 || got[0] != "alive" {
		t.Fatalf("version states = %v, want one alive version", got)
	}

	var err error
	out := captureStdout(t, func() { err = c.cmdVersions("versions", "secret/fresh") })
	if err != nil {
		t.Fatalf("cmdVersions: %v", err)
	}
	if !strings.Contains(out, "1") || !strings.Contains(out, "alive") {
		t.Errorf("versions should report version 1 alive, got:\n%s", out)
	}
}

// revert rewrites an old version forward as a new one, which exercises a read
// at a specific version followed by a write.
func TestCmdRevertWritesTheOldValueForward(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)

	c := newTestCLI(t)
	captureStdout(t, func() {
		if err := c.cmdRevert("revert", "secret/app", "1"); err != nil {
			t.Fatalf("cmdRevert: %v", err)
		}
	})

	states := fv.versionStates("secret/app")
	if len(states) != 3 {
		t.Fatalf("revert should have appended a version, states = %v", states)
	}

	var err error
	out := captureStdout(t, func() { err = c.cmdGet("get", "secret/app:password") })
	if err != nil {
		t.Fatalf("cmdGet: %v", err)
	}
	if strings.TrimSpace(out) != "one" {
		t.Errorf("latest value after revert = %q, want %q", strings.TrimSpace(out), "one")
	}
}
