package cli

// `safe ls` reads and writes the same escaped path syntax as the commands that
// walk a subtree, so its own output can be pasted back into it. These tests use
// the fake Vault's verbatim path storage to hold a folder whose literal name
// contains a colon, which is the only character that makes the two forms
// differ.

import (
	"strings"
	"testing"
)

// entriesOf splits a default (non -1) ls listing into its names. The listing is
// one line of double-space separated entries.
func entriesOf(out string) []string {
	return strings.Fields(strings.TrimSpace(out))
}

// seedColonFolder stores a secret under a literal colon-bearing folder, beside
// an ordinary one, on whichever mount version the caller started.
func seedColonFolder(t *testing.T, fv *cliFakeVault) {
	t.Helper()
	if fv.v2 {
		fv.setV2("secret/od:d/inner", map[string]string{"k": "v"})
		fv.setV2("secret/plain/inner", map[string]string{"k": "v"})
		return
	}
	fv.set("secret/od:d/inner", map[string]string{"k": "v"})
	fv.set("secret/plain/inner", map[string]string{"k": "v"})
}

// The listing safe prints is the listing safe accepts. Before the root was
// resolved, this errored with "no secret exists" on a path safe had printed.
func TestCmdLsAcceptsAnEscapedRoot(t *testing.T) {
	isolateHome(t)
	seedColonFolder(t, newCLIFakeV2(t))

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdLs("ls", `secret/od\:d`) })
	if err != nil {
		t.Fatalf("cmdLs: %v", err)
	}
	if got := entriesOf(out); len(got) != 1 || got[0] != "inner" {
		t.Errorf("ls %q = %q, want [inner]", `secret/od\:d`, got)
	}
}

// The liveness check on a version 2 mount re-parses the path it is given, so an
// unescaped colon in the folder name made it look up a key on a shorter path,
// miss, and drop the secret from the listing -- an empty listing at exit 0.
func TestCmdLsDoesNotDropAColonFolderQuietly(t *testing.T) {
	isolateHome(t)
	seedColonFolder(t, newCLIFakeV2(t))

	c := newTestCLI(t)
	var slow, quick string
	var err error
	slow = captureStdout(t, func() { err = c.cmdLs("ls", `secret/od\:d`) })
	if err != nil {
		t.Fatalf("cmdLs: %v", err)
	}
	c.opt.List.Quick = true
	quick = captureStdout(t, func() { err = c.cmdLs("ls", `secret/od\:d`) })
	if err != nil {
		t.Fatalf("cmdLs --quick: %v", err)
	}
	if strings.TrimSpace(slow) != strings.TrimSpace(quick) {
		t.Errorf("checking liveness changed the listing:\n  without -q: %q\n  with -q:    %q", slow, quick)
	}
}

// A version 1 mount never runs the liveness check, so this pins the root
// resolution on its own.
func TestCmdLsAcceptsAnEscapedRootOnAVersion1Mount(t *testing.T) {
	isolateHome(t)
	seedColonFolder(t, newCLIFake(t))

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdLs("ls", `secret/od\:d`) })
	if err != nil {
		t.Fatalf("cmdLs: %v", err)
	}
	if got := entriesOf(out); len(got) != 1 || got[0] != "inner" {
		t.Errorf("ls %q = %q, want [inner]", `secret/od\:d`, got)
	}
}

func TestCmdLsEscapesTheNamesItPrints(t *testing.T) {
	isolateHome(t)
	seedColonFolder(t, newCLIFakeV2(t))

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdLs("ls", "secret") })
	if err != nil {
		t.Fatalf("cmdLs: %v", err)
	}
	got := entriesOf(out)
	want := []string{`od\:d/`, "plain/"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("ls secret = %q, want %q", got, want)
	}
}

// What safe prints is what safe accepts: feed each entry back in.
func TestCmdLsOutputRoundTrips(t *testing.T) {
	isolateHome(t)
	seedColonFolder(t, newCLIFakeV2(t))

	c := newTestCLI(t)
	var err error
	first := captureStdout(t, func() { err = c.cmdLs("ls", "secret") })
	if err != nil {
		t.Fatalf("cmdLs: %v", err)
	}
	for _, entry := range entriesOf(first) {
		arg := "secret/" + strings.TrimSuffix(entry, "/")
		out := captureStdout(t, func() { err = c.cmdLs("ls", arg) })
		if err != nil {
			t.Fatalf("cmdLs(%q) rejected safe's own output: %v", arg, err)
		}
		if got := entriesOf(out); len(got) != 1 || got[0] != "inner" {
			t.Errorf("ls %q = %q, want [inner]", arg, got)
		}
	}
}

// An ordinary listing is unchanged: nothing in these names needs escaping.
func TestCmdLsLeavesPlainNamesAlone(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/app/db", map[string]string{"k": "v"})
	fv.set("secret/app/web/tls", map[string]string{"k": "v"})

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdLs("ls", "secret/app") })
	if err != nil {
		t.Fatalf("cmdLs: %v", err)
	}
	if strings.TrimRight(out, " \n") != "db  web/" {
		t.Errorf("ls secret/app = %q, want %q", out, "db  web/  \n")
	}

	c.opt.List.Single = true
	out = captureStdout(t, func() { err = c.cmdLs("ls", "secret/app") })
	if err != nil {
		t.Fatalf("cmdLs -1: %v", err)
	}
	if out != "db\nweb/\n" {
		t.Errorf("ls -1 secret/app = %q, want %q", out, "db\nweb/\n")
	}
}

// A key or a version cannot scope a listing, so naming one is refused rather
// than looked up as part of the path and reported as missing.
func TestCmdLsRefusesAKeyOrAVersion(t *testing.T) {
	isolateHome(t)
	seedColonFolder(t, newCLIFake(t))

	cases := []struct {
		arg  string
		want string
	}{
		{arg: "secret/plain:inner", want: "specific key"},
		{arg: "secret/plain^2", want: "specific version"},
	}
	for _, tc := range cases {
		t.Run(tc.arg, func(t *testing.T) {
			c := newTestCLI(t)
			err := c.cmdLs("ls", tc.arg)
			if err == nil {
				t.Fatalf("ls %q should have been refused", tc.arg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should mention %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "ls") {
				t.Errorf("error %q should name the command", err)
			}
		})
	}
}
