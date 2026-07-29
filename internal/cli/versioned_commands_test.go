package cli

// Version history only exists on a KV version 2 mount, so these paths were
// unreachable while the fake spoke version 1 only. They cover the success
// side of the version commands: that they act on the right versions, and that
// they reach the right secret when the path arrives in safe's escaped syntax.

import (
	"strings"
	"testing"
)

func TestCmdVersionsListsEveryVersionAndState(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
		map[string]string{"password": "three"},
	)
	fv.deleteV2("secret/app", 2)
	fv.destroyV2("secret/app", 1)

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdVersions("versions", "secret/app") })
	if err != nil {
		t.Fatalf("cmdVersions: %v", err)
	}

	for _, want := range []string{"destroyed", "deleted", "alive"} {
		if !strings.Contains(out, want) {
			t.Errorf("versions output should report %q, got:\n%s", want, out)
		}
	}
	for _, want := range []string{"1", "2", "3"} {
		if !strings.Contains(out, want) {
			t.Errorf("versions output should list version %s, got:\n%s", want, out)
		}
	}
}

// A path pasted back from safe's own output arrives escaped, while the client
// underneath takes literal Vault paths.
func TestCmdVersionsAcceptsEscapedPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/od:d", map[string]string{"k": "v"})

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdVersions("versions", `secret/od\:d`) })
	if err != nil {
		t.Fatalf("cmdVersions on an escaped path: %v", err)
	}
	if !strings.Contains(out, "alive") {
		t.Errorf("expected the version to be listed, got:\n%s", out)
	}
}

func TestCmdVersionsRejectsMissingSecret(t *testing.T) {
	isolateHome(t)
	newCLIFakeV2(t)

	c := newTestCLI(t)
	err := c.cmdVersions("versions", "secret/absent")
	if err == nil {
		t.Fatal("expected an error for a secret that does not exist, got nil")
	}
	if !strings.Contains(err.Error(), "secret/absent") {
		t.Errorf("error %q should name the missing secret", err)
	}
}

func TestCmdUndeleteAllRevivesEveryDeletedVersion(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
		map[string]string{"password": "three"},
	)
	fv.deleteV2("secret/app", 1, 3)

	c := newTestCLI(t)
	c.opt.Undelete.All = true
	if err := c.cmdUndelete("undelete", "secret/app"); err != nil {
		t.Fatalf("cmdUndelete --all: %v", err)
	}

	got := fv.versionStates("secret/app")
	want := []string{"alive", "alive", "alive"}
	if !equalStrings(got, want) {
		t.Errorf("version states = %v, want %v", got, want)
	}
}

// The regression this pins: --all looked the versions up under the parsed
// path but undeleted under the escaped one, so nothing was revived and the
// command still exited zero.
func TestCmdUndeleteAllAcceptsEscapedPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/od:d",
		map[string]string{"k": "one"},
		map[string]string{"k": "two"},
	)
	fv.deleteV2("secret/od:d", 1, 2)

	c := newTestCLI(t)
	c.opt.Undelete.All = true
	if err := c.cmdUndelete("undelete", `secret/od\:d`); err != nil {
		t.Fatalf("cmdUndelete --all on an escaped path: %v", err)
	}

	got := fv.versionStates("secret/od:d")
	want := []string{"alive", "alive"}
	if !equalStrings(got, want) {
		t.Errorf("version states = %v, want %v", got, want)
	}
}

func TestCmdUndeleteAllLeavesDestroyedVersionsAlone(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"k": "one"},
		map[string]string{"k": "two"},
	)
	fv.deleteV2("secret/app", 1, 2)
	fv.destroyV2("secret/app", 1)

	c := newTestCLI(t)
	c.opt.Undelete.All = true
	if err := c.cmdUndelete("undelete", "secret/app"); err != nil {
		t.Fatalf("cmdUndelete --all: %v", err)
	}

	got := fv.versionStates("secret/app")
	want := []string{"destroyed", "alive"}
	if !equalStrings(got, want) {
		t.Errorf("version states = %v, want %v", got, want)
	}
}

func TestCmdGetReadsTheRequestedVersion(t *testing.T) {
	isolateHome(t)
	newCLIFakeV2(t).setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)

	c := newTestCLI(t)

	cases := []struct {
		arg  string
		want string
	}{
		{"secret/app:password^1", "one"},
		{"secret/app:password^2", "two"},
		//No version means the latest, and so does version zero.
		{"secret/app:password", "two"},
		{"secret/app:password^0", "two"},
	}

	for _, tc := range cases {
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

func TestCmdGetRejectsDeletedVersion(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)
	fv.deleteV2("secret/app", 1)

	c := newTestCLI(t)
	err := c.cmdGet("get", "secret/app:password^1")
	if err == nil {
		t.Fatal("expected an error reading a deleted version, got nil")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
