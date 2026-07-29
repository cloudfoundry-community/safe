package cli

// A secret whose newest version has been deleted reads as though the secret
// were not there at all. It is: `safe versions` lists it, an older version
// still reads, and `safe undelete` brings it back — but `safe get` said "no
// secret exists at path", which sends the reader off to create one.
//
// Vault says which version it was and what happened to it, in the body of the
// 404 itself, but the client discards non-2xx bodies. Recovering it costs one
// metadata request, so it is paid here rather than in Read: a read with no
// version named is exactly what gen, uuid, ssh, rsa and dhparam do to a path
// they are about to create, and they would pay it on every run.

import (
	"strings"
	"testing"
)

// deletedLatest serves a v2 mount holding secret/d, whose second and newest
// version is deleted while the first is still alive.
func deletedLatest(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := newCLIFakeV2(t)
	fv.setV2("secret/d",
		map[string]string{"a": "one"},
		map[string]string{"a": "two"})
	fv.deleteV2("secret/d", 2)
	return fv
}

func getErr(t *testing.T, c *CLI, args ...string) string {
	t.Helper()
	err := c.cmdGet("get", args...)
	if err == nil {
		t.Fatalf("cmdGet(%v) = nil, want an error", args)
	}
	return err.Error()
}

// The headline case: the secret is there, and the message says which version
// went missing and how.
func TestGetNamesADeletedLatestVersion(t *testing.T) {
	const want = "version 2 of secret `secret/d` has been deleted"

	isolateHome(t)
	deletedLatest(t)
	c := newTestCLI(t)

	if got := getErr(t, c, "secret/d"); got != want {
		t.Errorf("get secret/d = %q, want %q", got, want)
	}
}

// Naming a key does not change what happened to the version.
func TestGetNamesADeletedLatestVersionWithAKey(t *testing.T) {
	const want = "version 2 of secret `secret/d` has been deleted"

	isolateHome(t)
	deletedLatest(t)
	c := newTestCLI(t)

	if got := getErr(t, c, "secret/d:a"); got != want {
		t.Errorf("get secret/d:a = %q, want %q", got, want)
	}
}

// A destroyed newest version is reported as destroyed, since undelete will not
// bring that one back and the reader should not go looking for it.
func TestGetNamesADestroyedLatestVersion(t *testing.T) {
	const want = "version 2 of secret `secret/d` has been destroyed"

	isolateHome(t)
	fv := deletedLatest(t)
	fv.destroyV2("secret/d", 2)
	c := newTestCLI(t)

	if got := getErr(t, c, "secret/d"); got != want {
		t.Errorf("get secret/d = %q, want %q", got, want)
	}
}

// A secret that really is absent still says so. This is the answer the old
// message was right about, and the one gen and friends depend on.
func TestGetStillReportsATrulyMissingSecret(t *testing.T) {
	const want = "no secret exists at path `secret/absent`"

	isolateHome(t)
	deletedLatest(t)
	c := newTestCLI(t)

	if got := getErr(t, c, "secret/absent"); got != want {
		t.Errorf("get secret/absent = %q, want %q", got, want)
	}
}

// A key that is not in a perfectly readable secret is still a missing key, not
// a version problem.
func TestGetStillReportsAMissingKeyOnALiveSecret(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/live", map[string]string{"a": "one"})
	c := newTestCLI(t)

	got := getErr(t, c, "secret/live:nope")
	if !strings.Contains(got, "no key `nope` exists in secret `secret/live`") {
		t.Errorf("get secret/live:nope = %q, want it to name the missing key", got)
	}
}

// A version named explicitly was already reported precisely, and must not be
// re-described as the latest.
func TestGetStillNamesTheVersionItWasGiven(t *testing.T) {
	const want = "no version 9 of secret `secret/d` exists"

	isolateHome(t)
	deletedLatest(t)
	c := newTestCLI(t)

	if got := getErr(t, c, "secret/d^9"); got != want {
		t.Errorf("get secret/d^9 = %q, want %q", got, want)
	}
}

// An older version that is still alive reads normally; nothing here changes
// what a successful get does.
func TestGetStillReadsAnOlderLiveVersion(t *testing.T) {
	isolateHome(t)
	deletedLatest(t)
	c := newTestCLI(t)

	out := captureStdout(t, func() {
		if err := c.cmdGet("get", "secret/d:a^1"); err != nil {
			t.Fatalf("cmdGet: %v", err)
		}
	})
	if strings.TrimSpace(out) != "one" {
		t.Errorf("get secret/d:a^1 = %q, want %q", strings.TrimSpace(out), "one")
	}
}

// The multi-path branch of get collects its errors separately, so it needs the
// same treatment.
func TestMultiPathGetNamesADeletedLatestVersion(t *testing.T) {
	isolateHome(t)
	fv := deletedLatest(t)
	fv.setV2("secret/other", map[string]string{"b": "two"})
	c := newTestCLI(t)

	got := getErr(t, c, "secret/d", "secret/other")
	if !strings.Contains(got, "version 2 of secret `secret/d` has been deleted") {
		t.Errorf("get secret/d secret/other = %q, want it to name version 2", got)
	}
}

// A version 1 mount has no version history to consult, and a missing secret
// there is simply missing.
func TestGetOnAVersion1MountStillReportsAMissingSecret(t *testing.T) {
	const want = "no secret exists at path `secret/absent`"

	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/live", map[string]string{"a": "one"})
	c := newTestCLI(t)

	if got := getErr(t, c, "secret/absent"); got != want {
		t.Errorf("get secret/absent = %q, want %q", got, want)
	}
}
