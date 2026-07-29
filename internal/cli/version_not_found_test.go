package cli

// Coverage for what a read says when the version it was given is not the
// reason a secret could not be read, or is.
//
// Every one of these used to print "no secret exists at path X" — true only
// in the last case, and actively misleading in the rest, since the secret is
// sitting right there and `safe versions` will list it.

import (
	"strings"
	"testing"
)

// readErr runs get and returns the error it produced, failing if there was
// none.
func readErr(t *testing.T, c *CLI, args ...string) string {
	t.Helper()
	err := c.cmdGet("get", args...)
	if err == nil {
		t.Fatalf("cmdGet(%v) = nil, want an error", args)
	}
	return err.Error()
}

// A version that was never created names itself, rather than accusing the
// secret of being absent.
func TestGetNamesAVersionThatNeverExisted(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/a",
		map[string]string{"k": "one"},
		map[string]string{"k": "two"})

	c := newTestCLI(t)
	got := readErr(t, c, "secret/a:k^99")
	if !strings.Contains(got, "no version 99 of secret `secret/a` exists") {
		t.Errorf("error = %q, want it to name version 99 of secret/a", got)
	}
}

// The same, with no key on the path: the version is still the problem.
func TestGetNamesAVersionThatNeverExistedWithoutAKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/a", map[string]string{"k": "one"})

	c := newTestCLI(t)
	got := readErr(t, c, "secret/a^99")
	if !strings.Contains(got, "no version 99 of secret `secret/a` exists") {
		t.Errorf("error = %q, want it to name version 99 of secret/a", got)
	}
}

// A deleted version is recoverable, so saying so points at safe undelete
// instead of at a secret the reader will not find anything wrong with.
func TestGetReportsADeletedVersionAsDeleted(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/del",
		map[string]string{"k": "one"},
		map[string]string{"k": "two"})
	fv.deleteV2("secret/del", 2)

	c := newTestCLI(t)
	got := readErr(t, c, "secret/del:k^2")
	if !strings.Contains(got, "version 2 of secret `secret/del` has been deleted") {
		t.Errorf("error = %q, want it to report version 2 as deleted", got)
	}
}

// A destroyed version is not recoverable, and the two words are worth
// keeping apart for someone deciding whether to go looking for a backup.
func TestGetReportsADestroyedVersionAsDestroyed(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/gone",
		map[string]string{"k": "one"},
		map[string]string{"k": "two"})
	fv.destroyV2("secret/gone", 1)

	c := newTestCLI(t)
	got := readErr(t, c, "secret/gone:k^1")
	if !strings.Contains(got, "version 1 of secret `secret/gone` has been destroyed") {
		t.Errorf("error = %q, want it to report version 1 as destroyed", got)
	}
}

// A secret that is genuinely absent keeps the message it always had, even
// when a version was asked for: there is no history to narrow it down with.
func TestGetStillReportsAMissingSecret(t *testing.T) {
	isolateHome(t)
	newCLIFakeV2(t)

	c := newTestCLI(t)
	for _, arg := range []string{"secret/nope:k", "secret/nope:k^99"} {
		got := readErr(t, c, arg)
		if !strings.Contains(got, "no secret exists at path `secret/nope`") {
			t.Errorf("cmdGet(%q) error = %q, want the missing-secret message", arg, got)
		}
	}
}

// A missing key in a version that does exist is still a missing key.
func TestGetStillReportsAMissingKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/a", map[string]string{"k": "one"})

	c := newTestCLI(t)
	got := readErr(t, c, "secret/a:nope^1")
	if !strings.Contains(got, "no key `nope` exists in secret `secret/a`") {
		t.Errorf("error = %q, want the missing-key message", got)
	}
}

// A version that is there reads normally; the new branch must not intercept
// a successful read.
func TestGetStillReadsAnExistingVersion(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/a",
		map[string]string{"k": "one"},
		map[string]string{"k": "two"})

	c := newTestCLI(t)
	out := captureStdout(t, func() {
		if err := c.cmdGet("get", "secret/a:k^1"); err != nil {
			t.Fatalf("cmdGet: %v", err)
		}
	})
	if strings.TrimSpace(out) != "one" {
		t.Errorf("get secret/a:k^1 = %q, want %q", strings.TrimSpace(out), "one")
	}
}
