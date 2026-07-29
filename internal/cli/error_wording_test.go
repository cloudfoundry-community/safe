package cli

// safe says "that version cannot be read" from three places — a read, a
// revert, and an undelete — and each phrased it differently, down to the
// capitalisation and which quote character closed the secret name. A reader
// who hits two of them has no way to tell they were told the same thing.
//
// These pin the one sentence, and pin the fact that sharing the sentence did
// not also share the error kind: an undelete failure travels into the tree
// walk, whose callers drop not-found errors on the floor.

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// versionedFake serves a v2 mount holding secret/s with three versions, the
// first destroyed and the second deleted, which is every state a version can
// be in at once.
func versionedFake(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := newCLIFakeV2(t)
	fv.setV2("secret/s",
		map[string]string{"a": "1"},
		map[string]string{"a": "2"},
		map[string]string{"a": "3"})
	fv.destroyV2("secret/s", 1)
	fv.deleteV2("secret/s", 2)
	return fv
}

// errText fails unless err is non-nil, and returns its message.
func errText(t *testing.T, err error, what string) string {
	t.Helper()
	if err == nil {
		t.Fatalf("%s = nil, want an error", what)
	}
	return err.Error()
}

// All three commands describe the same destroyed version the same way.
func TestDestroyedVersionReadsTheSameEverywhere(t *testing.T) {
	const want = "version 1 of secret `secret/s` has been destroyed"

	isolateHome(t)
	versionedFake(t)
	c := newTestCLI(t)

	for _, tc := range []struct {
		command string
		err     error
	}{
		{"get", c.cmdGet("get", "secret/s^1")},
		{"revert", c.cmdRevert("revert", "secret/s", "1")},
		{"undelete", c.cmdUndelete("undelete", "secret/s^1")},
	} {
		if got := errText(t, tc.err, tc.command); got != want {
			t.Errorf("%s = %q, want %q", tc.command, got, want)
		}
	}
}

// And the same for a version number that was never issued.
func TestMissingVersionReadsTheSameEverywhere(t *testing.T) {
	const want = "no version 9 of secret `secret/s` exists"

	isolateHome(t)
	versionedFake(t)
	c := newTestCLI(t)

	for _, tc := range []struct {
		command string
		err     error
	}{
		{"get", c.cmdGet("get", "secret/s^9")},
		{"revert", c.cmdRevert("revert", "secret/s", "9")},
		{"undelete", c.cmdUndelete("undelete", "secret/s^9")},
	} {
		if got := errText(t, tc.err, tc.command); got != want {
			t.Errorf("%s = %q, want %q", tc.command, got, want)
		}
	}
}

// revert can be told to go ahead anyway, so it appends the flag that would do
// it. What it appends the flag to is the sentence a read gives.
func TestRevertOnADeletedVersionLeadsWithTheSharedSentence(t *testing.T) {
	const shared = "version 2 of secret `secret/s` has been deleted"

	isolateHome(t)
	versionedFake(t)
	c := newTestCLI(t)

	got := errText(t, c.cmdRevert("revert", "secret/s", "2"), "revert")
	if !strings.HasPrefix(got, shared) {
		t.Errorf("revert = %q, want it to open with %q", got, shared)
	}
	if !strings.Contains(got, "--deleted") {
		t.Errorf("revert = %q, want it to name --deleted", got)
	}
	if reader := errText(t, c.cmdGet("get", "secret/s^2"), "get"); reader != shared {
		t.Errorf("get = %q, want %q", reader, shared)
	}
}

// A secret that is not there at all is reported as such by both commands that
// look up its history, rather than as a version problem.
func TestMissingSecretReadsTheSameEverywhere(t *testing.T) {
	const want = "no secret exists at path `secret/nope`"

	isolateHome(t)
	versionedFake(t)
	c := newTestCLI(t)

	for _, tc := range []struct {
		command string
		err     error
	}{
		{"get", c.cmdGet("get", "secret/nope^3")},
		{"revert", c.cmdRevert("revert", "secret/nope", "1")},
	} {
		if got := errText(t, tc.err, tc.command); got != want {
			t.Errorf("%s = %q, want %q", tc.command, got, want)
		}
	}
}

// copy checks the state of the version before it moves anything, and had its
// own way of describing what it found — one that echoed the path with its
// version glued on rather than naming the version.
func TestCopyOnAnUnreadableVersionUsesTheSharedSentence(t *testing.T) {
	isolateHome(t)
	versionedFake(t)
	c := newTestCLI(t)

	for _, tc := range []struct{ path, want string }{
		{"secret/s^1", "version 1 of secret `secret/s` has been destroyed"},
		{"secret/s^2", "version 2 of secret `secret/s` has been deleted"},
		{"secret/s^9", "no version 9 of secret `secret/s` exists"},
	} {
		got := errText(t, c.cmdCopy("copy", tc.path, "secret/dst"), "copy "+tc.path)
		if got != tc.want {
			t.Errorf("copy %s = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// With no version named, the number is the part the caller does not already
// know, so it is what the message leads with.
func TestCopyNamesTheVersionItLandedOn(t *testing.T) {
	const want = "version 2 of secret `secret/d` has been deleted"

	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/d",
		map[string]string{"a": "1"},
		map[string]string{"a": "2"})
	fv.deleteV2("secret/d", 2)

	c := newTestCLI(t)
	if got := errText(t, c.cmdCopy("copy", "secret/d", "secret/dst"), "copy"); got != want {
		t.Errorf("copy = %q, want %q", got, want)
	}
}

// A secret with nothing left to operate on is about the secret, not any one
// version, so it keeps its own sentence — in the same voice as the rest.
func TestDeleteAllOnASecretWithNothingAliveNamesTheSecret(t *testing.T) {
	const want = "no living version of secret `secret/d` exists"

	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/d", map[string]string{"a": "1"})
	fv.deleteV2("secret/d", 1)

	c := newTestCLI(t)
	c.opt.Delete.All = true
	if got := errText(t, c.cmdDelete("delete", "secret/d"), "delete -a"); got != want {
		t.Errorf("delete -a = %q, want %q", got, want)
	}
}

// The same for a destroy, which will settle for a deleted version and so says
// so when there is not one of those either.
func TestDestroyAllOnAFullyDestroyedSecretNamesTheSecret(t *testing.T) {
	const want = "no living or deleted version of secret `secret/d` exists"

	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/d", map[string]string{"a": "1"})
	fv.destroyV2("secret/d", 1)

	c := newTestCLI(t)
	c.opt.Delete.All = true
	c.opt.Delete.Destroy = true
	if got := errText(t, c.cmdDelete("delete", "secret/d"), "delete -a --destroy"); got != want {
		t.Errorf("delete -a --destroy = %q, want %q", got, want)
	}
}

// safe rm -f is meant to shrug at anything that is not there, and it decides
// what counts by asking IsNotFound. These have always been that kind, so
// naming the version must not change what -f does with them.
func TestForcedDeleteStillShrugsAtAnUnreadableVersion(t *testing.T) {
	isolateHome(t)
	versionedFake(t)
	c := newTestCLI(t)
	c.opt.Delete.Force = true

	for _, path := range []string{"secret/s^1", "secret/s^2", "secret/s^9"} {
		if err := c.cmdDelete("delete", path); err != nil {
			t.Errorf("delete -f %s = %v, want nil", path, err)
		}
	}
}

// Sharing the wording must not share the kind. Undelete's error reaches the
// tree walk, and a walk error that answers to IsNotFound is discarded by
// MoveCopyTree's skip-if-exists check, so a destroyed version reported as a
// not-found would go missing rather than stop the copy.
func TestUndeleteFailureIsNotANotFound(t *testing.T) {
	isolateHome(t)
	versionedFake(t)
	c := newTestCLI(t)

	err := c.cmdUndelete("undelete", "secret/s^1")
	if err == nil {
		t.Fatal("cmdUndelete on a destroyed version = nil, want an error")
	}
	if vault.IsNotFound(err) {
		t.Errorf("undelete error %q answers to IsNotFound; a tree walk would swallow it", err)
	}
}

// The same for revert, which reports the condition without reading it either.
func TestRevertFailureIsNotANotFound(t *testing.T) {
	isolateHome(t)
	versionedFake(t)
	c := newTestCLI(t)

	err := c.cmdRevert("revert", "secret/s", "1")
	if err == nil {
		t.Fatal("cmdRevert onto a destroyed version = nil, want an error")
	}
	if vault.IsNotFound(err) {
		t.Errorf("revert error %q answers to IsNotFound, but nothing was missing", err)
	}
}
