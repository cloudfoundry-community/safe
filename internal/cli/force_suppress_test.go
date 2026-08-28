package cli

// --force may only swallow a failure when EVERY collected failure says the
// secret was not there. DeleteTree and MoveCopyTree are fan-outs, so their
// error can carry several siblings; before allNotFound, whichever failure
// won the race decided suppression alone, and a run mixing a missing path
// with a permission error could exit 0 with the 403 never shown.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/internal/parallel"
	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func TestAllNotFoundJudgesEveryCollectedFailure(t *testing.T) {
	nf := vault.NewSecretNotFoundError("secret/gone")
	nf2 := vault.NewSecretNotFoundError("secret/also-gone")
	denied := errors.New("403 Forbidden: permission denied")

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"bare not-found", nf, true},
		{"bare permission error", denied, false},
		{"every sibling not-found", parallel.NewErrors(nf, nf2), true},
		{"not-found first, denied second", parallel.NewErrors(nf, denied), false},
		{"denied first, not-found second", parallel.NewErrors(denied, nf), false},
	}
	for _, tc := range cases {
		if got := allNotFound(tc.err); got != tc.want {
			t.Errorf("%s: allNotFound = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Two concurrently failing gen paths both end up in the error, so a partial
// write is never hidden behind whichever failure happened to arrive first.
// The gate guarantees both reads are in flight together before either is
// allowed to fail.
func TestCmdGenConcurrentFailuresNameBothPaths(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.denyGet("secret/a")
	fv.denyGet("secret/b")
	fv.holdRequests(2, `^GET /v1/secret/[ab]$`)

	c := newKeygenCLI(t)

	done := make(chan error, 1)
	go func() {
		done <- c.cmdGen("gen", "secret/a", "x", "secret/b", "y")
	}()

	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		fv.holdRequests(0, `^GET /v1/secret/[ab]$`)
		err = <-done
	}

	if err == nil {
		t.Fatal("expected an error from two denied reads, got nil")
	}
	for _, path := range []string{"secret/a", "secret/b"} {
		if !strings.Contains(err.Error(), path) {
			t.Errorf("error %q does not name failed path %s", err, path)
		}
	}
}

// A recursive --force delete of a path that is not there stays a success:
// the single not-found comes back bare and is still suppressed.
func TestRecursiveForceDeleteOfMissingPathExitsZero(t *testing.T) {
	isolateHome(t)
	newCLIFake(t)

	c := newTestCLI(t)
	c.opt.Delete.Recurse = true
	c.opt.Delete.Force = true
	if err := c.cmdDelete("delete", "secret/missing"); err != nil {
		t.Fatalf("delete -Rf of a missing path: %v, want nil", err)
	}
}

// A permission failure inside the delete fan-out survives --force: only
// not-found failures may be swallowed.
func TestRecursiveForceDeleteSurfacesPermissionError(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/x/a", map[string]string{"k": "1"})
	fv.set("secret/x/b", map[string]string{"k": "2"})
	fv.denyDelete("secret/x/a")

	c := newTestCLI(t)
	c.opt.Delete.Recurse = true
	c.opt.Delete.Force = true
	err := c.cmdDelete("delete", "secret/x")
	if err == nil {
		t.Fatal("expected the denied delete to surface despite --force, got nil")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error %q should carry the permission failure", err)
	}
}
