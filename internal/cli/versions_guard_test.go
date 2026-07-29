package cli

// versions takes a secret path. A version was already refused; a key was not,
// and used to reach Vault as part of the path and come back as a misleading
// "no secret exists".
//
// The successful lookup needs a KV v2 mount, which the CLI fake does not
// serve, so only the guards are covered here.

import (
	"strings"
	"testing"
)

func TestCmdVersionsRejectsKey(t *testing.T) {
	isolateHome(t)
	newCLIFake(t)

	c := newTestCLI(t)
	err := c.cmdVersions("versions", "secret/foo:mykey")
	if err == nil {
		t.Fatal("expected an error for a path naming a key, got nil")
	}
	if !strings.Contains(err.Error(), "key") {
		t.Errorf("error %q should mention a key", err)
	}
	if strings.Contains(err.Error(), "no secret exists") {
		t.Errorf("error %q should not report a missing secret", err)
	}
}

func TestCmdVersionsRejectsVersion(t *testing.T) {
	isolateHome(t)
	newCLIFake(t)

	c := newTestCLI(t)
	err := c.cmdVersions("versions", "secret/foo^2")
	if err == nil {
		t.Fatal("expected an error for a path naming a version, got nil")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("error %q should mention a version", err)
	}
}
