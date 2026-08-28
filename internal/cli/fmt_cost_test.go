package cli

// The --cost flag on `safe fmt` chooses the bcrypt work factor. The cost is
// embedded in the hash ("$2a$<cost>$..."), so the value that reached the
// bcrypt library is read straight off what was written to the Vault.

import (
	"strings"
	"testing"
)

func TestCmdFmtBcryptDefaultCost(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/pw", map[string]string{"password": "hunter2"})

	c := newTestCLI(t)
	if err := c.cmdFmt("fmt", "bcrypt", "secret/pw", "password", "hash"); err != nil {
		t.Fatalf("cmdFmt: %v", err)
	}

	hash := fv.get("secret/pw")["hash"]
	if !strings.HasPrefix(hash, "$2a$12$") {
		t.Errorf("bcrypt hash cost prefix = %q, want $2a$12$", hash)
	}
}

func TestCmdFmtBcryptChosenCost(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/pw", map[string]string{"password": "hunter2"})

	c := newTestCLI(t)
	c.opt.Fmt.Cost = 10
	if err := c.cmdFmt("fmt", "bcrypt", "secret/pw", "password", "hash"); err != nil {
		t.Fatalf("cmdFmt: %v", err)
	}

	hash := fv.get("secret/pw")["hash"]
	if !strings.HasPrefix(hash, "$2a$10$") {
		t.Errorf("bcrypt hash cost prefix = %q, want $2a$10$", hash)
	}
}

func TestCmdFmtBcryptCostBelowMinimumError(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/pw", map[string]string{"password": "hunter2"})

	c := newTestCLI(t)
	c.opt.Fmt.Cost = 9
	err := c.cmdFmt("fmt", "bcrypt", "secret/pw", "password", "hash")
	if err == nil {
		t.Fatal("cmdFmt with --cost 9: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "10") {
		t.Errorf("error %q does not name the minimum cost of 10", err)
	}
	if _, ok := fv.get("secret/pw")["hash"]; ok {
		t.Error("hash was written despite the cost error")
	}
}
