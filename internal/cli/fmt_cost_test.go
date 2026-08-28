package cli

// The --cost flag on `safe fmt` chooses the bcrypt work factor. The cost is
// embedded in the hash ("$2a$<cost>$..."), so the value that reached the
// bcrypt library is read straight off what was written to the Vault.
//
// Main pre-seeds opt.Fmt.Cost with vault.DefaultBcryptCost before go-cli
// parses the command line, since go-cli only overwrites the field from a
// literal --cost and otherwise leaves it at whatever it already held.
// newTestCLI builds a bare Options{} without running that seeding, so
// these tests set the field directly to whatever a real invocation would
// have carried into cmdFmt.

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func TestCmdFmtBcryptDefaultCost(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/pw", map[string]string{"password": "hunter2"})

	c := newTestCLI(t)
	c.opt.Fmt.Cost = vault.DefaultBcryptCost
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

// A bare --cost 0 must be judged like any other below-minimum value, not
// silently treated as though --cost had never been given.
func TestCmdFmtBcryptCostZeroIsRejected(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/pw", map[string]string{"password": "hunter2"})

	c := newTestCLI(t)
	c.opt.Fmt.Cost = 0
	err := c.cmdFmt("fmt", "bcrypt", "secret/pw", "password", "hash")
	if err == nil {
		t.Fatal("cmdFmt with --cost 0: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "10") {
		t.Errorf("error %q does not name the minimum cost of 10", err)
	}
	if _, ok := fv.get("secret/pw")["hash"]; ok {
		t.Error("hash was written despite the cost error")
	}
}

// A cost above what the bcrypt library will accept must be refused before
// the Vault read, not left to run for hours and then fail inside bcrypt.
func TestCmdFmtBcryptCostAboveMaximumError(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/pw", map[string]string{"password": "hunter2"})

	c := newTestCLI(t)
	c.opt.Fmt.Cost = 32
	err := c.cmdFmt("fmt", "bcrypt", "secret/pw", "password", "hash")
	if err == nil {
		t.Fatal("cmdFmt with --cost 32: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "31") {
		t.Errorf("error %q does not name the maximum cost of 31", err)
	}
	if got := len(fv.requests()); got != 0 {
		t.Errorf("cmdFmt with --cost 32 made %d requests, want 0 (refused before any Vault read)", got)
	}
	if _, ok := fv.get("secret/pw")["hash"]; ok {
		t.Error("hash was written despite the cost error")
	}
}
