package cli

// End-to-end coverage for safe gen and safe uuid writing to a colon-bearing
// path, driven through the fake Vault in vault_fake_test.go.
//
// Both commands split the path:key argument themselves, which unescapes the
// path, and then hand the result to Read and Write, which split again. The
// generated value has to land at the path the user named.

import (
	"testing"

	"github.com/pborman/uuid"
)

// defaultGenPolicy mirrors the character policy the CLI sets before dispatching
// gen; random() needs a non-empty policy.
const defaultGenPolicy = "a-zA-Z0-9"

// gen writes the new password into the colon-bearing secret, keeping the keys
// already there and leaving the truncated sibling alone.
func TestCmdGenColonBearingPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/we:ird", map[string]string{"existing": "keep"})
	fv.set("secret/we", map[string]string{"other": "untouched"})

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	if err := c.cmdGen("gen", `secret/we\:ird:pw`); err != nil {
		t.Fatalf("cmdGen: %v", err)
	}

	kv := fv.get("secret/we:ird")
	if len(kv["pw"]) != 64 {
		t.Errorf("secret/we:ird[pw] has length %d, want 64 (keys: %v)", len(kv["pw"]), kv)
	}
	if kv["existing"] != "keep" {
		t.Errorf("secret/we:ird = %v, want the existing key preserved", kv)
	}
	if sib := fv.get("secret/we"); sib["other"] != "untouched" {
		t.Errorf("sibling secret/we = %v, want map[other:untouched]", sib)
	}
}

// The colon-free control: gen against an ordinary path still writes a password.
func TestCmdGenPlainPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	if err := c.cmdGen("gen", "secret/plain:pw"); err != nil {
		t.Fatalf("cmdGen: %v", err)
	}
	if kv := fv.get("secret/plain"); len(kv["pw"]) != 64 {
		t.Errorf("secret/plain[pw] has length %d, want 64 (keys: %v)", len(kv["pw"]), kv)
	}
}

// uuid has the same shape as gen and must reach the same path.
func TestCmdUuidColonBearingPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/we", map[string]string{"other": "untouched"})

	c := newKeygenCLI(t)
	if err := c.cmdUuid("uuid", `secret/we\:ird:id`); err != nil {
		t.Fatalf("cmdUuid: %v", err)
	}

	kv := fv.get("secret/we:ird")
	if uuid.Parse(kv["id"]) == nil {
		t.Errorf("secret/we:ird[id] = %q, want a UUID (keys: %v)", kv["id"], kv)
	}
	if sib := fv.get("secret/we"); sib["other"] != "untouched" {
		t.Errorf("sibling secret/we = %v, want map[other:untouched]", sib)
	}
}

// The colon-free control: uuid against an ordinary path still writes a UUID.
func TestCmdUuidPlainPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	if err := c.cmdUuid("uuid", "secret/plain:id"); err != nil {
		t.Fatalf("cmdUuid: %v", err)
	}
	if kv := fv.get("secret/plain"); uuid.Parse(kv["id"]) == nil {
		t.Errorf("secret/plain[id] = %q, want a UUID (keys: %v)", kv["id"], kv)
	}
}
