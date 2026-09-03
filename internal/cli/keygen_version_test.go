package cli

// Coverage for gen and uuid refusing a version in the path they write to.
//
// Both commands accept path:key -- the key names what they are about to
// create -- so they cannot use assertWritablePath, which refuses a key as
// well. A version is a different matter: it names a revision that already
// exists, and neither command can write one, so naming one has to be an
// error rather than something quietly dropped.

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// assertVersionRefused fails unless err complains about the version notation.
func assertVersionRefused(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error naming the version notation, got nil")
	}
	if !strings.Contains(err.Error(), "/path^version") {
		t.Fatalf("error = %q, want it to name the /path^version notation", err)
	}
}

// ---------------------------------------------------------------------------
// gen
// ---------------------------------------------------------------------------

// The path:key form carries the version on the key, where gen splits the
// argument itself and used to discard it.
func TestCmdGenRefusesAVersionOnTheKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	assertVersionRefused(t, c.cmdGen("gen", `secret/g:pw^7`))

	if kv := fv.get("secret/g"); len(kv) != 0 {
		t.Errorf("secret/g = %v, want nothing written", kv)
	}
}

// The separate-key form can carry the version on the KEY argument instead
// of the path, and that form went unchecked: PATH:KEY refuses it, but
// PATH KEY wrote a literal key named "pw^2" -- unreadable through safe's own
// path:key^version syntax -- because only PathHasKey was checked on the key
// argument, not PathHasVersion.
func TestCmdGenRefusesAVersionOnTheSeparateKeyArgument(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	assertVersionRefused(t, c.cmdGen("gen", "secret/g", `pw^2`))

	if kv := fv.get("secret/g"); len(kv) != 0 {
		t.Errorf("secret/g = %v, want nothing written", kv)
	}
}

// The separate-key form carries the version on the path. This already
// failed, but only once Write was reached, after the password had been
// generated.
func TestCmdGenRefusesAVersionOnThePath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	assertVersionRefused(t, c.cmdGen("gen", `secret/g^7`, "pw"))

	if kv := fv.get("secret/g"); len(kv) != 0 {
		t.Errorf("secret/g = %v, want nothing written", kv)
	}
}

// An escaped caret is part of the name, not a version, so it still writes.
// This is what separates a check on the path syntax from one on the byte.
func TestCmdGenAcceptsAnEscapedCaret(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	if err := c.cmdGen("gen", `secret/g\^7:pw`); err != nil {
		t.Fatalf("cmdGen: %v", err)
	}
	if kv := fv.get(`secret/g^7`); len(kv["pw"]) != 64 {
		t.Errorf("secret/g^7[pw] has length %d, want 64 (keys: %v)", len(kv["pw"]), kv)
	}
}

// Version 0 means the latest, which is what gen writes anyway.
func TestCmdGenAcceptsVersionZero(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	if err := c.cmdGen("gen", `secret/g:pw^0`); err != nil {
		t.Fatalf("cmdGen: %v", err)
	}
	if kv := fv.get("secret/g"); len(kv["pw"]) != 64 {
		t.Errorf("secret/g[pw] has length %d, want 64 (keys: %v)", len(kv["pw"]), kv)
	}
}

// A later path is refused too, and the refusal names it rather than the one
// that came before.
func TestCmdGenRefusesAVersionOnALaterPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	err := c.cmdGen("gen", "secret/first:pw", `secret/second:pw^7`)
	assertVersionRefused(t, err)
	if !strings.Contains(err.Error(), "secret/second") {
		t.Errorf("error = %q, want it to name secret/second", err)
	}
	if kv := fv.get("secret/second"); len(kv) != 0 {
		t.Errorf("secret/second = %v, want nothing written", kv)
	}
}

// ---------------------------------------------------------------------------
// uuid
// ---------------------------------------------------------------------------

func TestCmdUuidRefusesAVersionOnTheKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	assertVersionRefused(t, c.cmdUuid("uuid", `secret/u:id^7`))

	if kv := fv.get("secret/u"); len(kv) != 0 {
		t.Errorf("secret/u = %v, want nothing written", kv)
	}
}

func TestCmdUuidRefusesAVersionOnThePath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	assertVersionRefused(t, c.cmdUuid("uuid", `secret/u^7`))

	if kv := fv.get("secret/u"); len(kv) != 0 {
		t.Errorf("secret/u = %v, want nothing written", kv)
	}
}

func TestCmdUuidAcceptsAnEscapedCaret(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	if err := c.cmdUuid("uuid", `secret/u\^7:id`); err != nil {
		t.Fatalf("cmdUuid: %v", err)
	}
	kv := fv.get(`secret/u^7`)
	if _, err := uuid.Parse(kv["id"]); err != nil {
		t.Errorf("secret/u^7[id] = %q, want a UUID (keys: %v)", kv["id"], kv)
	}
}
