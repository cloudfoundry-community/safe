package cli

// Arg-count guard tests for keygen command handlers.
//
// Covered handlers and the pre-connect guard each exercises:
//
//   cmdUuid   — requires exactly 1 arg (guard before connect)
//   cmdGen    — requires >= 1 arg after optional numeric length prefix (guard before connect)
//   cmdSsh    — requires >= 1 path arg after optional numeric bits prefix (guard before connect)
//   cmdRsa    — requires >= 1 path arg after optional numeric bits prefix (guard before connect)
//   cmdDhparam — requires >= 1 path arg after optional numeric bits prefix (guard before connect)
//
// All handlers call rc.Apply before connect(); we isolate HOME so rc.Apply
// returns an empty config without error.
//
// Cases that require a live Vault (e.g. the actual write path) are not covered
// here — those need a Vault seam (see TC-01 in testing-cli.md).

import "testing"

// newKeygenCLI builds a *CLI with keygen commands registered for r.Usage.
func newKeygenCLI(t *testing.T) *CLI {
	t.Helper()
	r := NewRunner()
	opt := &Options{}
	c := &CLI{opt: opt, r: r}
	for _, name := range []string{"uuid", "gen", "ssh", "rsa", "dhparam"} {
		r.Dispatch(name, &Help{
			Summary: name,
			Usage:   "safe " + name + " ...",
			Type:    NonDestructiveCommand,
		}, func(cmd string, args ...string) error { return nil })
	}
	c.r = r
	c.opt = opt
	return c
}

// ---------------------------------------------------------------------------
// cmdUuid
// ---------------------------------------------------------------------------

func TestCmdUuid_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newKeygenCLI(t)
	err := c.cmdUuid("uuid")
	assertUsageError(t, err, "uuid")
}

func TestCmdUuid_TwoArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newKeygenCLI(t)
	err := c.cmdUuid("uuid", "secret/path", "extra")
	assertUsageError(t, err, "uuid")
}

// ---------------------------------------------------------------------------
// cmdGen
// ---------------------------------------------------------------------------

// cmdGen with zero args (no length prefix, no path) must return *UsageError.
func TestCmdGen_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newKeygenCLI(t)
	err := c.cmdGen("gen")
	assertUsageError(t, err, "gen")
}

// cmdGen with a numeric-only arg treats it as the length, leaving zero paths —
// the inner loop guard fires.
func TestCmdGen_LengthOnlyNoPath_ReturnsUsageError(t *testing.T) {
	// "32" is parsed as length; no path follows → inner loop guard fires.
	// The loop calls connect() before the inner guard, so this requires Vault presence.
	// The zero-arg case above covers the outer guard.
	t.Skip("inner loop guard runs after connect(); requires live Vault")
}

// ---------------------------------------------------------------------------
// cmdSsh
// ---------------------------------------------------------------------------

// cmdSsh with zero args (no bits prefix, no path) returns *UsageError.
func TestCmdSsh_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newKeygenCLI(t)
	err := c.cmdSsh("ssh")
	assertUsageError(t, err, "ssh")
}

// cmdSsh with only a numeric arg (treated as bits), no path, returns *UsageError.
func TestCmdSsh_BitsOnlyNoPath_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newKeygenCLI(t)
	// "2048" parsed as bits; args becomes empty → guard fires before connect.
	err := c.cmdSsh("ssh", "2048")
	assertUsageError(t, err, "ssh")
}

// ---------------------------------------------------------------------------
// cmdRsa
// ---------------------------------------------------------------------------

func TestCmdRsa_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newKeygenCLI(t)
	err := c.cmdRsa("rsa")
	assertUsageError(t, err, "rsa")
}

func TestCmdRsa_BitsOnlyNoPath_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newKeygenCLI(t)
	err := c.cmdRsa("rsa", "4096")
	assertUsageError(t, err, "rsa")
}

// ---------------------------------------------------------------------------
// cmdDhparam
// ---------------------------------------------------------------------------

func TestCmdDhparam_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newKeygenCLI(t)
	err := c.cmdDhparam("dhparam")
	assertUsageError(t, err, "dhparam")
}

func TestCmdDhparam_BitsOnlyNoPath_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newKeygenCLI(t)
	err := c.cmdDhparam("dhparam", "2048")
	assertUsageError(t, err, "dhparam")
}
