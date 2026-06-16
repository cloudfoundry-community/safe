package cli

// Arg-count guard tests for command handlers that validate argument count
// before calling connect(). Each handler calls rc.Apply(opt.UseTarget) first.
// rc.Apply reads ~/.saferc; we redirect HOME to a tmpdir so the file is absent
// and rc.Apply returns an empty config with no error.
//
// Handlers covered (guard runs before connect()):
//   - cmdDelete  — requires >= 1 arg
//   - cmdRevert  — requires exactly 2 args
//   - cmdFmt     — requires exactly 4 args
//   - cmdMove    — requires exactly 2 args
//   - cmdCopy    — requires exactly 2 args
//
// For each handler we build a minimal *CLI with NewRunner (so r.Usage works),
// ensure the guard fires, and assert the returned error is a *UsageError.
// No Vault connection is made because connect() is only called after the guard.

import (
	"errors"
	"testing"
)

// isolateHome redirects HOME and SAFE_TARGET so rc.Apply reads an empty config
// from a temp directory and does not inherit the developer's real ~/.saferc.
func isolateHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("SAFE_TARGET", "")
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("VAULT_TOKEN", "")
}

// newTestCLI builds a *CLI with a registered set of common commands so that
// r.Usage("<cmd>") can return a properly-typed *UsageError.
func newTestCLI(t *testing.T) *CLI {
	t.Helper()
	r := NewRunner()
	opt := &Options{}
	c := &CLI{opt: opt, r: r}

	// Register the commands whose guards we test. Dispatch stores the topic so
	// r.Usage works correctly.
	for _, name := range []string{
		"delete", "revert", "fmt", "move", "copy",
		"get", "exists", "undelete",
	} {
		n := name // capture
		r.Dispatch(n, &Help{
			Summary: n,
			Usage:   "safe " + n + " ...",
			Type:    NonDestructiveCommand,
		}, func(cmd string, args ...string) error { return nil })
		_ = n
	}

	c.r = r
	c.opt = opt
	return c
}

// assertUsageError fails the test if err is not a *UsageError for topic.
func assertUsageError(t *testing.T, err error, topic string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected *UsageError for topic %q, got nil", topic)
	}
	var ue *UsageError
	if !errors.As(err, &ue) {
		t.Fatalf("expected *UsageError, got %T: %v", err, err)
	}
	if ue.Topic != topic {
		t.Errorf("UsageError.Topic: got %q, want %q", ue.Topic, topic)
	}
}

// ---------------------------------------------------------------------------
// cmdDelete
// ---------------------------------------------------------------------------

func TestCmdDelete_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdDelete("delete" /* no args */)
	assertUsageError(t, err, "delete")
}

// ---------------------------------------------------------------------------
// cmdRevert
// ---------------------------------------------------------------------------

func TestCmdRevert_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdRevert("revert")
	assertUsageError(t, err, "revert")
}

func TestCmdRevert_OneArg_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdRevert("revert", "secret/path")
	assertUsageError(t, err, "revert")
}

func TestCmdRevert_ThreeArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdRevert("revert", "secret/path", "1", "extra")
	assertUsageError(t, err, "revert")
}

// ---------------------------------------------------------------------------
// cmdFmt
// ---------------------------------------------------------------------------

func TestCmdFmt_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdFmt("fmt")
	assertUsageError(t, err, "fmt")
}

func TestCmdFmt_TwoArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdFmt("fmt", "base64", "secret/path")
	assertUsageError(t, err, "fmt")
}

func TestCmdFmt_ThreeArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdFmt("fmt", "base64", "secret/path", "oldkey")
	assertUsageError(t, err, "fmt")
}

func TestCmdFmt_FiveArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdFmt("fmt", "base64", "secret/path", "oldkey", "newkey", "extra")
	assertUsageError(t, err, "fmt")
}

// ---------------------------------------------------------------------------
// cmdMove
// ---------------------------------------------------------------------------

func TestCmdMove_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdMove("move")
	assertUsageError(t, err, "move")
}

func TestCmdMove_OneArg_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdMove("move", "secret/src")
	assertUsageError(t, err, "move")
}

func TestCmdMove_ThreeArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdMove("move", "secret/src", "secret/dst", "extra")
	assertUsageError(t, err, "move")
}

// ---------------------------------------------------------------------------
// cmdCopy
// ---------------------------------------------------------------------------

func TestCmdCopy_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdCopy("copy")
	assertUsageError(t, err, "copy")
}

func TestCmdCopy_OneArg_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdCopy("copy", "secret/src")
	assertUsageError(t, err, "copy")
}

func TestCmdCopy_ThreeArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdCopy("copy", "secret/src", "secret/dst", "extra")
	assertUsageError(t, err, "copy")
}

// ---------------------------------------------------------------------------
// cmdGet
// ---------------------------------------------------------------------------

func TestCmdGet_ZeroArgs_ReturnsUsageError(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdGet("get")
	assertUsageError(t, err, "get")
}
