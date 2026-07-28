package cli

// Pre-connect guard tests for cmdValues. Argument expansion and prompting
// happen before connect(), so bad @-arguments and an empty prompt response
// must error without any Vault connection. Match behavior itself is covered
// by the FindValueMatches tests in pkg/vault.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

// TestCmdValues_EmptyPrompt_NoValuesError: with no positional values, safe
// prompts for one; an empty response is a hard error raised before connect.
func TestCmdValues_EmptyPrompt_NoValuesError(t *testing.T) {
	isolateHome(t)
	prompt.SetReader(strings.NewReader("\n"))
	t.Cleanup(func() { prompt.SetReader(nil) })

	c := newTestCLI(t)
	err := c.cmdValues("values")
	if err == nil {
		t.Fatal("expected an error for an empty prompt response, got nil")
	}
	if !strings.Contains(err.Error(), "no values specified") {
		t.Errorf("error %q should mention 'no values specified'", err)
	}
}

// A bare @ argument fails during expansion, before connect.
func TestCmdValues_BareAt_Errors(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	err := c.cmdValues("values", "@")
	if err == nil {
		t.Fatal("expected an error for bare @, got nil")
	}
	if !strings.Contains(err.Error(), "no file specified") {
		t.Errorf("error %q should mention 'no file specified'", err)
	}
}

// An unreadable @FILE argument fails during expansion, before connect.
func TestCmdValues_MissingFile_Errors(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	err := c.cmdValues("values", "@"+missing)
	if err == nil {
		t.Fatal("expected an error for a missing @FILE, got nil")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q should name the file %q", err, missing)
	}
}
