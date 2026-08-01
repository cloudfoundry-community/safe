package cli

// Tests for cmdVault (server.go): the passthrough to the system `vault`
// binary. A fake `vault` executable placed first on PATH records its
// arguments and environment in a file, so the passthrough can be driven
// deterministically without a real Vault installation.
//
// captureStderr mutates os.Stderr — do NOT add t.Parallel to any test in
// this file.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeBin writes an executable shell script into a fresh directory and
// prepends that directory to PATH for the duration of the test, so the script
// shadows any real binary of the same name.
func installFakeBin(t *testing.T, name, script string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0700); err != nil { // #nosec G306 -- must be executable
		t.Fatalf("writing fake %s: %v", name, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// installFakeVaultRecorder installs a fake `vault` that dumps its argv and
// environment to a file and exits with $FAKE_VAULT_EXIT (default 0). It
// returns the path of the dump file.
func installFakeVaultRecorder(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "vault-run.txt")
	t.Setenv("FAKE_VAULT_OUT", out)
	installFakeBin(t, "vault", `#!/bin/sh
{
  printf 'args:'
  for a in "$@"; do printf ' %s' "$a"; done
  printf '\n'
  env
} > "$FAKE_VAULT_OUT"
exit "${FAKE_VAULT_EXIT:-0}"
`)
	return out
}

// clearProxyEnv empties every variable NewProxyRouter and cmdVault consult so
// the developer's real proxy settings cannot leak into an assertion.
func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"NO_PROXY", "no_proxy",
		"SAFE_ALL_PROXY", "safe_all_proxy",
	} {
		// t.Setenv registers the restore; Unsetenv removes the variable so it
		// does not appear in os.Environ() as an empty entry.
		t.Setenv(name, "")
		_ = os.Unsetenv(name)
	}
}

func TestCmdVault_UnknownTargetErrors(t *testing.T) {
	isolateHome(t)
	c := &CLI{opt: &Options{}, r: NewRunner()}
	c.opt.UseTarget = "no-such-target"

	err := c.cmdVault("vault", "status")
	if err == nil {
		t.Fatal("expected an error for an unknown target, got nil")
	}
	if !strings.Contains(err.Error(), "no-such-target") {
		t.Errorf("error does not name the unknown target: %v", err)
	}
}

func TestCmdVault_RunsVaultBinaryWithArgs(t *testing.T) {
	isolateHome(t)
	clearProxyEnv(t)
	out := installFakeVaultRecorder(t)
	c := &CLI{opt: &Options{}, r: NewRunner()}

	if err := c.cmdVault("vault", "token", "lookup"); err != nil {
		t.Fatalf("cmdVault returned unexpected error: %v", err)
	}

	dump, err := os.ReadFile(out) // #nosec G304 -- test-owned temp file
	if err != nil {
		t.Fatalf("the fake vault left no dump, so it never ran: %v", err)
	}
	if !strings.Contains(string(dump), "args: token lookup") {
		t.Errorf("fake vault saw the wrong arguments:\n%s", dump)
	}
}

func TestCmdVault_PropagatesNonZeroExit(t *testing.T) {
	isolateHome(t)
	clearProxyEnv(t)
	installFakeVaultRecorder(t)
	t.Setenv("FAKE_VAULT_EXIT", "3")
	c := &CLI{opt: &Options{}, r: NewRunner()}

	err := c.cmdVault("vault", "status")
	if err == nil {
		t.Fatal("expected the vault exit status to surface as an error, got nil")
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *exec.ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() != 3 {
		t.Errorf("exit code: got %d, want 3", exitErr.ExitCode())
	}
}

func TestCmdVault_NoClobberIsWarnedAndIgnored(t *testing.T) {
	// No t.Parallel — captureStderr mutates os.Stderr.
	isolateHome(t)
	clearProxyEnv(t)
	installFakeVaultRecorder(t)
	c := &CLI{opt: &Options{}, r: NewRunner()}
	c.opt.SkipIfExists = true

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdVault("vault", "status")
	})
	if err != nil {
		t.Fatalf("cmdVault returned unexpected error: %v", err)
	}
	if !strings.Contains(stderr, "--no-clobber") || !strings.Contains(stderr, "ignored") {
		t.Errorf("expected a warning that --no-clobber is ignored, got: %q", stderr)
	}
}

func TestCmdVault_StatusUnsetsVaultNamespace(t *testing.T) {
	isolateHome(t)
	clearProxyEnv(t)
	out := installFakeVaultRecorder(t)
	t.Setenv("VAULT_NAMESPACE", "testns")
	c := &CLI{opt: &Options{}, r: NewRunner()}

	// The leading flag exercises the skip-flags-then-check loop.
	if err := c.cmdVault("vault", "-tls-skip-verify", "status"); err != nil {
		t.Fatalf("cmdVault returned unexpected error: %v", err)
	}

	dump, err := os.ReadFile(out) // #nosec G304 -- test-owned temp file
	if err != nil {
		t.Fatalf("the fake vault left no dump, so it never ran: %v", err)
	}
	if strings.Contains(string(dump), "VAULT_NAMESPACE=testns") {
		t.Errorf("vault status still saw VAULT_NAMESPACE:\n%s", dump)
	}
}

func TestCmdVault_NonStatusKeepsVaultNamespace(t *testing.T) {
	isolateHome(t)
	clearProxyEnv(t)
	out := installFakeVaultRecorder(t)
	t.Setenv("VAULT_NAMESPACE", "testns")
	c := &CLI{opt: &Options{}, r: NewRunner()}

	if err := c.cmdVault("vault", "token", "lookup"); err != nil {
		t.Fatalf("cmdVault returned unexpected error: %v", err)
	}

	dump, err := os.ReadFile(out) // #nosec G304 -- test-owned temp file
	if err != nil {
		t.Fatalf("the fake vault left no dump, so it never ran: %v", err)
	}
	if !strings.Contains(string(dump), "VAULT_NAMESPACE=testns") {
		t.Errorf("VAULT_NAMESPACE did not reach the vault binary:\n%s", dump)
	}
}

func TestCmdVault_UppercasesLowercaseProxyVars(t *testing.T) {
	isolateHome(t)
	clearProxyEnv(t)
	out := installFakeVaultRecorder(t)
	t.Setenv("http_proxy", "http://127.0.0.1:9")
	t.Setenv("https_proxy", "http://127.0.0.1:10")
	t.Setenv("no_proxy", "internal.example.com")
	c := &CLI{opt: &Options{}, r: NewRunner()}

	if err := c.cmdVault("vault", "token", "lookup"); err != nil {
		t.Fatalf("cmdVault returned unexpected error: %v", err)
	}

	dump, err := os.ReadFile(out) // #nosec G304 -- test-owned temp file
	if err != nil {
		t.Fatalf("the fake vault left no dump, so it never ran: %v", err)
	}
	env := string(dump)
	if !strings.Contains(env, "HTTP_PROXY=http://127.0.0.1:9") {
		t.Errorf("http_proxy was not promoted to HTTP_PROXY:\n%s", env)
	}
	if strings.Contains(env, "http_proxy=http://127.0.0.1:9") {
		t.Errorf("lowercase http_proxy leaked through unconverted:\n%s", env)
	}
	if !strings.Contains(env, "HTTPS_PROXY=http://127.0.0.1:10") {
		t.Errorf("https_proxy was not promoted to HTTPS_PROXY:\n%s", env)
	}
	if !strings.Contains(env, "NO_PROXY=internal.example.com") {
		t.Errorf("no_proxy was not promoted to NO_PROXY:\n%s", env)
	}
}

func TestCmdVault_BadSSHProxyErrors(t *testing.T) {
	isolateHome(t)
	clearProxyEnv(t)
	installFakeVaultRecorder(t)
	// An ssh+socks5 proxy with no private key fails inside NewProxyRouter
	// before any network activity.
	t.Setenv("SAFE_ALL_PROXY", "ssh+socks5://user@127.0.0.1:22")
	c := &CLI{opt: &Options{}, r: NewRunner()}

	err := c.cmdVault("vault", "status")
	if err == nil {
		t.Fatal("expected a proxy setup error, got nil")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("expected the missing private key named, got: %v", err)
	}
}
