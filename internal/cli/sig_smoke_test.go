package cli

// Signals waits for SIGTERM, SIGINT, or SIGQUIT, puts the terminal back the
// way it was found, and exits 1. The exit is the observable part, and it can
// only be seen from outside: a process that dies of the signal itself reports
// no exit code at all, while one that catches it leaves with status 1. These
// tests park safe at an interactive prompt and interrupt it.

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// interruptAtThePrompt starts safe target -i against a home with one Vault
// configured, waits for the prompt that reads from stdin, and delivers sig.
// It returns the exit status and whether the process exited on its own
// rather than being killed by the signal.
func interruptAtThePrompt(t *testing.T, sig syscall.Signal) (status int, exited bool) {
	t.Helper()

	home := t.TempDir()
	saferc := `version: 1
current: alpha
vaults:
  alpha:
    url: https://alpha.example.com
    token: token-alpha
`
	if err := os.WriteFile(filepath.Join(home, ".saferc"), []byte(saferc), 0600); err != nil {
		t.Fatalf("write .saferc: %v", err)
	}

	cmd := exec.Command(safeBinary(t), "target", "-i")
	cmd.Env = append(os.Environ(), "HOME="+home, "SAFE_TARGET=", "VAULT_ADDR=", "VAULT_TOKEN=")

	// stdin stays open so the prompt blocks instead of hitting EOF.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	defer func() { _ = stdin.Close() }()

	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting safe target -i: %v", err)
	}
	// A process that never reaches the prompt, or never dies, should fail
	// the test rather than hang it.
	killer := time.AfterFunc(30*time.Second, func() { _ = cmd.Process.Kill() })
	defer killer.Stop()

	// Wait until safe is at the prompt, reading stdin, before signaling.
	var seen strings.Builder
	buf := make([]byte, 1)
	for !strings.Contains(seen.String(), "Which Vault") {
		n, err := stderr.Read(buf)
		seen.Write(buf[:n])
		if err != nil {
			t.Fatalf("safe never asked which Vault to target; stderr so far:\n%s", seen.String())
		}
	}

	if err := cmd.Process.Signal(sig); err != nil {
		t.Fatalf("delivering %v: %v", sig, err)
	}
	_, _ = io.Copy(io.Discard, stderr)

	var exitErr *exec.ExitError
	switch err := cmd.Wait(); {
	case err == nil:
		return 0, true
	case errors.As(err, &exitErr):
		ws, ok := exitErr.Sys().(syscall.WaitStatus)
		return exitErr.ExitCode(), ok && ws.Exited()
	default:
		t.Fatalf("waiting on safe: %v", err)
		return 0, false
	}
}

// An interrupted safe leaves with exit status 1 -- its own exit, not death by
// the signal, so anything it has to put back on the way out gets put back.
func TestASignalEndsSafeWithExitStatusOne(t *testing.T) {
	for name, sig := range map[string]syscall.Signal{
		"SIGTERM": syscall.SIGTERM,
		"SIGINT":  syscall.SIGINT,
	} {
		t.Run(name, func(t *testing.T) {
			status, exited := interruptAtThePrompt(t, sig)
			if !exited {
				t.Fatalf("safe was killed by %s instead of catching it", name)
			}
			if status != 1 {
				t.Errorf("safe exited %d on %s, want 1", status, name)
			}
		})
	}
}
