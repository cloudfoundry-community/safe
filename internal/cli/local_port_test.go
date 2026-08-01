//go:build unix

package cli

// Port selection for `safe local`. The old dial probe raced every concurrent
// starter toward the same "free" port, and a lost race surfaced as a generic
// startup timeout. Selection now bind-probes, treats the server's own bind
// failure as the answer, and retries on it -- unless the operator pinned the
// port, which fails with a diagnosis instead.

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// holdPort binds and holds a port from the scan range.
func holdPort(t *testing.T) int {
	t.Helper()
	port, err := findCandidatePort(localPortScanStart)
	if err != nil {
		t.Fatalf("finding a port to hold: %v", err)
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("holding port %d: %v", port, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return port
}

// With the first scanned port held by someone else, auto-scan must come up
// on another port rather than fail or stall.
func TestLocalAutoScanAvoidsHeldPort(t *testing.T) {
	engine := localEngine(t)
	held := holdPort(t)

	home := t.TempDir()
	cmd, output, _ := startSafeLocal(t, home, engine, "dodger")

	deadline := time.Now().Add(30 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if strings.Contains(output.String(), "Now targeting") {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("safe local did not become ready:\n%s", output.String())
	}
	cfg, ok := readSafercAt(t, home)
	if !ok || cfg.Vaults["dodger"] == nil {
		t.Fatalf("no registered target after readiness:\n%s", output.String())
	}
	if url := cfg.Vaults["dodger"].URL; strings.HasSuffix(url, fmt.Sprintf(":%d", held)) {
		t.Errorf("safe local claims the held port: %s", url)
	}

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Errorf("safe local did not exit after SIGINT:\n%s", output.String())
	}
}

// An explicit --port that is taken is an error naming the port and the way
// out -- not an auto-retry onto a port the operator did not ask for, and not
// a startup timeout with the server's stderr dumped raw.
func TestLocalExplicitPortHeldFailsAccurately(t *testing.T) {
	engine := localEngine(t)
	held := holdPort(t)

	home := t.TempDir()
	cmd, output, _ := startSafeLocal(t, home, engine, "pinned", "--port", fmt.Sprintf("%d", held))

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Errorf("safe local exited zero with its port held:\n%s", output.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("safe local did not exit with its port held:\n%s", output.String())
	}

	out := output.String()
	if !strings.Contains(out, fmt.Sprintf("port %d is already in use", held)) {
		t.Errorf("failure does not diagnose the held port %d:\n%s", held, out)
	}
	if !strings.Contains(out, "--port") {
		t.Errorf("failure does not point at --port:\n%s", out)
	}

	// No half-registered target may survive the failed start.
	if cfg, ok := readSafercAt(t, home); ok {
		if _, found := cfg.Vaults["pinned"]; found {
			t.Errorf("failed start left a target in ~/.saferc")
		}
	}
}

// A listener override pinning the address to a held port defeats every
// retry; the loop must run its bounded course and then say what it tried.
// (This is also the only deterministic way to drive the retry path: the
// probe passes, the server's own bind fails, ten times.)
func TestLocalRetryLoopIsBounded(t *testing.T) {
	engine := localEngine(t)
	held := holdPort(t)

	home := t.TempDir()
	cmd, output, tmpDir := startSafeLocal(t, home, engine, "bounded",
		"--listener", fmt.Sprintf("address=127.0.0.1:%d", held))

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Errorf("safe local exited zero with its listener address held:\n%s", output.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("retry loop did not terminate:\n%s", output.String())
	}

	if !strings.Contains(output.String(), "10 attempts") {
		t.Errorf("failure does not report the bounded attempts:\n%s", output.String())
	}

	// Every attempt's temp config file must be cleaned up. The process ran
	// with a private TMPDIR, so anything left there is safe's own leak.
	leftovers, err := filepath.Glob(filepath.Join(tmpDir, "kazoo*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(leftovers) > 0 {
		t.Errorf("%d temp config files leaked: %v", len(leftovers), leftovers)
	}
}
