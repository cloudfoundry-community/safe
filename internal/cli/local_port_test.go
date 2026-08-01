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
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	p := startSafeLocal(t, home, engine, "dodger")

	awaitLocalReady(t, p, 30*time.Second)
	cfg, ok := readSafercAt(t, home)
	if !ok || cfg.Vaults["dodger"] == nil {
		t.Fatalf("no registered target after readiness:\n%s", p.output.String())
	}
	if url := cfg.Vaults["dodger"].URL; strings.HasSuffix(url, fmt.Sprintf(":%d", held)) {
		t.Errorf("safe local claims the held port: %s", url)
	}

	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGINT)
	if _, ok := p.waitExit(15 * time.Second); !ok {
		t.Errorf("safe local did not exit after SIGINT:\n%s", p.output.String())
	}
}

// An explicit --port that is taken is an error naming the port and the way
// out -- not an auto-retry onto a port the operator did not ask for, and not
// a startup timeout with the server's stderr dumped raw.
func TestLocalExplicitPortHeldFailsAccurately(t *testing.T) {
	engine := localEngine(t)
	held := holdPort(t)

	home := t.TempDir()
	p := startSafeLocal(t, home, engine, "pinned", "--port", fmt.Sprintf("%d", held))

	err, ok := p.waitExit(30 * time.Second)
	if !ok {
		t.Fatalf("safe local did not exit with its port held:\n%s", p.output.String())
	}
	if err == nil {
		t.Errorf("safe local exited zero with its port held:\n%s", p.output.String())
	}

	out := p.output.String()
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

// strangerVault answers on a port of our choosing like a live,
// already-initialized vault, and records every Init it receives.
func strangerVault(t *testing.T) (int, *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding the stranger's port: %v", err)
	}
	var inits atomic.Int64
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.HasSuffix(r.URL.Path, "/sys/init") && r.Method != http.MethodGet {
				inits.Add(1)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":["Vault is already initialized"]}`))
				return
			}
			_, _ = w.Write([]byte(`{"initialized":true,"sealed":false,"standby":false}`))
		}),
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().(*net.TCPAddr).Port, &inits
}

// A stranger already answering on the chosen port must be refused, never
// initialized. The child loses the bind and says so, but not instantly --
// and an answer on the port arrives before the child has even tried. If
// that answer counts as readiness, safe sends Init to a vault it never
// started, which is the incident, replayed deterministically.
func TestLocalRefusesStrangerOnExplicitPort(t *testing.T) {
	engine := localEngine(t)
	port, inits := strangerVault(t)

	home := t.TempDir()
	p := startSafeLocal(t, home, engine, "usurped", "--port", fmt.Sprintf("%d", port))

	err, ok := p.waitExit(30 * time.Second)
	if !ok {
		t.Fatalf("safe local did not exit with a stranger on its port:\n%s", p.output.String())
	}
	if err == nil {
		t.Errorf("safe local exited zero with a stranger on its port:\n%s", p.output.String())
	}
	if n := inits.Load(); n != 0 {
		t.Errorf("the stranger received %d Init calls; want 0\n%s", n, p.output.String())
	}
	if !strings.Contains(p.output.String(), fmt.Sprintf("port %d is already in use", port)) {
		t.Errorf("failure does not diagnose the held port %d:\n%s", port, p.output.String())
	}
	if cfg, ok := readSafercAt(t, home); ok {
		if _, found := cfg.Vaults["usurped"]; found {
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
	p := startSafeLocal(t, home, engine, "bounded",
		"--listener", fmt.Sprintf("address=127.0.0.1:%d", held))

	exitErr, ok := p.waitExit(60 * time.Second)
	if !ok {
		t.Fatalf("retry loop did not terminate:\n%s", p.output.String())
	}
	if exitErr == nil {
		t.Errorf("safe local exited zero with its listener address held:\n%s", p.output.String())
	}

	if !strings.Contains(p.output.String(), "10 attempts") {
		t.Errorf("failure does not report the bounded attempts:\n%s", p.output.String())
	}

	// Every attempt's temp config file must be cleaned up. The process ran
	// with a private TMPDIR, so anything left there is safe's own leak.
	leftovers, err := filepath.Glob(filepath.Join(p.tmpDir, "kazoo*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(leftovers) > 0 {
		t.Errorf("%d temp config files leaked: %v", len(leftovers), leftovers)
	}
}
