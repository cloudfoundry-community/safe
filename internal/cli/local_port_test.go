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

// compliantStrangerVault answers on a port of our choosing as a fully
// functional, already-listening Vault -- init, unseal, mount, and the
// handshake write all succeed -- and counts every request. Unlike
// strangerVault (which refuses Init), this one lets a misdirected safe local
// complete its whole lifecycle against it undetected, which is what proves a
// fix reaches the address the child actually renders rather than the one
// --port named.
func compliantStrangerVault(t *testing.T) (port int, hits *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding the stranger's port: %v", err)
	}
	var n atomic.Int64
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n.Add(1)
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/v1/sys/init" && r.Method == http.MethodPut:
				_, _ = w.Write([]byte(`{"keys":["stranger-key"],"keys_base64":["stranger-key"],"root_token":"stranger-root"}`))
			case r.URL.Path == "/v1/sys/unseal" && r.Method == http.MethodPut:
				_, _ = w.Write([]byte(`{"sealed":false}`))
			case r.URL.Path == "/v1/sys/mounts" && r.Method == http.MethodGet:
				_, _ = w.Write([]byte(`{"data":{}}`))
			case strings.HasPrefix(r.URL.Path, "/v1/sys/mounts/") && r.Method == http.MethodPost:
				w.WriteHeader(http.StatusNoContent)
			case r.URL.Path == "/v1/secret/handshake":
				w.WriteHeader(http.StatusNoContent)
			default:
				_, _ = w.Write([]byte(`{"initialized":false,"sealed":true}`))
			}
		}),
	}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return l.Addr().(*net.TCPAddr).Port, &n
}

// A --listener address= override decouples the actual bind from --port. The
// probe, the client, and the registered target must all follow the rendered
// address, not the port -- a stranger sitting on the --port value must
// receive nothing, and the real (fake) engine, bound at the overridden
// address, must get the whole lifecycle instead.
func TestLocalTargetsRenderedListenerAddressNotPort(t *testing.T) {
	installFakeLocalVault(t)
	strangerPort, hits := compliantStrangerVault(t)
	enginePort := freePort(t)

	home := t.TempDir()
	p := startSafeLocal(t, home, "vault", "listener-override",
		"--port", fmt.Sprintf("%d", strangerPort),
		"--listener", fmt.Sprintf("address=127.0.0.1:%d", enginePort))

	awaitLocalReady(t, p, 30*time.Second)

	if n := hits.Load(); n != 0 {
		t.Errorf("the stranger on --port received %d requests; want 0\n%s", n, p.output.String())
	}

	cfg, ok := readSafercAt(t, home)
	if !ok || cfg.Vaults["listener-override"] == nil {
		t.Fatalf("no registered target after readiness:\n%s", p.output.String())
	}
	want := fmt.Sprintf("http://127.0.0.1:%d", enginePort)
	if got := cfg.Vaults["listener-override"].URL; got != want {
		t.Errorf("registered target URL: got %q, want %q (the rendered listener address)", got, want)
	}

	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGINT)
	if _, ok := p.waitExit(15 * time.Second); !ok {
		t.Errorf("safe local did not exit after SIGINT:\n%s", p.output.String())
	}
}

// A MountExists or AddMount failure must kill the engine it already
// initialized and unsealed, the same as every other post-launch failure --
// not leave it running, reparented to init, holding a live root token that
// is sitting in ~/.saferc. The fake engine deliberately does not exit on its
// own for either failure (see server_local_run_test.go), so a quiet port
// here can only mean safe's own die() reached it.
func TestLocalMountFailureKillsEngine(t *testing.T) {
	for _, fail := range []string{"mounts-list", "mounts-create"} {
		t.Run(fail, func(t *testing.T) {
			installFakeLocalVault(t)
			t.Setenv("SAFE_FAKE_VAULT_FAIL", fail)
			home := t.TempDir()
			port := freePort(t)
			p := startSafeLocal(t, home, "vault", "local-"+fail, "--port", fmt.Sprintf("%d", port))

			err, ok := p.waitExit(30 * time.Second)
			if !ok {
				t.Fatalf("safe local did not exit after the mount failure:\n%s", p.output.String())
			}
			if err == nil {
				t.Errorf("safe local exited zero after the mount failure:\n%s", p.output.String())
			}
			if !strings.Contains(p.output.String(), "shutting down") {
				t.Errorf("expected a shutdown notice, got:\n%s", p.output.String())
			}

			deadline := time.Now().Add(5 * time.Second)
			for {
				client := &http.Client{Timeout: 500 * time.Millisecond}
				resp, getErr := client.Get(fmt.Sprintf("http://127.0.0.1:%d/v1/sys/health", port))
				if getErr != nil {
					break
				}
				_ = resp.Body.Close()
				if time.Now().After(deadline) {
					t.Fatalf("engine still answering on :%d after safe local's exit", port)
				}
				time.Sleep(100 * time.Millisecond)
			}

			leftovers, globErr := filepath.Glob(filepath.Join(p.tmpDir, "kazoo*"))
			if globErr != nil {
				t.Fatalf("glob: %v", globErr)
			}
			if len(leftovers) > 0 {
				t.Errorf("%d temp config files leaked: %v", len(leftovers), leftovers)
			}

			if cfg, ok := readSafercAt(t, home); ok {
				if _, found := cfg.Vaults["local-"+fail]; found {
					t.Errorf("failed start left a target in ~/.saferc")
				}
			}
		})
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
