//go:build unix

package cli

// `safe local` must talk only to the server it starts. It used to build its
// client by re-reading ~/.saferc and applying whatever `current` named -- so
// a stale, concurrently changed, or unwritable config aimed Init(1,1) at a
// remote production Vault. These tests target the real binary at a recording
// decoy and require that it receives no requests, ever.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/cloudfoundry-community/safe/pkg/rc"
)

// localEngine names an installed engine binary, or skips the test.
func localEngine(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"vault", "bao"} {
		if _, err := exec.LookPath(name); err == nil {
			return name
		}
	}
	t.Skip("neither vault nor bao is installed; skipping safe local test")
	return ""
}

// decoyVault records every request it receives. A `safe local` that reaches
// it has connected through config state instead of to its own server.
func decoyVault(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		t.Logf("decoy vault received: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// localProc is one `safe local` process under test. done is closed once the
// single reaper goroutine has collected the exit, after which waitErr holds
// it; every consumer -- tests, fleet teardown, the launch cleanup -- reads
// that instead of calling Wait themselves, so nothing races over the one
// Wait a process allows, and pollers can tell a death from a slow start.
type localProc struct {
	name    string
	cmd     *exec.Cmd
	output  *lockedBuffer
	tmpDir  string
	done    chan struct{}
	waitErr error
}

// exited reports whether the process has been reaped.
func (p *localProc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// waitExit waits up to d for the exit and returns it; ok is false on
// timeout, and the caller decides how loudly that fails.
func (p *localProc) waitExit(d time.Duration) (err error, ok bool) {
	select {
	case <-p.done:
		return p.waitErr, true
	case <-time.After(d):
		return nil, false
	}
}

// awaitLocalReady waits for the "Now targeting" line, failing fast with the
// process's own words if it dies first instead of sitting out the deadline.
func awaitLocalReady(t *testing.T, p *localProc, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if strings.Contains(p.output.String(), "Now targeting") {
			return
		}
		if p.exited() {
			t.Fatalf("%s exited before becoming ready:\n%s", p.name, p.output.String())
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not become ready:\n%s", p.name, p.output.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// startSafeLocal runs `safe local --memory --as <name>` in its own process
// group under the given home, so the whole tree (safe plus the server child)
// can be torn down without orphans. The process gets a private TMPDIR so
// tests can check exactly which temp files it leaves behind.
func startSafeLocal(t *testing.T, home, engine, name string, extra ...string) *localProc {
	t.Helper()
	args := append([]string{"local", "--memory", "--engine", engine, "--as", name}, extra...)
	tmpDir := t.TempDir()
	cmd := exec.Command(safeBinary(t), args...)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"TMPDIR="+tmpDir,
		"SAFE_TARGET=",
		"VAULT_ADDR=",
		"VAULT_TOKEN=",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var output lockedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting safe local: %v", err)
	}
	p := &localProc{name: name, cmd: cmd, output: &output, tmpDir: tmpDir, done: make(chan struct{})}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
	})
	return p
}

func readSafercAt(t *testing.T, home string) (rc.Config, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, ".saferc"))
	if err != nil {
		return rc.Config{}, false
	}
	var cfg rc.Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("~/.saferc does not parse: %v\n%s", err, b)
	}
	return cfg, true
}

// A reachable target named by `current` must receive nothing while safe
// local brings up, initializes, and tears down its own server.
func TestLocalNeverTouchesConfiguredTarget(t *testing.T) {
	engine := localEngine(t)
	decoy, hits := decoyVault(t)

	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".saferc"), fmt.Appendf(nil,
		"version: 1\ncurrent: prod\nvaults:\n  prod:\n    url: %s\n    token: prod-token\n",
		decoy.URL), 0600); err != nil {
		t.Fatalf("seeding ~/.saferc: %v", err)
	}

	p := startSafeLocal(t, home, engine, "isolated")

	// "Now targeting" is printed once setup is complete and safe has settled
	// into waiting on its server; interrupting before that point exercises
	// the setup error paths instead of the teardown.
	awaitLocalReady(t, p, 30*time.Second)
	if cfg, ok := readSafercAt(t, home); !ok || cfg.Vaults["isolated"] == nil || cfg.Vaults["isolated"].Token == "" {
		t.Errorf("ready without a stored token for the temporary target")
	}

	// Wind the server down the way Ctrl-C would: SIGINT to the process
	// group. safe ignores it; the server exits; safe cleans up.
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGINT)
	if _, ok := p.waitExit(15 * time.Second); !ok {
		t.Errorf("safe local did not exit after SIGINT:\n%s", p.output.String())
	}

	if n := hits.Load(); n != 0 {
		t.Errorf("the configured target received %d requests from safe local; want 0\n%s", n, p.output.String())
	}

	// And the teardown removed the temporary target, restoring `prod`.
	if cfg, ok := readSafercAt(t, home); ok {
		if _, found := cfg.Vaults["isolated"]; found {
			t.Errorf("temporary target still present after teardown")
		}
		if cfg.Current != "prod" {
			t.Errorf("current = %q after teardown, want %q", cfg.Current, "prod")
		}
	}
}

// The incident replay: when the config cannot be written, safe local used to
// carry on with the stale config -- whose `current` named a remote Vault --
// and issue Init(1,1) at it. It must abort instead, touching nothing.
func TestLocalAbortsWhenConfigUnwritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	engine := localEngine(t)
	decoy, hits := decoyVault(t)

	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".saferc"), fmt.Appendf(nil,
		"version: 1\ncurrent: prod\nvaults:\n  prod:\n    url: %s\n    token: prod-token\n",
		decoy.URL), 0600); err != nil {
		t.Fatalf("seeding ~/.saferc: %v", err)
	}
	if err := os.Chmod(home, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0700) })

	p := startSafeLocal(t, home, engine, "isolated")

	err, ok := p.waitExit(30 * time.Second)
	if !ok {
		t.Fatalf("safe local did not abort with an unwritable config:\n%s", p.output.String())
	}
	if err == nil {
		t.Errorf("safe local exited zero with an unwritable config:\n%s", p.output.String())
	}

	if n := hits.Load(); n != 0 {
		t.Errorf("the configured target received %d requests; want 0\n%s", n, p.output.String())
	}
	if !strings.Contains(p.output.String(), ".saferc") {
		t.Errorf("abort message does not name the config file:\n%s", p.output.String())
	}
}
