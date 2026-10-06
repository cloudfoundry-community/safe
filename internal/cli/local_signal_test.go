//go:build unix

package cli

// `safe local` must tear itself down -- kill its engine, remove its temp
// config, restore the previous target -- on every signal that ends it, not
// just the SIGINT a terminal Ctrl-C sends. These tests deliver SIGTERM and
// SIGQUIT directly to the safe process (never the engine child, which only
// die() may kill), and separately confirm SIGINT still reaches the normal
// engine-driven shutdown path when the previously-current target carries CA
// certificates.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A signal that ends `safe local` before it has torn down must leave neither
// its engine nor its temp config behind.
func TestLocalTerminalSignalsTearDownTheEngine(t *testing.T) {
	for name, sig := range map[string]syscall.Signal{
		"SIGTERM": syscall.SIGTERM,
		"SIGQUIT": syscall.SIGQUIT,
	} {
		t.Run(name, func(t *testing.T) {
			installFakeLocalVault(t)
			// The fake must not exit on its own once the handshake lands --
			// otherwise the normal echan-driven shutdown could win the race
			// and the test would prove nothing about the signal path.
			t.Setenv("SAFE_FAKE_VAULT_FAIL", "hang")
			home := t.TempDir()
			p := startSafeLocal(t, home, "vault", "signal-"+strings.ToLower(name))

			awaitLocalReady(t, p, 30*time.Second)

			// Signal only the safe process, never the process group: an
			// engine that outlives this is safe's own doing (or not), not
			// the signal reaching it directly.
			if err := p.cmd.Process.Signal(sig); err != nil {
				t.Fatalf("delivering %s: %v", name, err)
			}
			if _, ok := p.waitExit(15 * time.Second); !ok {
				t.Fatalf("safe local did not exit after %s:\n%s", name, p.output.String())
			}

			if !strings.Contains(p.output.String(), "shutting down") {
				t.Errorf("expected a shutdown notice after %s, got:\n%s", name, p.output.String())
			}

			if cfg, ok := readSafercAt(t, home); ok {
				if _, found := cfg.Vaults["signal-"+strings.ToLower(name)]; found {
					t.Errorf("%s left the temporary target in ~/.saferc", name)
				}
			}

			leftovers, err := filepath.Glob(filepath.Join(p.tmpDir, "kazoo*"))
			if err != nil {
				t.Fatalf("glob: %v", err)
			}
			if len(leftovers) > 0 {
				t.Errorf("%d temp config files leaked after %s: %v", len(leftovers), name, leftovers)
			}
		})
	}
}

// `tmux kill-session` ends a pane with SIGHUP. The engine treats SIGHUP as a
// config reload and keeps running, so safe must take it down; otherwise the
// engine outlives the session holding the port and, under raft, the lock
// on its data. In a pane running `safe local ... 2>&1 | tee log`, tee dies
// of the same hangup, so safe's teardown must also survive writing to a
// pipe that nobody reads any more.
func TestLocalSIGHUPTearsDownTheEngine(t *testing.T) {
	for _, readerGone := range []bool{false, true} {
		name := "output read"
		if readerGone {
			name = "output reader gone"
		}
		t.Run(name, func(t *testing.T) {
			installFakeLocalVault(t)
			t.Setenv("SAFE_FAKE_VAULT_FAIL", "hang")
			home := t.TempDir()
			port := freePort(t)
			args := []string{"local", "--memory", "--engine", "vault", "--as", "signal-sighup", "--port", fmt.Sprintf("%d", port)}

			var p *localProc
			var out *os.File
			if readerGone {
				p, out = startSafeLocalPiped(t, home, "signal-sighup", args...)
			} else {
				p = startSafeLocalWith(t, home, "signal-sighup", "", args...)
			}
			awaitLocalReady(t, p, 30*time.Second)
			if out != nil {
				// What tee does when the session hangs up.
				_ = out.Close()
			}

			// Signal only the safe process: a real engine shrugs SIGHUP off,
			// so whatever stops this one has to be safe.
			if err := p.cmd.Process.Signal(syscall.SIGHUP); err != nil {
				t.Fatalf("delivering SIGHUP: %v", err)
			}
			if _, ok := p.waitExit(15 * time.Second); !ok {
				t.Fatalf("safe local did not exit after SIGHUP:\n%s", p.output.String())
			}
			assertPortQuiet(t, port)

			if cfg, ok := readSafercAt(t, home); ok {
				if _, found := cfg.Vaults["signal-sighup"]; found {
					t.Errorf("SIGHUP left the temporary target in ~/.saferc")
				}
			}
			leftovers, err := filepath.Glob(filepath.Join(p.tmpDir, "kazoo*"))
			if err != nil {
				t.Fatalf("glob: %v", err)
			}
			if len(leftovers) > 0 {
				t.Errorf("%d temp config files leaked after SIGHUP: %v", len(leftovers), leftovers)
			}
		})
	}
}

// startSafeLocalPiped is startSafeLocalWith, except that safe writes to a
// pipe the test reads until "Now targeting" appears. The returned file is
// the pipe's read end, which the test closes to play a reader that went
// away. The output buffer keeps everything read before then.
func startSafeLocalPiped(t *testing.T, home, name string, args ...string) (*localProc, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating the output pipe: %v", err)
	}
	tmpDir := t.TempDir()
	cmd := exec.Command(safeBinary(t), args...)
	cmd.Env = append(os.Environ(),
		"HOME="+home, "TMPDIR="+tmpDir, "SAFE_TARGET=", "VAULT_ADDR=", "VAULT_TOKEN=")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting safe local: %v", err)
	}
	_ = w.Close()

	var output lockedBuffer
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				_, _ = output.Write(buf[:n])
			}
			if rerr != nil {
				return
			}
		}
	}()
	p := &localProc{name: name, cmd: cmd, output: &output, tmpDir: tmpDir, done: make(chan struct{})}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
		_ = r.Close()
	})
	return p, r
}

// A previously-current target carrying ca_certs used to re-arm SIGINT
// delivery through rc.Apply's temp-CA-cert cleanup handler, which killed
// safe local outside its own teardown -- displacing the operator's real
// target with a dead temporary one. SIGINT must still reach the normal,
// engine-driven shutdown path (the engine dies from the signal too, since it
// is delivered to the whole process group; that unblocks cmdLocal's own
// wait) and restore `alpha` as current.
func TestLocalSIGINTIgnoredEvenWithCACertCurrentTarget(t *testing.T) {
	installFakeLocalVault(t)
	home := t.TempDir()
	saferc := `version: 1
current: alpha
vaults:
  alpha:
    url: https://alpha.example.com
    token: token-alpha
    ca_certs:
      - |
        -----BEGIN CERTIFICATE-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
        -----END CERTIFICATE-----
`
	if err := os.WriteFile(filepath.Join(home, ".saferc"), []byte(saferc), 0600); err != nil {
		t.Fatalf("seeding ~/.saferc: %v", err)
	}

	p := startSafeLocal(t, home, "vault", "sigint-cacert")
	awaitLocalReady(t, p, 30*time.Second)

	// The whole group: a terminal Ctrl-C reaches both safe (ignored) and the
	// engine child (which has no handler of its own and dies of it,
	// unblocking cmdLocal's wait on srv.echan).
	if err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGINT); err != nil {
		t.Fatalf("delivering SIGINT to the group: %v", err)
	}
	if _, ok := p.waitExit(15 * time.Second); !ok {
		t.Fatalf("safe local did not exit after SIGINT:\n%s", p.output.String())
	}

	if !strings.Contains(p.output.String(), "terminated normally") {
		t.Errorf("expected the normal engine-driven shutdown, not a bare kill:\n%s", p.output.String())
	}

	cfg, ok := readSafercAt(t, home)
	if !ok {
		t.Fatalf("no ~/.saferc after teardown:\n%s", p.output.String())
	}
	if _, found := cfg.Vaults["sigint-cacert"]; found {
		t.Errorf("temporary target still present after teardown")
	}
	if cfg.Current != "alpha" {
		t.Errorf("current = %q after teardown, want %q\n%s", cfg.Current, "alpha", p.output.String())
	}
	if cfg.Vaults["alpha"] == nil || cfg.Vaults["alpha"].Token != "token-alpha" {
		t.Errorf("the previously-current target was not left intact")
	}
}
