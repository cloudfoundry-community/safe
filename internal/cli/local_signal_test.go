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
	"os"
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
