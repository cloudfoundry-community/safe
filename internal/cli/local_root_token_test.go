//go:build unix

package cli

// Reopening an existing local vault with --root-token-file. OpenBao
// disables the unauthenticated sys/generate-root API by default, so a
// caller that already holds the root token hands it to safe in a file, and
// safe must use that token without ever calling generate-root.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

// initializedRaftDir returns a raft directory that reads as initialized,
// which is all cmdLocal looks at before it launches the engine.
func initializedRaftDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "raft")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vault.db"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeTokenFile writes a root token file with mode 0600.
func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "root.key")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// noReadReader fails the test if anything reads from it. It stands in for
// stdin where safe must give up before it prompts for the unseal key.
type noReadReader struct{ t *testing.T }

func (r noReadReader) Read([]byte) (int, error) {
	r.t.Fatalf("safe read the unseal key before it refused the root token file")
	return 0, nil
}

func TestLocalReopensWithSavedRootToken(t *testing.T) {
	installFakeLocalVault(t)
	// Keep the engine running so the registered target can be read while
	// safe is still up.
	t.Setenv("SAFE_FAKE_VAULT_FAIL", "hang")
	genroot := filepath.Join(t.TempDir(), "generate-root.log")
	t.Setenv("SAFE_FAKE_VAULT_GENROOT_LOG", genroot)

	home := t.TempDir()
	tokenFile := writeTokenFile(t, "  saved-root-token\n")
	p := startSafeLocalWith(t, home, "reopened", "local-seal-key\n",
		"local", "--raft", initializedRaftDir(t), "--engine", "vault", "--as", "reopened",
		"--port", fmt.Sprintf("%d", freeRaftPort(t)), "--root-token-file", tokenFile)

	awaitLocalReady(t, p, 30*time.Second)

	cfg, ok := readSafercAt(t, home)
	if !ok || cfg.Vaults["reopened"] == nil {
		t.Fatalf("no registered target after readiness:\n%s", p.output.String())
	}
	if cfg.Vaults["reopened"].Token != "saved-root-token" {
		t.Errorf("the target does not carry the token from %s", tokenFile)
	}
	if _, err := os.Stat(genroot); !os.IsNotExist(err) {
		calls, _ := os.ReadFile(genroot) // #nosec G304 -- test temp file
		t.Errorf("safe called sys/generate-root despite --root-token-file:\n%s", calls)
	}
	if strings.Contains(p.output.String(), "saved-root-token") {
		t.Errorf("safe printed the root token")
	}

	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("delivering SIGTERM: %v", err)
	}
	if _, ok := p.waitExit(15 * time.Second); !ok {
		t.Fatalf("safe local did not exit after SIGTERM:\n%s", p.output.String())
	}
}

func TestCmdLocal_RootTokenFileRefusals(t *testing.T) {
	t.Run("memory storage has nothing to reopen", func(t *testing.T) {
		isolateHome(t)
		t.Setenv("PATH", t.TempDir())
		c := localCLI(t)
		c.opt.Local.Memory = true
		c.opt.Local.RootTokenFile = writeTokenFile(t, "saved-root-token\n")

		err := c.cmdLocal("local")
		if err == nil {
			t.Fatal("expected an error for --root-token-file with --memory, got nil")
		}
		for _, want := range []string{"--root-token-file", "--memory"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error should name %s, got: %v", want, err)
			}
		}
	})

	t.Run("uninitialized storage has nothing to reopen", func(t *testing.T) {
		isolateHome(t)
		installFakeLocalVault(t)
		c := localCLI(t)
		dir := filepath.Join(t.TempDir(), "raft")
		c.opt.Local.Raft = dir
		c.opt.Local.Port = freePort(t)
		c.opt.Local.RootTokenFile = writeTokenFile(t, "saved-root-token\n")

		var err error
		captureStdout(t, func() {
			captureStderr(t, func() {
				err = c.cmdLocal("local")
			})
		})
		if err == nil {
			t.Fatal("expected an error for --root-token-file on uninitialized storage, got nil")
		}
		if !strings.Contains(err.Error(), "--root-token-file") || !strings.Contains(err.Error(), "initialized") {
			t.Errorf("unexpected error wording: %v", err)
		}
		if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
			t.Errorf("the raft directory was created before the refusal")
		}
	})

	t.Run("an empty token file is refused before the unseal prompt", func(t *testing.T) {
		isolateHome(t)
		installFakeLocalVault(t)
		prompt.SetReader(noReadReader{t})
		t.Cleanup(func() { prompt.SetReader(nil) })
		c := localCLI(t)
		c.opt.Local.Raft = initializedRaftDir(t)
		c.opt.Local.Port = freePort(t)
		c.opt.Local.RootTokenFile = writeTokenFile(t, " \n\t\n")

		err := c.cmdLocal("local")
		if err == nil {
			t.Fatal("expected an error for an empty token file, got nil")
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("unexpected error wording: %v", err)
		}
	})
}

func TestReadRootTokenFile(t *testing.T) {
	t.Run("trims surrounding whitespace", func(t *testing.T) {
		var warn bytes.Buffer
		got, err := readRootTokenFile(writeTokenFile(t, "\n  s.abc123 \n"), &warn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "s.abc123" {
			t.Errorf("token was not trimmed")
		}
		if warn.Len() != 0 {
			t.Errorf("unexpected warning for a 0600 file: %s", warn.String())
		}
	})
	t.Run("refuses an empty file", func(t *testing.T) {
		_, err := readRootTokenFile(writeTokenFile(t, "  \n"), &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Errorf("expected an empty-file error, got %v", err)
		}
	})
	t.Run("refuses more than one token", func(t *testing.T) {
		_, err := readRootTokenFile(writeTokenFile(t, "s.one\ns.two\n"), &bytes.Buffer{})
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if strings.Contains(err.Error(), "s.one") || strings.Contains(err.Error(), "s.two") {
			t.Errorf("the error repeats the file's contents: %v", err)
		}
	})
	t.Run("refuses a missing file", func(t *testing.T) {
		_, err := readRootTokenFile(filepath.Join(t.TempDir(), "nope"), &bytes.Buffer{})
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})
	t.Run("warns when group or others can read the file", func(t *testing.T) {
		path := writeTokenFile(t, "s.abc123\n")
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		var warn bytes.Buffer
		got, err := readRootTokenFile(path, &warn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "s.abc123" {
			t.Errorf("token was not read")
		}
		if !strings.Contains(warn.String(), path) || strings.Contains(warn.String(), "s.abc123") {
			t.Errorf("expected a warning naming the file and not the token, got: %s", warn.String())
		}
	})
}
