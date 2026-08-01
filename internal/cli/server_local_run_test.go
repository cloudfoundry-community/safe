package cli

// Full-lifecycle tests for cmdLocal (server.go). The fake `vault` on PATH
// answers `vault version` directly; for `vault server -config <file>` it
// re-executes this test binary, where TestFakeLocalVaultHelper reads the
// listener port out of the rendered config and serves just enough of the
// Vault API for cmdLocal to initialize, unseal, mount, and write the
// handshake. The helper exits shortly after the handshake write lands, which
// is what a real `safe local` sees when its Vault shuts down, so the test
// drives the whole path: startup wait, init, unseal, mount creation, target
// bookkeeping, and the cleanup that removes the temporary target again.
//
// captureStderr mutates os.Stderr — do NOT add t.Parallel to any test in
// this file.

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// scheduleExit closes done once, a beat after the current response, so the
// helper's answer reaches the client before the process goes away.
func scheduleExit(once *sync.Once, done chan struct{}) {
	once.Do(func() {
		go func() {
			time.Sleep(150 * time.Millisecond)
			close(done)
		}()
	})
}

// TestFakeLocalVaultHelper is not a test: it is the body of the fake `vault
// server` process. It only runs when the fake vault script re-executes the
// test binary with SAFE_FAKE_VAULT_HELPER=1; otherwise it skips. The
// SAFE_FAKE_VAULT_FAIL variable, inherited from the test through the script,
// selects a failure the real Vault could produce at that point.
func TestFakeLocalVaultHelper(t *testing.T) {
	if os.Getenv("SAFE_FAKE_VAULT_HELPER") != "1" {
		t.Skip("helper process body, not a test")
	}

	cfg, err := os.ReadFile(os.Getenv("SAFE_FAKE_VAULT_CONFIG")) // #nosec G304 -- path written by the test that spawned us
	if err != nil {
		os.Exit(9)
	}
	m := regexp.MustCompile(`address\s*=\s*"127\.0\.0\.1:(\d+)"`).FindSubmatch(cfg)
	if m == nil {
		os.Exit(9)
	}

	var (
		mu          sync.Mutex
		initialized bool
		exitOnce    sync.Once
	)
	done := make(chan struct{})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/sys/health":
			mu.Lock()
			ready := initialized
			mu.Unlock()
			if !ready {
				// 501 is how Vault reports "not initialized", which safe
				// reads as "listening but sealed" — enough to end the
				// startup wait.
				w.WriteHeader(http.StatusNotImplemented)
			}
			_, _ = w.Write([]byte(`{}`))

		case r.URL.Path == "/v1/sys/init" && r.Method == http.MethodPut:
			mu.Lock()
			initialized = true
			mu.Unlock()
			_, _ = w.Write([]byte(`{"keys":["local-seal-key"],"keys_base64":["local-seal-key"],"root_token":"local-root-token"}`))

		case r.URL.Path == "/v1/sys/unseal" && r.Method == http.MethodPut:
			_, _ = w.Write([]byte(`{"sealed":false}`))

		case r.URL.Path == "/v1/sys/mounts" && r.Method == http.MethodGet:
			if os.Getenv("SAFE_FAKE_VAULT_FAIL") == "mounts-list" {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"errors":["mount listing is down"]}`))
				scheduleExit(&exitOnce, done)
				return
			}
			_, _ = w.Write([]byte(`{"data":{}}`))

		case strings.HasPrefix(r.URL.Path, "/v1/sys/mounts/") && r.Method == http.MethodPost:
			if os.Getenv("SAFE_FAKE_VAULT_FAIL") == "mounts-create" {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"errors":["mount creation is down"]}`))
				scheduleExit(&exitOnce, done)
				return
			}
			w.WriteHeader(http.StatusNoContent)

		case strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts"):
			_, _ = w.Write([]byte(`{"data":{"secret":{"secret/":{"type":"kv","options":{"version":"1"}}}}}`))

		case r.URL.Path == "/v1/secret/handshake" &&
			(r.Method == http.MethodPut || r.Method == http.MethodPost):
			w.WriteHeader(http.StatusNoContent)
			// The handshake write is the last thing cmdLocal asks of the
			// Vault; shut down shortly after so the response gets out first.
			scheduleExit(&exitOnce, done)

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		}
	})

	ln, err := net.Listen("tcp", "127.0.0.1:"+string(m[1]))
	if err != nil {
		os.Exit(9)
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	<-done
	os.Exit(0)
}

// installFakeLocalVault installs a fake `vault` whose `server` subcommand
// re-executes the test binary as TestFakeLocalVaultHelper.
func installFakeLocalVault(t *testing.T) {
	t.Helper()
	t.Setenv("SAFE_FAKE_VAULT_TESTBIN", os.Args[0])
	installFakeBin(t, "vault", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "Vault v1.15.4"
  exit 0
fi
if [ "$1" = "server" ]; then
  SAFE_FAKE_VAULT_HELPER=1 SAFE_FAKE_VAULT_CONFIG="$3" \
    exec "$SAFE_FAKE_VAULT_TESTBIN" -test.run '^TestFakeLocalVaultHelper$' -test.count=1
fi
echo "unexpected invocation: vault $*" >&2
exit 42
`)
}

func TestCmdLocal_MemoryBackedLifecycle(t *testing.T) {
	// No t.Parallel — captureStderr mutates os.Stderr.
	isolateHome(t)
	installFakeLocalVault(t)
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.As = "local-mem-test"

	var err error
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			err = c.cmdLocal("local")
		})
	})
	if err != nil {
		t.Fatalf("cmdLocal returned unexpected error: %v\nstderr:\n%s", err, stderr)
	}

	if !strings.Contains(stdout, "safe has mounted") {
		t.Errorf("expected the mount notice on stdout, got:\n%s", stdout)
	}
	if !strings.Contains(stderr, "local-mem-test") {
		t.Errorf("expected the temporary target named, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "MEMORY-BACKED") {
		t.Errorf("expected the memory-backed warning, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "Vault terminated normally") {
		t.Errorf("expected the normal-termination notice, got:\n%s", stderr)
	}
	if got := os.Getenv("VAULT_TOKEN"); got != "local-root-token" {
		t.Errorf("VAULT_TOKEN: got %q, want the root token from init", got)
	}

	saferc, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".saferc"))
	if err != nil {
		t.Fatalf("reading .saferc: %v", err)
	}
	if strings.Contains(string(saferc), "local-mem-test") {
		t.Errorf("the temporary target was not cleaned out of .saferc:\n%s", saferc)
	}
}

func TestCmdLocal_FileBackedLifecycleWithRandomName(t *testing.T) {
	// No t.Parallel — captureStderr mutates os.Stderr.
	isolateHome(t)
	installFakeLocalVault(t)
	c := localCLI(t)
	c.opt.Local.File = filepath.Join(t.TempDir(), "local-vault.db")

	var err error
	var stderr string
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			err = c.cmdLocal("local")
		})
	})
	if err != nil {
		t.Fatalf("cmdLocal returned unexpected error: %v\nstderr:\n%s", err, stderr)
	}

	if !strings.Contains(stderr, "Storing data (encrypted) in") {
		t.Errorf("expected the storage-file notice, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "local-seal-key") {
		t.Errorf("expected the seal key echoed, got:\n%s", stderr)
	}

	saferc, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".saferc"))
	if err != nil {
		t.Fatalf("reading .saferc: %v", err)
	}
	if strings.Contains(string(saferc), "http://127.0.0.1:") {
		t.Errorf("the temporary target was not cleaned out of .saferc:\n%s", saferc)
	}
}

func TestCmdLocal_RestoresPreviousTargetOnExit(t *testing.T) {
	// No t.Parallel — captureStderr mutates os.Stderr.
	isolateHome(t)
	writeSaferc(t, `version: 1
current: alpha
vaults:
  alpha:
    url: http://127.0.0.1:1
    token: token-alpha
    no_strongbox: true
`)
	installFakeLocalVault(t)
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.As = "local-prev-test"

	var err error
	captureStdout(t, func() {
		captureStderr(t, func() {
			err = c.cmdLocal("local")
		})
	})
	if err != nil {
		t.Fatalf("cmdLocal returned unexpected error: %v", err)
	}

	saferc, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".saferc"))
	if err != nil {
		t.Fatalf("reading .saferc: %v", err)
	}
	if !strings.Contains(string(saferc), "current: alpha") {
		t.Errorf("the previous target was not restored as current:\n%s", saferc)
	}
	if strings.Contains(string(saferc), "local-prev-test") {
		t.Errorf("the temporary target was not cleaned out of .saferc:\n%s", saferc)
	}
}

func TestCmdLocal_UnreadableSafercErrors(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, "\t{{ this is not yaml")
	// The rc failure comes after the server is spawned, so the fake exits
	// immediately to leave nothing running.
	t.Setenv("SAFE_FAKE_VAULT_TESTBIN", os.Args[0])
	installFakeBin(t, "vault", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "Vault v1.15.4"
  exit 0
fi
exit 0
`)
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.Port = 8219

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error for an unreadable .saferc, got nil")
	}
}

func TestCmdLocal_MountListFailureSurfaces(t *testing.T) {
	// No t.Parallel — captureStderr mutates os.Stderr.
	isolateHome(t)
	installFakeLocalVault(t)
	t.Setenv("SAFE_FAKE_VAULT_FAIL", "mounts-list")
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.As = "local-lsfail-test"

	var err error
	captureStdout(t, func() {
		captureStderr(t, func() {
			err = c.cmdLocal("local")
		})
	})
	if err == nil {
		t.Fatal("expected the mount-listing failure to surface, got nil")
	}
	if !strings.Contains(err.Error(), "Could not list mounts") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdLocal_MountCreateFailureSurfaces(t *testing.T) {
	// No t.Parallel — captureStderr mutates os.Stderr.
	isolateHome(t)
	installFakeLocalVault(t)
	t.Setenv("SAFE_FAKE_VAULT_FAIL", "mounts-create")
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.As = "local-mkfail-test"

	var err error
	captureStdout(t, func() {
		captureStderr(t, func() {
			err = c.cmdLocal("local")
		})
	})
	if err == nil {
		t.Fatal("expected the mount-creation failure to surface, got nil")
	}
	if !strings.Contains(err.Error(), "Could not add") {
		t.Errorf("unexpected error wording: %v", err)
	}
}
