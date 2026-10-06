package cli

// Tests for cmdLocal's validation paths (server.go): everything that fails
// before a Vault server process is spawned. Where a `vault` binary is needed
// for version probing, a fake that only answers `vault version` is placed on
// PATH (installFakeBin lives in server_vault_cmd_test.go).

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// installFakeVaultVersionOnly installs a fake `vault` that answers `vault
// version` with the given string and rejects any other invocation, so a test
// that must not reach `vault server` fails loudly if it does.
func installFakeVaultVersionOnly(t *testing.T, version string) {
	t.Helper()
	installFakeBin(t, "vault", `#!/bin/sh
if [ "$1" = "version" ]; then
  echo "`+version+`"
  exit 0
fi
echo "unexpected invocation: vault $*" >&2
exit 42
`)
}

func localCLI(t *testing.T) *CLI {
	t.Helper()
	return &CLI{opt: &Options{}, r: NewRunner()}
}

func TestCmdLocal_NeitherMemoryNorFileErrors(t *testing.T) {
	isolateHome(t)
	c := localCLI(t)

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error when none of --memory, --file, or --raft is given, got nil")
	}
	for _, flag := range []string{"--memory", "--file", "--raft"} {
		if !strings.Contains(err.Error(), flag) {
			t.Errorf("error should name %s, got: %v", flag, err)
		}
	}
}

func TestCmdLocal_BothMemoryAndFileErrors(t *testing.T) {
	isolateHome(t)
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.File = filepath.Join(t.TempDir(), "vault.db")

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error when both --memory and --file are given, got nil")
	}
	if !strings.Contains(err.Error(), "only one") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdLocal_MutuallyExclusiveStorageFlags(t *testing.T) {
	cases := []struct {
		name       string
		memory     bool
		file, raft string
	}{
		{"memory and raft", true, "", "/x/raft"},
		{"file and raft", false, "/x/file", "/x/raft"},
		{"all three", true, "/x/file", "/x/raft"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			// No engine on PATH: validation must refuse before one is
			// looked for, let alone started.
			t.Setenv("PATH", t.TempDir())
			c := localCLI(t)
			c.opt.Local.Memory = tc.memory
			c.opt.Local.File = tc.file
			c.opt.Local.Raft = tc.raft

			err := c.cmdLocal("local")
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !strings.Contains(err.Error(), "only one") {
				t.Errorf("unexpected error wording: %v", err)
			}
			for _, flag := range []string{"--memory", "--file", "--raft"} {
				if !strings.Contains(err.Error(), flag) {
					t.Errorf("error should name %s, got: %v", flag, err)
				}
			}
		})
	}
}

// The cluster port only means something to raft; the other backends run no
// cluster listener, so accepting it there would silently do nothing.
func TestCmdLocal_ClusterPortRequiresRaft(t *testing.T) {
	cases := []struct {
		name   string
		memory bool
		file   string
	}{
		{"memory", true, ""},
		{"file", false, "/x/file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			// No engine on PATH: validation must refuse before one is
			// looked for, let alone started.
			t.Setenv("PATH", t.TempDir())
			c := localCLI(t)
			c.opt.Local.Memory = tc.memory
			c.opt.Local.File = tc.file
			c.opt.Local.ClusterPort = 9500

			err := c.cmdLocal("local")
			if err == nil {
				t.Fatal("expected an error for --cluster-port without --raft, got nil")
			}
			for _, want := range []string{"--cluster-port", "--raft"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error should name %s, got: %v", want, err)
				}
			}
		})
	}
}

func TestCmdLocal_ClusterPortMustDifferFromPort(t *testing.T) {
	isolateHome(t)
	t.Setenv("PATH", t.TempDir())
	c := localCLI(t)
	dir := filepath.Join(t.TempDir(), "raft")
	c.opt.Local.Raft = dir
	c.opt.Local.Port = 8219
	c.opt.Local.ClusterPort = 8219

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error for a cluster port equal to the API port, got nil")
	}
	if !strings.Contains(err.Error(), "--cluster-port") || !strings.Contains(err.Error(), "8219") {
		t.Errorf("unexpected error wording: %v", err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Errorf("the raft directory was created before validation failed")
	}
}

func TestCmdLocal_MissingVaultBinaryErrors(t *testing.T) {
	isolateHome(t)
	// PATH holds only an empty directory, so there is no vault to run.
	t.Setenv("PATH", t.TempDir())
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.Port = 8219

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error when vault is not installed, got nil")
	}
	if !strings.Contains(err.Error(), "neither vault nor bao") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdLocal_MalformedConfigPairErrors(t *testing.T) {
	isolateHome(t)
	installFakeVaultVersionOnly(t, "Vault v1.15.4")
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.Port = 8219
	c.opt.Local.Config = []string{"not-a-pair"}

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error for a malformed --config pair, got nil")
	}
	if !strings.Contains(err.Error(), "expected key=value") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

// A --listener override that turns TLS on cannot be auto-targeted: the probe
// and client cmdLocal builds for its own server speak plain HTTP only, so
// guessing a scheme or trusting a self-signed cert is not on the table. This
// must be refused before a server is even spawned.
func TestCmdLocal_ListenerOverrideEnablingTLSIsRefused(t *testing.T) {
	isolateHome(t)
	installFakeVaultVersionOnly(t, "Vault v1.15.4")
	c := localCLI(t)
	c.opt.Local.Memory = true
	c.opt.Local.Port = 8219
	c.opt.Local.Listener = []string{"tls_disable=0"}

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error for a --listener override that enables TLS, got nil")
	}
	if !strings.Contains(err.Error(), "TLS") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestCmdLocal_MalformedListenerPairErrorsWithOldVault(t *testing.T) {
	isolateHome(t)
	// A pre-0.8 Vault takes the legacy "backend" storage-key branch before
	// the listener pair is rejected.
	installFakeVaultVersionOnly(t, "Vault v0.7.3")
	c := localCLI(t)
	c.opt.Local.File = filepath.Join(t.TempDir(), "does-not-exist.db")
	c.opt.Local.Port = 8219
	c.opt.Local.Listener = []string{"=no-key"}

	err := c.cmdLocal("local")
	if err == nil {
		t.Fatal("expected an error for a malformed --listener pair, got nil")
	}
	if !strings.Contains(err.Error(), "empty key") {
		t.Errorf("unexpected error wording: %v", err)
	}
}

func TestWaitLocalActive(t *testing.T) {
	t.Run("waits through standby and not-yet-active until health is 200", func(t *testing.T) {
		var hits atomic.Int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/health" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			if hits.Add(1) < 3 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		if err := waitLocalActive(ts.URL, 5*time.Second, time.Millisecond); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := hits.Load(); got != 3 {
			t.Errorf("health polled %d times, want 3", got)
		}
	})

	t.Run("gives up when the node never becomes active", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer ts.Close()

		if err := waitLocalActive(ts.URL, 50*time.Millisecond, time.Millisecond); err == nil {
			t.Fatal("expected a timeout error, got nil")
		}
	})
}
