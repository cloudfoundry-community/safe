package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFakeBinary(t *testing.T, dir, name string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
}

// installEngines puts fake bao/vault binaries on a PATH containing nothing
// else, so lookup order is decided by selectEngine rather than by whatever the
// developer happens to have installed. It returns the directory holding them.
func installEngines(t *testing.T, binaries ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, b := range binaries {
		writeFakeBinary(t, dir, b)
	}
	t.Setenv("PATH", dir)
	return dir
}

func TestSelectEngineAutoDetect(t *testing.T) {
	tests := []struct {
		name     string
		install  []string
		want     string
		wantErr  bool
		errWants []string
	}{
		{name: "vault only", install: []string{"vault"}, want: "vault"},
		{name: "bao only", install: []string{"bao"}, want: "bao"},
		{name: "both prefers vault", install: []string{"bao", "vault"}, want: "vault"},
		{
			name:     "neither names both candidates",
			install:  nil,
			wantErr:  true,
			errWants: []string{"vault", "bao"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			installEngines(t, tc.install...)
			t.Setenv("SAFE_ENGINE", "")

			eng, err := selectEngine("")

			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got engine %q", eng.Name())
				}
				for _, s := range tc.errWants {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("error %q does not mention %q", err, s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eng.Name() != tc.want {
				t.Errorf("got engine %q, want %q", eng.Name(), tc.want)
			}
		})
	}
}

func TestSelectEnginePreference(t *testing.T) {
	tests := []struct {
		name       string
		install    []string
		preference string
		want       string
		wantErr    bool
		errWants   []string
	}{
		{name: "pin bao with both", install: []string{"bao", "vault"}, preference: "bao", want: "bao"},
		{name: "pin vault with both", install: []string{"bao", "vault"}, preference: "vault", want: "vault"},
		{
			name:       "pinned engine missing does not fall back",
			install:    []string{"vault"},
			preference: "bao",
			wantErr:    true,
			errWants:   []string{"bao"},
		},
		{
			name:       "pin is case-insensitive",
			install:    []string{"bao", "vault"},
			preference: "Vault",
			want:       "vault",
		},
		{
			name:       "unknown engine names the supported set",
			install:    []string{"bao", "vault"},
			preference: "etcd",
			wantErr:    true,
			errWants:   []string{"etcd", "vault", "bao", "--engine"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			installEngines(t, tc.install...)
			t.Setenv("SAFE_ENGINE", "")

			eng, err := selectEngine(tc.preference)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got engine %q", eng.Name())
				}
				for _, s := range tc.errWants {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("error %q does not mention %q", err, s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eng.Name() != tc.want {
				t.Errorf("got engine %q, want %q", eng.Name(), tc.want)
			}
		})
	}
}

// SAFE_ENGINE moves the default off vault without having to pass --engine on
// every invocation. The flag still wins, so a scripted --engine cannot be
// silently redirected by an exported preference.
func TestSelectEngineEnvPreference(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		flag    string
		want    string
		wantErr bool
	}{
		{name: "env selects bao", env: "bao", want: "bao"},
		{name: "env selects vault", env: "vault", want: "vault"},
		{name: "env is case-insensitive", env: "BAO", want: "bao"},
		{name: "flag overrides env", env: "bao", flag: "vault", want: "vault"},
		{name: "blank env falls through to auto-detect", env: "", want: "vault"},
		{name: "whitespace env is ignored", env: "   ", want: "vault"},
		{name: "invalid env is an error", env: "consul", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			installEngines(t, "bao", "vault")
			t.Setenv("SAFE_ENGINE", tc.env)

			eng, err := selectEngine(tc.flag)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got engine %q", eng.Name())
				}
				if !strings.Contains(err.Error(), "SAFE_ENGINE") {
					t.Errorf("error %q should name the SAFE_ENGINE source", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eng.Name() != tc.want {
				t.Errorf("got engine %q, want %q", eng.Name(), tc.want)
			}
		})
	}
}

// Every engine safe can resolve carries a proper name for user-facing prose,
// so no message can end up reading "shutting down the bao".
func TestSelectEngineTitle(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"vault", "Vault"},
		{"bao", "OpenBao"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installEngines(t, tc.name)
			t.Setenv("SAFE_ENGINE", "")

			eng, err := selectEngine("")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eng.Title() != tc.want {
				t.Errorf("Title() = %q, want %q", eng.Title(), tc.want)
			}
		})
	}
}

// The resolved binary is the exact file the lookup verified, not the bare
// name, so the server safe starts is the one it confirmed was present.
func TestSelectEngineResolvesBinaryPath(t *testing.T) {
	dir := installEngines(t, "bao")
	t.Setenv("SAFE_ENGINE", "")

	eng, err := selectEngine("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := filepath.Join(dir, "bao"); eng.Binary() != want {
		t.Errorf("Binary() = %q, want %q", eng.Binary(), want)
	}
}

// Auto-detection iterates engineNames and looks each name up in turn, so a
// bao that sits in an earlier $PATH directory than vault must still lose to
// vault. A first-hit-along-$PATH walk would pass every single-directory test
// while silently inverting the documented default.
func TestSelectEngineOrderBeatsPathOrder(t *testing.T) {
	baoDir := t.TempDir()
	vaultDir := t.TempDir()
	writeFakeBinary(t, baoDir, "bao")
	writeFakeBinary(t, vaultDir, "vault")
	t.Setenv("PATH", baoDir+string(os.PathListSeparator)+vaultDir)
	t.Setenv("SAFE_ENGINE", "")

	eng, err := selectEngine("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng.Name() != "vault" {
		t.Errorf("got engine %q, want vault despite bao earlier on $PATH", eng.Name())
	}
	if want := filepath.Join(vaultDir, "vault"); eng.Binary() != want {
		t.Errorf("Binary() = %q, want %q", eng.Binary(), want)
	}
}
