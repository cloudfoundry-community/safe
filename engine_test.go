package main

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

func setupPATH(t *testing.T, binaries []string) {
	t.Helper()
	dir := t.TempDir()
	for _, b := range binaries {
		writeFakeBinary(t, dir, b)
	}
	t.Setenv("PATH", dir)
}

func TestSelectLocalEngine_AutoDetect(t *testing.T) {
	tests := []struct {
		name     string
		install  []string
		wantName string
		wantErr  bool
		errMatch []string
	}{
		{name: "bao only", install: []string{"bao"}, wantName: "bao"},
		{name: "vault only", install: []string{"vault"}, wantName: "vault"},
		{name: "both prefers bao", install: []string{"bao", "vault"}, wantName: "bao"},
		{name: "neither", install: nil, wantErr: true, errMatch: []string{"bao", "vault"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setupPATH(t, tc.install)

			eng, err := selectLocalEngine("")

			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got engine %q", eng.Name())
				}
				for _, s := range tc.errMatch {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("error %q missing %q", err, s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eng.Name() != tc.wantName {
				t.Errorf("got engine %q, want %q", eng.Name(), tc.wantName)
			}
		})
	}
}

func TestSelectLocalEngine_Preference(t *testing.T) {
	tests := []struct {
		name       string
		install    []string
		preference string
		wantName   string
		wantErr    bool
	}{
		{name: "prefer bao with both", install: []string{"bao", "vault"}, preference: "bao", wantName: "bao"},
		{name: "prefer vault with both", install: []string{"bao", "vault"}, preference: "vault", wantName: "vault"},
		{name: "prefer bao but only vault", install: []string{"vault"}, preference: "bao", wantErr: true},
		{name: "prefer vault but only bao", install: []string{"bao"}, preference: "vault", wantErr: true},
		{name: "invalid preference", install: []string{"bao"}, preference: "etcd", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setupPATH(t, tc.install)

			eng, err := selectLocalEngine(tc.preference)

			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got engine %q", eng.Name())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if eng.Name() != tc.wantName {
				t.Errorf("got engine %q, want %q", eng.Name(), tc.wantName)
			}
		})
	}
}
