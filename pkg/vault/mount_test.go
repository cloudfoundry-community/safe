package vault_test

import (
	"slices"
	"testing"
)

// A Vault holds more than the one mount safe starts with, and the mount
// listing is what every command that reaches past a single tree is built on.
func TestListMountsNamesEveryMount(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mount("kv", "kv")
	fv.mount("legacy", "generic")

	mounts, err := v.ListMounts()
	if err != nil {
		t.Fatalf("ListMounts: %v", err)
	}

	for _, want := range []string{"secret", "kv", "legacy"} {
		if !slices.Contains(mounts, want) {
			t.Errorf("ListMounts left out %q: %v", want, mounts)
		}
	}
}

func TestMountExists(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mount("kv", "kv")

	cases := []struct {
		path string
		want bool
	}{
		{"secret", true},
		{"secret/", true},
		{"/secret/", true},
		{"kv", true},
		{"nowhere", false},
		//A mount is named by its own path, not by what lives under it.
		{"secret/handshake", false},
		{"", false},
	}
	for _, tc := range cases {
		got, err := v.MountExists(tc.path)
		if err != nil {
			t.Fatalf("MountExists(%q): %v", tc.path, err)
		}
		if got != tc.want {
			t.Errorf("MountExists(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// safe local mounts its own KV backend before it writes anything to it.
func TestAddMountMakesTheMountExist(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)

	if exists, err := v.MountExists("fresh"); err != nil || exists {
		t.Fatalf("MountExists(fresh) = %v, %v before it is added", exists, err)
	}
	if err := v.AddMount("fresh", 2); err != nil {
		t.Fatalf("AddMount: %v", err)
	}

	exists, err := v.MountExists("fresh")
	if err != nil {
		t.Fatalf("MountExists after AddMount: %v", err)
	}
	if !exists {
		t.Errorf("the mount AddMount made does not exist")
	}

	//The version asked for is the version the mount is made with: safe local
	// asks for 2, and a v1 mount would answer on other paths entirely.
	fv.mu.RLock()
	defer fv.mu.RUnlock()
	if got := fv.mounts["fresh"]; got.version != 2 || got.typ != "kv" {
		t.Errorf("mount made as %+v, want a version 2 kv mount", got)
	}
}

func TestAddMountOnAPathAlreadyTakenFails(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	if err := v.AddMount("secret", 2); err == nil {
		t.Errorf("AddMount over an existing mount gave no error")
	}
}

// Mounts answers by backend type, which is how the walk of a whole Vault
// finds the trees to walk: kv and generic are the two names the key-value
// backend has had.
func TestMountsSelectsByType(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mount("kv", "kv")
	fv.mount("legacy", "generic")
	fv.pki["ca"] = true

	cases := []struct {
		typ  string
		want []string
	}{
		{"kv", []string{"kv/", "secret/"}},
		{"generic", []string{"legacy/"}},
		{"pki", []string{"ca/"}},
		{"nosuchtype", []string{}},
	}
	for _, tc := range cases {
		got, err := v.Mounts(tc.typ)
		if err != nil {
			t.Fatalf("Mounts(%q): %v", tc.typ, err)
		}
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("Mounts(%q) = %v, want %v", tc.typ, got, tc.want)
		}
	}
}

func TestIsMounted(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mount("kv", "kv")

	cases := []struct {
		typ, path string
		want      bool
	}{
		{"kv", "secret", true},
		{"kv", "secret/", true},
		{"kv", "kv", true},
		{"kv", "nowhere", false},
		//The type has to match too, or safe would take any mount for a PKI
		// backend and issue certificates against it.
		{"pki", "secret", false},
	}
	for _, tc := range cases {
		got, err := v.IsMounted(tc.typ, tc.path)
		if err != nil {
			t.Fatalf("IsMounted(%q, %q): %v", tc.typ, tc.path, err)
		}
		if got != tc.want {
			t.Errorf("IsMounted(%q, %q) = %v, want %v", tc.typ, tc.path, got, tc.want)
		}
	}
}
