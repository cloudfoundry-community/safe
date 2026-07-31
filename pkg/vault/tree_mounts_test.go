package vault_test

import (
	"slices"
	"sync/atomic"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// safe tree /, safe paths /, and safe export / all start from the root of the
// Vault, where there is no path to list -- only mounts to find and walk in
// turn.
func TestConstructSecretsAtRootReachesEveryMount(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mount("kv", "kv")
	fv.mount("legacy", "generic")

	fv.set("secret/handshake", map[string]string{"k": "v"})
	fv.set("kv/deploy/creds", map[string]string{"k": "v"})
	fv.set("legacy/old", map[string]string{"k": "v"})

	s, err := v.ConstructSecrets("/", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	got := paths(s)
	slices.Sort(got)
	want := []string{"kv/deploy/creds", "legacy/old", "secret/handshake"}
	if !slices.Equal(got, want) {
		t.Errorf("walking the root gave %v, want %v", got, want)
	}
}

// A mount with a secret at its own root is both a secret and a folder, and
// the walk has to report it as both rather than picking one.
func TestConstructSecretsAtRootFindsASecretOnAMountRoot(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mount("kv", "kv")

	fv.set("kv", map[string]string{"k": "v"})
	fv.set("kv/below", map[string]string{"k": "v"})

	s, err := v.ConstructSecrets("/", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	got := paths(s)
	slices.Sort(got)
	want := []string{"kv", "kv/below"}
	if !slices.Equal(got, want) {
		t.Errorf("walking the root gave %v, want %v", got, want)
	}
}

// An empty mount contributes nothing, and must not stop the walk of the ones
// that hold something.
func TestConstructSecretsAtRootSkipsAnEmptyMount(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mount("empty", "kv")

	fv.set("secret/handshake", map[string]string{"k": "v"})

	s, err := v.ConstructSecrets("/", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	got := paths(s)
	if !slices.Equal(got, []string{"secret/handshake"}) {
		t.Errorf("walking the root gave %v, want just secret/handshake", got)
	}
}

// A mount whose whole tree the token cannot list is skipped and counted, and
// the mounts it can read still come back.
func TestConstructSecretsAtRootCountsAForbiddenMount(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mount("locked", "kv")

	fv.set("secret/handshake", map[string]string{"k": "v"})
	fv.set("locked/away", map[string]string{"k": "v"})
	fv.forbid("locked")

	var skipped atomic.Uint64
	s, err := v.ConstructSecrets("/", vault.TreeOpts{
		FetchKeys:        true,
		SkippedForbidden: &skipped,
	})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	got := paths(s)
	if !slices.Equal(got, []string{"secret/handshake"}) {
		t.Errorf("walking the root gave %v, want just secret/handshake", got)
	}
	if n := skipped.Load(); n != 1 {
		t.Errorf("skipped = %d, want 1 (the mount the token cannot read)", n)
	}
}

// paths is the path of every secret the walk returned, without the keys that
// Paths() names alongside them.
func paths(s vault.Secrets) []string {
	out := make([]string, 0, len(s))
	for _, entry := range s {
		out = append(out, entry.Path)
	}
	return out
}
