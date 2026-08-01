package vault_test

import (
	"sync/atomic"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// A walk that hits 403s below a readable root must skip those subtrees,
// return every reachable sibling, and report how many nodes it skipped.
func TestConstructSecrets_CountsForbiddenSkips(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)

	fv.set("secret/ok", map[string]string{"k": "v"})
	fv.set("secret/hidden/deep", map[string]string{"k": "v"})
	fv.set("secret/unreadable", map[string]string{"k": "v"})
	fv.forbid("secret/hidden")     // list of the subtree 403s
	fv.forbid("secret/unreadable") // get of the leaf 403s

	var skipped atomic.Uint64
	s, err := v.ConstructSecrets("secret", vault.TreeOpts{
		FetchKeys:        true,
		SkippedForbidden: &skipped,
	})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	got := map[string]bool{}
	for _, entry := range s {
		got[entry.Path] = true
		// The get-403 leaf stays listed by its parent, but its keys must
		// never be fetched.
		if entry.Path == "secret/unreadable" {
			for _, ver := range entry.Versions {
				if len(ver.Data.Keys()) != 0 {
					t.Errorf("forbidden secret %s has key data: %v", entry.Path, ver.Data.Keys())
				}
			}
		}
	}
	if !got["secret/ok"] {
		t.Errorf("walk missing readable sibling secret/ok (got %v)", s.Paths())
	}
	if got["secret/hidden/deep"] {
		t.Errorf("walk descended into forbidden subtree (got %v)", s.Paths())
	}
	if n := skipped.Load(); n != 2 {
		t.Errorf("skipped = %d, want 2 (one list 403, one get 403)", n)
	}
}

// A KV v2 mount must skip and count a forbidden data read exactly like a v1
// mount does: `safe values` promises that denied subtrees are skipped and
// counted, regardless of the KV engine version behind them. A policy that
// grants list/metadata but denies the data read on one leaf is a normal
// per-team layout, and it must not abort the walk of the whole subtree.
func TestConstructSecrets_CountsForbiddenSkipsOnKVv2(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv")

	fv.setV2("kv/ok", map[string]string{"k": "v"})
	fv.setV2("kv/unreadable", map[string]string{"k": "v"})
	fv.forbid("kv/unreadable") // data get 403s; list/metadata stay permitted

	var skipped atomic.Uint64
	s, err := v.ConstructSecrets("kv", vault.TreeOpts{
		FetchKeys:        true,
		SkippedForbidden: &skipped,
	})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	got := map[string]bool{}
	for _, entry := range s {
		got[entry.Path] = true
		if entry.Path == "kv/unreadable" {
			for _, ver := range entry.Versions {
				if len(ver.Data.Keys()) != 0 {
					t.Errorf("forbidden secret %s has key data: %v", entry.Path, ver.Data.Keys())
				}
			}
		}
	}
	if !got["kv/ok"] {
		t.Errorf("walk missing readable sibling kv/ok (got %v)", s.Paths())
	}
	if n := skipped.Load(); n != 1 {
		t.Errorf("skipped = %d, want 1 (the forbidden data read)", n)
	}
}

// Without a counter wired in, forbidden subtrees are still skipped silently
// and the nil SkippedForbidden must not be touched.
func TestConstructSecrets_NilSkipCounterUnused(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)

	fv.set("secret/ok", map[string]string{"k": "v"})
	fv.set("secret/hidden/deep", map[string]string{"k": "v"})
	fv.forbid("secret/hidden")

	s, err := v.ConstructSecrets("secret", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}
	found := false
	for _, entry := range s {
		if entry.Path == "secret/ok" {
			found = true
		}
	}
	if !found {
		t.Errorf("walk missing readable sibling secret/ok (got %v)", s.Paths())
	}
}
