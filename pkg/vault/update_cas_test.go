package vault_test

// Update is the check-and-set read-modify-write every RMW command routes
// through: read the live version, apply the caller's fn to the fresh
// state, write back naming that version, and on a conflict re-read and
// re-apply, so a concurrent writer's keys survive instead of being
// silently overwritten. The not-found branch is the subtle part, pinned
// here the way a live Vault behaves: a soft-deleted or destroyed-latest
// path answers the data read with 404 while its metadata keeps the
// current version, and Vault rejects cas=0 whenever any metadata
// survives -- so the write must check-and-set against the metadata's
// version, not assume "create only".

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
	"github.com/cloudfoundry-community/vaultkv"
)

const (
	updDataGet  = `^GET /v1/kv2/data/x(\?.*)?$`
	updDataPut  = `^(PUT|POST) /v1/kv2/data/x$`
	updMetaGet  = `^GET /v1/kv2/metadata/x$`
	updDataPath = "kv2/x"
)

// latestV2Data returns the newest alive version's data at path, for
// assertions on what a converged Update left behind.
func latestV2Data(t *testing.T, fv *fakeVault, path string) map[string]string {
	t.Helper()
	fv.mu.RLock()
	defer fv.mu.RUnlock()
	h := fv.v2data[path]
	if h == nil || len(h.versions) == 0 {
		t.Fatalf("no versions at %s", path)
	}
	v := h.versions[len(h.versions)-1]
	cp := map[string]string{}
	for k, val := range v.data {
		cp[k] = val
	}
	return cp
}

// A concurrent write landing between Update's read and its write conflicts
// the check-and-set; the retry re-reads and re-applies, so the final
// secret carries both the concurrent writer's key and the generated one.
// The whole exchange costs exactly 2 data reads and 2 writes.
func TestUpdateInterleavedWriteConverges(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"other": "x"})

	fv.afterRequest(updDataGet, 1, func() {
		fv.setV2(updDataPath, map[string]string{"other": "x", "theirs": "y"})
	})

	version, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if !exists {
			t.Error("exists = false on a path that has data")
		}
		if err := s.Set("gen", "ours", false); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if version != 3 {
		t.Errorf("Update returned version %d, want 3 (initial, concurrent, ours)", version)
	}

	got := latestV2Data(t, fv, updDataPath)
	for k, want := range map[string]string{"other": "x", "theirs": "y", "gen": "ours"} {
		if got[k] != want {
			t.Errorf("final secret[%s] = %q, want %q (full: %v)", k, got[k], want, got)
		}
	}
	if gets := fv.requestCount(updDataGet); gets != 2 {
		t.Errorf("data reads = %d, want exactly 2", gets)
	}
	if puts := fv.requestCount(updDataPut); puts != 2 {
		t.Errorf("data writes = %d, want exactly 2 (one refused, one landed)", puts)
	}
	if metas := fv.requestCount(updMetaGet); metas != 0 {
		t.Errorf("metadata reads = %d, want 0 on the found path", metas)
	}
}

// Two processes creating the same secret: ours reads nothing, resolves
// cas=0 from the absent metadata, and the concurrent create lands first.
// The cas=0 write conflicts, and the retry builds on the winner's value.
func TestUpdateCreateRaceConverges(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")

	var observed []bool
	fv.afterRequest(updMetaGet, 1, func() {
		fv.setV2(updDataPath, map[string]string{"theirs": "y"})
	})

	_, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		observed = append(observed, exists)
		if err := s.Set("gen", "ours", false); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	got := latestV2Data(t, fv, updDataPath)
	if got["theirs"] != "y" || got["gen"] != "ours" {
		t.Errorf("final secret = %v, want the concurrent key and the generated key", got)
	}
	if len(observed) != 2 || observed[0] || !observed[1] {
		t.Errorf("fn observed exists=%v, want [false true]", observed)
	}
}

// A version that appears between the 404 and the metadata consultation is
// alive, so the 404 is stale rather than a deletion: Update must re-read
// and build on the live value, not write over it from an empty seed.
func TestUpdateStale404RereadsInsteadOfClobbering(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")

	fv.afterRequest(updDataGet, 1, func() {
		fv.setV2(updDataPath, map[string]string{"theirs": "y"})
	})

	_, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if err := s.Set("gen", "ours", false); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	got := latestV2Data(t, fv, updDataPath)
	if got["theirs"] != "y" || got["gen"] != "ours" {
		t.Errorf("final secret = %v, want the concurrent key preserved alongside the generated key", got)
	}
}

// A soft-deleted path answers its data read with 404 while the metadata
// keeps current_version, and Vault rejects cas=0 there -- the write must
// check-and-set against the metadata's version and create the next one.
func TestUpdateWritesToSoftDeletedPath(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"old": "gone"})
	fv.deleteV2(updDataPath, 1)

	version, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if exists {
			t.Error("exists = true on a soft-deleted path")
		}
		if err := s.Set("new", "value", false); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	})
	if err != nil {
		t.Fatalf("Update on a soft-deleted path: %v", err)
	}
	if version != 2 {
		t.Errorf("Update returned version %d, want 2", version)
	}
	if states := fv.v2States(updDataPath); len(states) != 2 || states[0] != "deleted" || states[1] != "alive" {
		t.Errorf("version states = %v, want [deleted alive]", states)
	}
	//The metadata consultation is the one extra request this branch pays.
	if gets := fv.requestCount(updDataGet); gets != 1 {
		t.Errorf("data reads = %d, want 1", gets)
	}
	if metas := fv.requestCount(updMetaGet); metas != 1 {
		t.Errorf("metadata reads = %d, want exactly 1", metas)
	}
	if puts := fv.requestCount(updDataPut); puts != 1 {
		t.Errorf("data writes = %d, want 1", puts)
	}
}

// Same for a destroyed latest version: the data 404 hides a surviving
// current_version that the write must name.
func TestUpdateWritesToDestroyedLatestPath(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"a": "1"}, map[string]string{"b": "2"})
	fv.destroyV2(updDataPath, 2)

	version, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if err := s.Set("new", "value", false); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	})
	if err != nil {
		t.Fatalf("Update on a destroyed-latest path: %v", err)
	}
	if version != 3 {
		t.Errorf("Update returned version %d, want 3", version)
	}
	if got := latestV2Data(t, fv, updDataPath); got["new"] != "value" {
		t.Errorf("final secret = %v, want the new value", got)
	}
}

// A missing path is an answer, not an error: fn hears exists == false and
// can decline the write, which costs nothing further.
func TestUpdateMissingPathReportsNotExists(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")

	called := 0
	version, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		called++
		if exists {
			t.Error("exists = true on a missing path")
		}
		return nil, false, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if version != 0 || called != 1 {
		t.Errorf("version = %d, fn calls = %d; want 0 and 1", version, called)
	}
	if puts := fv.requestCount(updDataPut); puts != 0 {
		t.Errorf("data writes = %d, want 0 when fn declines", puts)
	}
}

// Sustained conflict gives up after five attempts, and the error says
// which path kept moving.
func TestUpdateExhaustionNamesThePath(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"n": "0"})

	//Every read is immediately followed by a concurrent bump, so every
	// check-and-set write names a version that is already stale.
	fv.afterRequest(updDataGet, 0, func() {
		fv.setV2(updDataPath, map[string]string{"n": "bumped"})
	})

	_, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if err := s.Set("gen", "ours", false); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	})
	if err == nil {
		t.Fatal("Update under sustained conflict = nil, want an error")
	}
	if !strings.Contains(err.Error(), updDataPath) {
		t.Errorf("error = %q, want it to name %s", err, updDataPath)
	}
	if !vaultkv.IsCASConflict(err) {
		t.Errorf("error = %q, want the conflict to stay recognizable through the wrap", err)
	}
	if gets := fv.requestCount(updDataGet); gets != 5 {
		t.Errorf("data reads = %d, want 5 (one per attempt)", gets)
	}
	if puts := fv.requestCount(updDataPut); puts != 5 {
		t.Errorf("data writes = %d, want 5 refused attempts", puts)
	}
}

// fn may hand back a replacement secret instead of mutating the one it
// was given -- the CA path re-serializes through X509.Secret, which
// builds a new one.
func TestUpdateReplacementSecretPersists(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"old": "x"})

	_, err := v.Update(updDataPath, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		out := vault.NewSecret()
		if err := out.Set("rebuilt", "yes", false); err != nil {
			return nil, false, err
		}
		return out, true, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := latestV2Data(t, fv, updDataPath)
	if got["rebuilt"] != "yes" || got["old"] != "" {
		t.Errorf("final secret = %v, want only the replacement's keys", got)
	}
}

// On a KV v1 mount there is no versioning and no check-and-set: Update
// degrades to a plain read-then-write, one GET and one POST, and the
// stored value is exactly the data -- no options envelope rides along.
func TestUpdateV1MountPlainWrite(t *testing.T) {
	v, fv := newTestVault(t)
	fv.set("secret/x", map[string]string{"other": "x"})

	version, err := v.Update("secret/x", func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if !exists {
			t.Error("exists = false on a v1 path that has data")
		}
		if err := s.Set("gen", "ours", false); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	})
	if err != nil {
		t.Fatalf("Update on v1: %v", err)
	}
	if version != 1 {
		t.Errorf("Update returned version %d, want 1 (v1 mounts report version 1)", version)
	}

	got := mustGetSecret(t, fv, "secret/x")
	if len(got) != 2 || got["other"] != "x" || got["gen"] != "ours" {
		t.Errorf("stored secret = %v, want exactly the two data keys", got)
	}
	if gets := fv.requestCount(`^GET /v1/secret/x(\?.*)?$`); gets != 1 {
		t.Errorf("reads = %d, want 1", gets)
	}
	if puts := fv.requestCount(`^(PUT|POST) /v1/secret/x$`); puts != 1 {
		t.Errorf("writes = %d, want 1", puts)
	}
}

// Update writes whole secrets; the path:key and path^version notations
// name less than one, and are refused the way Write refuses them.
func TestUpdateRefusesKeyAndVersionNotation(t *testing.T) {
	v, _ := newTestVault(t)

	for _, path := range []string{"secret/x:key", "secret/x^2"} {
		_, err := v.Update(path, func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
			return nil, true, nil
		})
		if err == nil {
			t.Errorf("Update(%q) = nil, want a refusal", path)
		}
	}
}
