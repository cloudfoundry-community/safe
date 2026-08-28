package vault_test

import (
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// A recursive copy must fetch each secret once (via the walk) and write
// it once, never re-reading what the walk already returned, and never
// re-reading metadata per secret.
func TestCopyTreeWritesFromWalkedData(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/src/a", map[string]string{"k": "va"})
	fv.setV2("kv2/src/b", map[string]string{"k": "vb"})
	fv.setV2("kv2/src/sub/c", map[string]string{"k": "vc"})

	fv.resetRequestLog()
	err := v.MoveCopyTree("kv2/src", "kv2/dst", false, vault.MoveCopyOpts{})
	if err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}

	for path, want := range map[string]string{
		"kv2/dst/a": "va", "kv2/dst/b": "vb", "kv2/dst/sub/c": "vc",
	} {
		s, err := v.Read(path)
		if err != nil {
			t.Fatalf("Read %s: %v", path, err)
		}
		if got := s.Get("k"); got != want {
			t.Errorf("%s k = %q, want %q", path, got, want)
		}
	}

	if got := fv.requestCount(`^GET /v1/kv2/data/src`); got != 3 {
		t.Errorf("source data GETs = %d, want 3 (one per secret)", got)
	}
	if got := fv.requestCount(`^(PUT|POST) /v1/kv2/data/dst`); got != 3 {
		t.Errorf("destination writes = %d, want 3", got)
	}
	if got := fv.requestCount(`^GET /v1/kv2/metadata/src/[^?]+$`); got != 0 {
		t.Errorf("per-secret metadata GETs = %d, want 0", got)
	}
}

// A recursive move is the copy plus exactly one delete request per source
// secret, with no per-secret metadata reads.
func TestMoveTreeDeletesSourcesOnce(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/src/a", map[string]string{"k": "va"})
	fv.setV2("kv2/src/b", map[string]string{"k": "vb"})

	fv.resetRequestLog()
	err := v.MoveCopyTree("kv2/src", "kv2/dst", true, vault.MoveCopyOpts{})
	if err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}

	if _, err := v.Read("kv2/src/a"); err == nil {
		t.Error("kv2/src/a still readable after move")
	}
	if _, err := v.Read("kv2/dst/a"); err != nil {
		t.Errorf("kv2/dst/a not readable after move: %v", err)
	}
	if got := fv.requestCount(`^GET /v1/kv2/metadata/src/[^?]+$`); got != 0 {
		t.Errorf("per-secret metadata GETs = %d, want 0", got)
	}
	// Non-deep move: versionless delete, one request per source secret.
	if got := fv.requestCount(`^DELETE /v1/kv2/data/src/`); got != 2 {
		t.Errorf("source deletes = %d, want 2", got)
	}
}

// --no-clobber must still refuse when a destination path exists; the
// keyed walk changed what Paths() emits, so the comparison is on entry
// paths now, and this pins it.
func TestCopyTreeNoClobberStillRefuses(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/src/a", map[string]string{"k": "new"})
	fv.setV2("kv2/dst/a", map[string]string{"k": "old"})

	err := v.MoveCopyTree("kv2/src", "kv2/dst", false, vault.MoveCopyOpts{SkipIfExists: true, Quiet: true})
	if err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}
	s, err := v.Read("kv2/dst/a")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := s.Get("k"); got != "old" {
		t.Errorf("dst/a k = %q, want untouched %q", got, "old")
	}
}

// A secret at the walk root itself is copied exactly once (Declared
// Behavior Change 2: the old trailing root probe wrote it twice).
func TestCopyTreeRootSecretCopiedOnce(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/src", map[string]string{"root": "r"})
	fv.setV2("kv2/src/child", map[string]string{"k": "v"})

	err := v.MoveCopyTree("kv2/src", "kv2/dst", false, vault.MoveCopyOpts{})
	if err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}
	if got := fv.v2States("kv2/dst"); len(got) != 1 {
		t.Errorf("dst root has %d versions, want 1 (single write)", len(got))
	}
}

// Deep move with deleted versions: version states survive the move and
// sources are destroyed, pinning the previously-untested v2 deep branch.
func TestMoveTreeDeepPreservesVersionStates(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/src/a", map[string]string{"k": "v1"}, map[string]string{"k": "v2"})
	fv.deleteV2("kv2/src/a", 1)

	err := v.MoveCopyTree("kv2/src", "kv2/dst", true, vault.MoveCopyOpts{Deep: true, DeletedVersions: true})
	if err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}
	if got := fv.v2States("kv2/dst/a"); len(got) != 2 || got[0] != "deleted" || got[1] != "alive" {
		t.Errorf("dst/a states = %v, want [deleted alive]", got)
	}
	if got := fv.v2States("kv2/src/a"); len(got) != 0 && got[len(got)-1] != "destroyed" {
		t.Errorf("src/a not destroyed after deep move: %v", got)
	}
}

// A recursive move (or copy) must refuse the whole operation, not partially
// complete it, when part of the source tree could not be read: the walk
// skips what it cannot read rather than aborting, so treating it as a
// complete inventory would let an entry nothing was actually read from
// reach the source delete/destroy. Neither the readable sibling nor the
// forbidden secret itself may be touched.
func TestMoveCopyTreeRefusesOnForbiddenSource(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/src/a", map[string]string{"k": "va"})
	fv.setV2("kv2/src/b", map[string]string{"k": "vb"})
	fv.forbid("kv2/src/b")

	if err := v.MoveCopyTree("kv2/src", "kv2/dst", true, vault.MoveCopyOpts{Quiet: true}); err == nil {
		t.Fatal("MoveCopyTree(move): expected refusal for an inaccessible source secret, got nil")
	}
	if got := fv.v2States("kv2/src/b"); len(got) != 1 || got[0] != "alive" {
		t.Errorf("forbidden source kv2/src/b was modified: states=%v", got)
	}
	if _, err := v.Read("kv2/dst/a"); err == nil {
		t.Error("kv2/dst/a was written despite the walk refusal")
	}

	if err := v.MoveCopyTree("kv2/src", "kv2/dst2", false, vault.MoveCopyOpts{Quiet: true}); err == nil {
		t.Fatal("MoveCopyTree(copy): expected refusal for an inaccessible source secret, got nil")
	}
	if _, err := v.Read("kv2/dst2/a"); err == nil {
		t.Error("kv2/dst2/a was written despite the walk refusal")
	}
}

// Tree copies run their per-secret writes concurrently.
func TestCopyTreeRunsWritesConcurrently(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	for _, name := range []string{"a", "b", "c", "d"} {
		fv.setV2("kv2/src/"+name, map[string]string{"k": name})
	}
	release := fv.holdRequests(2, `^(PUT|POST) /v1/kv2/data/dst/`)

	done := make(chan error, 1)
	go func() {
		done <- v.MoveCopyTree("kv2/src", "kv2/dst", false, vault.MoveCopyOpts{})
	}()

	select {
	case <-release: // two writes were concurrently in flight
	case err := <-done:
		t.Fatalf("MoveCopyTree finished without write overlap: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no overlap within 5s: writes are serialized")
	}
	if err := <-done; err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}
}

// MoveCopyTree must reject DeletedVersions without Deep the same way
// v.Copy does; the rewrite must not silently downgrade to a shallow copy
// plus a versionless delete.
func TestMoveCopyTreeDeletedVersionsRequiresDeep(t *testing.T) {
	v, fv := newTestVault(t)
	fv.set("secret/src", map[string]string{"k": "v"})

	err := v.MoveCopyTree("secret/src", "secret/dst", false, vault.MoveCopyOpts{
		DeletedVersions: true,
		Deep:            false,
		Quiet:           true,
	})
	if err == nil {
		t.Fatal("expected error for DeletedVersions without Deep, got nil")
	}
	if !strings.Contains(err.Error(), "Deep") {
		t.Errorf("unexpected error message: %v", err)
	}
}
