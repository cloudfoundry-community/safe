package vault_test

import (
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
	"github.com/cloudfoundry-community/vaultkv"
)

// Two Versions lookups on the same path within one process cost one
// metadata request, and the caller gets an independent slice each time.
func TestVersionsIsCachedPerPath(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/a", map[string]string{"k": "v"})

	fv.resetRequestLog()
	first, err := v.Versions("kv2/a")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	second, err := v.Versions("kv2/a")
	if err != nil {
		t.Fatalf("Versions (second): %v", err)
	}
	if got := fv.requestCount(`^GET /v1/kv2/metadata/a$`); got != 1 {
		t.Errorf("metadata GETs = %d, want 1", got)
	}
	if len(first) > 0 && len(second) > 0 && &first[0] == &second[0] {
		t.Error("cached slice returned by reference; callers can corrupt it")
	}
}

// A write, delete, undelete, or destroy through the Vault invalidates the
// cached history for that path, simulating the chained-command shape
// (`safe x -- y`) that shares one *Vault after Task 13.
func TestVersionsCacheInvalidatedByMutations(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/a", map[string]string{"k": "v"})

	before, err := v.Versions("kv2/a")
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}

	s, _ := v.Read("kv2/a")
	_ = s.Set("k", "v2", false)
	if err := v.Write("kv2/a", s); err != nil {
		t.Fatalf("Write: %v", err)
	}
	after, err := v.Versions("kv2/a")
	if err != nil {
		t.Fatalf("Versions after write: %v", err)
	}
	if len(after) != len(before)+1 {
		t.Errorf("versions after write = %d, want %d", len(after), len(before)+1)
	}

	if err := v.Delete("kv2/a", vault.DeleteOpts{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	postDelete, err := v.Versions("kv2/a")
	if err != nil {
		t.Fatalf("Versions after delete: %v", err)
	}
	if postDelete[len(postDelete)-1].Deleted != true {
		t.Error("cache not invalidated by delete")
	}

	if err := v.UndeleteVersions("kv2/a", []uint{postDelete[len(postDelete)-1].Version}); err != nil {
		t.Fatalf("UndeleteVersions: %v", err)
	}
	postUndelete, err := v.Versions("kv2/a")
	if err != nil {
		t.Fatalf("Versions after undelete: %v", err)
	}
	if postUndelete[len(postUndelete)-1].Deleted {
		t.Error("cache not invalidated by UndeleteVersions")
	}
}

// Literal paths containing ':' must invalidate under the same key they
// cache under (ParsePath would truncate them).
func TestVersionsCacheColonPathInvalidation(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/od:d", map[string]string{"k": "v"})

	if _, err := v.Versions("kv2/od:d"); err != nil {
		t.Fatalf("Versions: %v", err)
	}
	s := vault.NewSecret()
	_ = s.Set("k", "v2", false)
	if err := v.Write(vault.EncodePath("kv2/od:d", "", 0), s); err != nil {
		t.Fatalf("Write: %v", err)
	}
	after, err := v.Versions("kv2/od:d")
	if err != nil {
		t.Fatalf("Versions after write: %v", err)
	}
	if len(after) != 2 {
		t.Errorf("versions = %d, want 2 (stale cache under mis-keyed entry)", len(after))
	}
}

// A non-GET/HEAD Curl call is an arbitrary API request -- `safe curl PUT
// /v1/kv2/data/a ...` -- not resolvable to one secret path the way every
// other mutating method here is, so it flushes the whole cache rather than
// one entry it cannot identify.
func TestVersionsCacheFlushedByCurlWrite(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/a", map[string]string{"k": "v"})

	if _, err := v.Versions("kv2/a"); err != nil {
		t.Fatalf("Versions: %v", err)
	}

	resp, err := v.Curl("PUT", "kv2/data/a", []byte(`{"data":{"k":"v2"}}`))
	if err != nil {
		t.Fatalf("Curl: %v", err)
	}
	_ = resp.Body.Close()

	fv.resetRequestLog()
	after, err := v.Versions("kv2/a")
	if err != nil {
		t.Fatalf("Versions after Curl PUT: %v", err)
	}
	if len(after) != 2 {
		t.Errorf("versions after Curl PUT = %d, want 2 (stale cache)", len(after))
	}
	if got := fv.requestCount(`^GET /v1/kv2/metadata/a$`); got != 1 {
		t.Errorf("metadata GETs after Curl PUT = %d, want 1 (cache not flushed)", got)
	}
}

// A Versions fetch that straddles a concurrent invalidation must not stick
// in the cache: a slow reader can be mid-fetch when a Write invalidates,
// and the read's own store-into-cache step, which runs after the fetch
// returns, must lose to that invalidation rather than overwrite it back in.
// go test -race cannot catch a regression here -- it is a logical race
// between two requests, not a data race on memory, since every cache access
// is already lock-guarded -- so this test drives the interleaving directly
// with the fake's request gate instead of relying on the race detector.
func TestVersionsCacheDoesNotStickAcrossStraddledInvalidation(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/a", map[string]string{"k": "v"})

	// need=2 never trips on its own: only one real metadata GET will ever
	// be in flight, so the request parks until explicitly released below.
	fv.holdRequests(2, `^GET /v1/kv2/metadata/a$`)

	done := make(chan struct{})
	var straddled []vaultkv.KVVersion
	var straddledErr error
	go func() {
		straddled, straddledErr = v.Versions("kv2/a")
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for fv.requestCount(`^GET /v1/kv2/metadata/a$`) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("metadata GET never arrived within 2s")
		}
		time.Sleep(time.Millisecond)
	}

	// Invalidate while the fetch above is still parked mid-flight.
	s, _ := v.Read("kv2/a")
	_ = s.Set("k", "v2", false)
	if err := v.Write("kv2/a", s); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Release the parked GET now that the invalidation has already run.
	fv.holdRequests(0, `^GET /v1/kv2/metadata/a$`)

	<-done
	if straddledErr != nil {
		t.Fatalf("Versions (straddling): %v", straddledErr)
	}
	if len(straddled) != 2 {
		t.Fatalf("straddling Versions = %d, want 2", len(straddled))
	}

	// If the straddling fetch above wrongly cached its result, this call
	// would be served from cache with zero further requests.
	fv.resetRequestLog()
	after, err := v.Versions("kv2/a")
	if err != nil {
		t.Fatalf("Versions after straddle: %v", err)
	}
	if len(after) != 2 {
		t.Errorf("versions after straddle = %d, want 2", len(after))
	}
	if got := fv.requestCount(`^GET /v1/kv2/metadata/a$`); got != 1 {
		t.Errorf("metadata GETs after straddle = %d, want 1 (straddling fetch stuck in cache)", got)
	}
}

// A deep move with deleted versions invalidates cached history at both
// endpoints: SecretEntry.Copy mutates dst directly through the client
// (tree.go), and the move's client.DestroyAll wipes src's metadata
// directly (vault.go), neither going through a Vault method that would
// otherwise invalidate. The source here carries only alive versions, so
// the walk's own undelete/re-delete cycle for a deleted version -- which
// separately invalidates any source path it touches -- never runs and so
// cannot mask a missing invalidation at either of the two sites this test
// means to pin. Warming the cache for both endpoints before the move, and
// requiring fresh, correct state after, means deleting either site's
// invalidation call fails this test even though the three earlier tests
// in this file stay green.
func TestVersionsCacheInvalidatedByDeepMoveBothEndpoints(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/src/a", map[string]string{"k": "v1"}, map[string]string{"k": "v2"})
	fv.setV2("kv2/dst/a", map[string]string{"k": "stale"})

	if _, err := v.Versions("kv2/src/a"); err != nil {
		t.Fatalf("Versions(src) warm: %v", err)
	}
	if _, err := v.Versions("kv2/dst/a"); err != nil {
		t.Fatalf("Versions(dst) warm: %v", err)
	}

	if err := v.MoveCopyTree("kv2/src", "kv2/dst", true, vault.MoveCopyOpts{Deep: true, DeletedVersions: true}); err != nil {
		t.Fatalf("MoveCopyTree: %v", err)
	}

	dstVersions, err := v.Versions("kv2/dst/a")
	if err != nil {
		t.Fatalf("Versions(dst) after move: %v", err)
	}
	if len(dstVersions) != 2 {
		t.Errorf("dst versions after move = %d, want 2 (stale pre-move cache)", len(dstVersions))
	}

	if _, err := v.Versions("kv2/src/a"); !vault.IsSecretNotFound(err) {
		t.Errorf("Versions(src) after deep move = (_, %v), want SecretNotFound (stale pre-move cache; metadata was wiped by DestroyAll)", err)
	}
}
