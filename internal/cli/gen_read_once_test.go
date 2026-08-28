package cli

// cmdGen used to run a full read-modify-write per (path, key) target, so
// `safe gen secret/db user secret/db pass` read secret/db twice on its way
// to two writes. A group now reads its path once and applies its keys
// cumulatively against that in-memory state, one write per key -- N keys
// cost N+1 requests instead of 2N, while the write-per-key keeps one Vault
// version per generated key, exactly as before.

import (
	"strings"
	"testing"
)

// secretRequests filters the fake's log down to the requests that touched
// the version 1 data path, so budgets ignore mount discovery and anything
// else on the wire.
func secretRequests(fv *cliFakeVault, path string) []string {
	var out []string
	for _, r := range fv.requests() {
		if strings.HasSuffix(r, " /v1/"+path) {
			out = append(out, r)
		}
	}
	return out
}

// Two keys on one path cost one GET and two PUTs -- the second key's write
// builds on the first's in-memory state instead of re-reading it.
func TestCmdGenReadsEachPathOnceForAllKeys(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy

	if err := c.cmdGen("gen", "16", "secret/db", "user", "secret/db", "pass"); err != nil {
		t.Fatalf("cmdGen: %v", err)
	}

	reqs := secretRequests(fv, "secret/db")
	want := []string{"GET /v1/secret/db", "PUT /v1/secret/db", "PUT /v1/secret/db"}
	if len(reqs) != len(want) {
		t.Fatalf("requests to secret/db = %v, want %v", reqs, want)
	}
	for i, r := range want {
		if reqs[i] != r {
			t.Fatalf("requests to secret/db = %v, want %v", reqs, want)
		}
	}

	kv := fv.get("secret/db")
	for _, key := range []string{"user", "pass"} {
		if len(kv[key]) != 16 {
			t.Errorf("secret/db[%s] has length %d, want 16 (keys: %v)", key, len(kv[key]), kv)
		}
	}
}

// On a version 2 mount the single read still yields one version per
// generated key -- three keys, three versions -- and each write carries
// every key generated before it, so the history is cumulative.
func TestCmdGenCumulativeWritesKeepOneVersionPerKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy

	if err := c.cmdGen("gen", "16", "secret/x", "a", "secret/x", "b", "secret/x", "c"); err != nil {
		t.Fatalf("cmdGen: %v", err)
	}

	if states := fv.versionStates("secret/x"); len(states) != 3 {
		t.Fatalf("version states = %v, want 3 (one version per generated key)", states)
	}

	// Every request that touches path x, data or metadata alike -- not
	// just the data endpoint -- so a stray metadata GET on this virgin
	// path (which has no history for it to find anything at) fails the
	// budget instead of going unseen.
	var gets, puts, metas int
	for _, r := range fv.requests() {
		switch {
		case strings.HasPrefix(r, "GET /v1/secret/data/x"):
			gets++
		case strings.HasPrefix(r, "PUT /v1/secret/data/x"), strings.HasPrefix(r, "POST /v1/secret/data/x"):
			puts++
		case strings.HasPrefix(r, "GET /v1/secret/metadata/x"):
			metas++
		}
	}
	if gets != 1 || puts != 3 || metas != 0 {
		t.Errorf("secret/x traffic = %d GETs, %d PUTs, %d metadata GETs; want 1, 3, 0\n%v", gets, puts, metas, fv.requests())
	}

	// Version N holds keys 1..N: the chain accumulates, never resets.
	fv.mu.Lock()
	history := fv.versions["secret/x"]
	var perVersion []int
	for _, v := range history {
		perVersion = append(perVersion, len(v.data))
	}
	fv.mu.Unlock()
	for i, n := range perVersion {
		if n != i+1 {
			t.Errorf("version %d holds %d keys, want %d (key counts per version: %v)", i+1, n, i+1, perVersion)
		}
	}
}

// A --no-clobber skip keeps the existing value in the accumulated state, so
// the writes for the keys that follow carry it rather than dropping it.
func TestCmdGenNoClobberSkipCarriesExistingValueThroughWrites(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/db", map[string]string{"user": "keepme"})

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	c.opt.SkipIfExists = true

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdGen("gen", "16", "secret/db", "user", "secret/db", "pass")
	})
	if err != nil {
		t.Fatalf("cmdGen: %v", err)
	}
	if !strings.Contains(stderr, "secret/db:user") {
		t.Errorf("stderr should carry the refusal notice for secret/db:user\n---\n%s", stderr)
	}

	// The skipped key costs no write: one GET, then one PUT for pass.
	reqs := secretRequests(fv, "secret/db")
	want := []string{"GET /v1/secret/db", "PUT /v1/secret/db"}
	if len(reqs) != len(want) || reqs[0] != want[0] || reqs[1] != want[1] {
		t.Fatalf("requests to secret/db = %v, want %v", reqs, want)
	}

	kv := fv.get("secret/db")
	if kv["user"] != "keepme" {
		t.Errorf("secret/db[user] = %q, want the pre-existing value to survive", kv["user"])
	}
	if len(kv["pass"]) != 16 {
		t.Errorf("secret/db[pass] has length %d, want 16 (keys: %v)", len(kv["pass"]), kv)
	}
}
