package cli

// cmdGen's target loop now groups targets by their canonical secret path and
// generates distinct paths concurrently; multiple keys on the same path stay
// sequential, so a read-modify-write on that path never races itself and
// only ever produces one Vault version per generated key.

import (
	"strings"
	"testing"
	"time"
)

// Four distinct paths overlap their Read/Write traffic, rather than being
// generated one at a time.
//
// This deliberately does not go through captureStdout: on a genuine miss (no
// overlap within the deadline) the parked request, and so cmdGen, would
// otherwise still be blocked when the test function returns, leaving a
// goroutine that could still touch the fake Vault after its httptest server
// has been torn down by t.Cleanup.
func TestCmdGenWritesDistinctPathsConcurrently(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	pattern := `^(PUT|POST) /v1/secret/[a-z]$`
	release := fv.holdRequests(2, pattern)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy

	done := make(chan error, 1)
	go func() {
		done <- c.cmdGen("gen", "16",
			"secret/a:pw", "secret/b:pw", "secret/c:pw", "secret/d:pw")
	}()

	var cmdErr error
	var overlapped bool
	select {
	case <-release:
		overlapped = true
		cmdErr = <-done
	case cmdErr = <-done:
		// finished with no observed overlap
	case <-time.After(5 * time.Second):
		fv.holdRequests(0, pattern) // let the parked request, and cmdGen, finish
		cmdErr = <-done
	}

	if cmdErr != nil {
		t.Fatalf("cmdGen: %v", cmdErr)
	}
	if !overlapped {
		t.Fatal("no overlap observed: distinct paths are generated sequentially")
	}
}

// Two keys on the same path -- naming it twice on the command line -- still
// go through a read-modify-write per key, one after the other: the second
// generated key must see the first one already in the secret, and the fake's
// version history must show one version per key rather than one shared
// version that raced the other's write.
func TestCmdGenSamePathStaysSequentialWithinAGroup(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy

	if err := c.cmdGen("gen", "16", "secret/x:a", "secret/x:b"); err != nil {
		t.Fatalf("cmdGen: %v", err)
	}

	if states := fv.versionStates("secret/x"); len(states) != 2 {
		t.Fatalf("version states = %v, want 2 (one read-modify-write per key)", states)
	}

	for _, key := range []string{"a", "b"} {
		var err error
		out := captureStdout(t, func() { err = c.cmdGet("get", "secret/x:"+key) })
		if err != nil {
			t.Fatalf("cmdGet(secret/x:%s): %v", key, err)
		}
		if got := len(strings.TrimSpace(out)); got != 16 {
			t.Errorf("secret/x:%s has length %d, want 16", key, got)
		}
	}
}

// secret//x and secret/x name the same secret; grouping has to canonicalize
// both spellings to the same key or the second target's read-modify-write
// races the first's and one of the two generated keys is lost.
func TestCmdGenCanonicalizesGroupingKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy

	if err := c.cmdGen("gen", "16", "secret//x:a", "secret/x:b"); err != nil {
		t.Fatalf("cmdGen: %v", err)
	}

	kv := fv.get("secret/x")
	if len(kv["a"]) != 16 {
		t.Errorf("secret/x[a] has length %d, want 16 (keys: %v)", len(kv["a"]), kv)
	}
	if len(kv["b"]) != 16 {
		t.Errorf("secret/x[b] has length %d, want 16 (keys: %v)", len(kv["b"]), kv)
	}
}
