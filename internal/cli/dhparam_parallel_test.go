package cli

// cmdDhparam's path loop now groups targets by their canonical secret path,
// the same way cmdGen, cmdSsh, and cmdRsa do (keygen_parallel_test.go), and
// generates distinct paths concurrently through dhparamPaths. Unlike those
// three, dhparamPaths cannot be driven through a stubbed generator here --
// dhparamGen lives in pkg/vault, unexported, and its stubbing seam
// (pkg/vault/dhparam_seam_test.go) is only reachable from vault_test, not
// from this package -- so these tests pay for a real, small (1024-bit)
// openssl dhparam per case, same as pkg/vault/secret_dhparam_test.go does.

import (
	"testing"
	"time"
)

// Four distinct paths overlap their underlying Read/Write traffic, rather
// than generating their DH parameters one at a time.
//
// This deliberately does not go through captureStdout, for the same reason
// as TestCmdGenWritesDistinctPathsConcurrently: on a genuine miss the parked
// request would otherwise still be blocked when the test returns.
func TestCmdDhparamWritesDistinctPathsConcurrently(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	pattern := `^(PUT|POST) /v1/secret/[a-z]$`
	release := fv.holdRequests(2, pattern)

	c := newKeygenCLI(t)

	done := make(chan error, 1)
	go func() {
		done <- c.cmdDhparam("dhparam", "1024",
			"secret/a", "secret/b", "secret/c", "secret/d")
	}()

	var cmdErr error
	var overlapped bool
	select {
	case <-release:
		overlapped = true
		cmdErr = <-done
	case cmdErr = <-done:
		// finished with no observed overlap
	case <-time.After(10 * time.Second):
		fv.holdRequests(0, pattern) // let the parked request, and cmdDhparam, finish
		cmdErr = <-done
	}

	if cmdErr != nil {
		t.Fatalf("cmdDhparam: %v", cmdErr)
	}
	if !overlapped {
		t.Fatal("no overlap observed: distinct paths generate their DH parameters sequentially")
	}

	for _, name := range []string{"a", "b", "c", "d"} {
		path := "secret/" + name
		kv := fv.get(path)
		if kv["dhparam-pem"] == "" {
			t.Errorf("%s has no dhparam-pem written", path)
		}
	}
}

// secret//x and secret/x name the same secret; grouping has to canonicalize
// both spellings to the same key, or the second target's read-modify-write
// races the first's rather than seeing it.
//
// skipIfExists is the load-bearing part of this test: within a correctly
// grouped pair the second argument runs only after the first has written,
// sees "dhparam-pem" already there, and skips -- exactly one version.
// Mis-grouped (e.g. keyed by the raw argument instead of the canonical
// path), both arguments land in their own group and race: both read empty,
// both skip nothing, both write, leaving two alive versions. A version
// count alone (with skipIfExists off) cannot tell these apart -- KV v2
// appends a version on every write either way, correctly grouped or not.
func TestDhparamPathsCanonicalizesGroupingKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)

	v := connect(true)

	if err := dhparamPaths(v, []string{"secret//x", "secret/x"}, 1024, true, true); err != nil {
		t.Fatalf("dhparamPaths: %v", err)
	}

	if states := fv.versionStates("secret/x"); len(states) != 1 {
		t.Fatalf("version states = %v, want 1 (second argument skips: dhparam-pem already present)", states)
	}
}
