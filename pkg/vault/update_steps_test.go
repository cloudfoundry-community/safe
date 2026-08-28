package vault_test

// UpdateSteps is the chained form of Update that cmdGen's one-read,
// write-per-key groups run on: a single read seeds the accumulated state,
// each step's write persists that state as its own version check-and-set
// against the version the previous write assigned, and a conflict re-reads
// and re-applies only the steps whose writes have not landed -- persisted
// keys ride along in the fresh read rather than being generated again.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// A conflict in the middle of a chain retries just the unpersisted tail:
// the concurrent writer's key survives, every step's key lands exactly
// once, and the version history counts one version per write -- ours and
// theirs -- with no version wasted on re-writing what already landed.
func TestUpdateStepsChainConvergesAcrossConflict(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")

	//The concurrent writer lands between our second and third writes,
	// building on our latest version the way a real process would.
	fv.afterRequest(`^(PUT|POST) /v1/kv2/data/x$`, 2, func() {
		merged := map[string]string{}
		for k, val := range latestV2Data(t, fv, updDataPath) {
			merged[k] = val
		}
		merged["theirs"] = "y"
		fv.setV2(updDataPath, merged)
	})

	calls := map[int]int{}
	err := v.UpdateSteps(updDataPath, 4, func(step int, s *vault.Secret, exists bool) (bool, error) {
		calls[step]++
		if err := s.Set(fmt.Sprintf("k%d", step), fmt.Sprintf("v%d", step), false); err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("UpdateSteps: %v", err)
	}

	got := latestV2Data(t, fv, updDataPath)
	for _, k := range []string{"k0", "k1", "k2", "k3", "theirs"} {
		if got[k] == "" {
			t.Errorf("final secret is missing %s (full: %v)", k, got)
		}
	}
	if states := fv.v2States(updDataPath); len(states) != 5 {
		t.Errorf("version count = %d, want 5 (four writes of ours, one of theirs)", len(states))
	}
	//Steps 0 and 1 persisted before the conflict and must not run again;
	// step 2's write was refused, so it alone repeats; step 3 runs once,
	// after the retry.
	want := map[int]int{0: 1, 1: 1, 2: 2, 3: 1}
	for step, n := range want {
		if calls[step] != n {
			t.Errorf("step %d ran %d times, want %d", step, calls[step], n)
		}
	}
	if gets := fv.requestCount(updDataGet); gets != 2 {
		t.Errorf("data reads = %d, want 2 (the seed and the conflict re-read)", gets)
	}
	if puts := fv.requestCount(updDataPut); puts != 5 {
		t.Errorf("data writes = %d, want 5 (four landed, one refused)", puts)
	}
}

// A step that declines its write is not "done": every retry pass
// re-evaluates it against the fresh state, exactly like a --no-clobber
// skip re-deciding after a concurrent writer moved the secret.
func TestUpdateStepsReevaluatesDeclinedStepsOnRetry(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"a": "1"})

	fv.afterRequest(updDataGet, 1, func() {
		fv.setV2(updDataPath, map[string]string{"a": "1", "theirs": "y"})
	})

	calls := map[int]int{}
	err := v.UpdateSteps(updDataPath, 2, func(step int, s *vault.Secret, exists bool) (bool, error) {
		calls[step]++
		if step == 0 {
			return false, nil
		}
		if err := s.Set("gen", "ours", false); err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("UpdateSteps: %v", err)
	}
	if calls[0] != 2 || calls[1] != 2 {
		t.Errorf("step runs = %v, want both steps re-run on the retry pass", calls)
	}
	got := latestV2Data(t, fv, updDataPath)
	if got["theirs"] != "y" || got["gen"] != "ours" {
		t.Errorf("final secret = %v, want the concurrent key and the generated key", got)
	}
}

// On a KV v1 mount the chain is a plain read followed by one write per
// step, no cas sent and no retries possible.
func TestUpdateStepsV1PlainWrites(t *testing.T) {
	v, fv := newTestVault(t)

	err := v.UpdateSteps("secret/x", 3, func(step int, s *vault.Secret, exists bool) (bool, error) {
		if err := s.Set(fmt.Sprintf("k%d", step), "v", false); err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("UpdateSteps on v1: %v", err)
	}
	got := mustGetSecret(t, fv, "secret/x")
	if len(got) != 3 {
		t.Errorf("stored secret = %v, want the three step keys", got)
	}
	if gets := fv.requestCount(`^GET /v1/secret/x(\?.*)?$`); gets != 1 {
		t.Errorf("reads = %d, want 1", gets)
	}
	if puts := fv.requestCount(`^(PUT|POST) /v1/secret/x$`); puts != 3 {
		t.Errorf("writes = %d, want 3", puts)
	}
}

// The whole chain shares one budget of five read passes; sustained
// conflict fails naming the path.
func TestUpdateStepsExhaustionNamesThePath(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2(updDataPath, map[string]string{"n": "0"})

	fv.afterRequest(updDataGet, 0, func() {
		fv.setV2(updDataPath, map[string]string{"n": "bumped"})
	})

	err := v.UpdateSteps(updDataPath, 2, func(step int, s *vault.Secret, exists bool) (bool, error) {
		if err := s.Set(fmt.Sprintf("k%d", step), "v", false); err != nil {
			return false, err
		}
		return true, nil
	})
	if err == nil {
		t.Fatal("UpdateSteps under sustained conflict = nil, want an error")
	}
	if !strings.Contains(err.Error(), updDataPath) {
		t.Errorf("error = %q, want it to name %s", err, updDataPath)
	}
	if gets := fv.requestCount(updDataGet); gets != 5 {
		t.Errorf("data reads = %d, want 5 (one per pass)", gets)
	}
}
