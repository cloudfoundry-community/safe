package cli

// The version 2 fake enforces Vault's check-and-set contract on data
// writes, so a command-level test can play a concurrent writer and watch a
// stale write be refused. The contract, pinned here at the wire level
// exactly as a real Vault answers it: a PUT carrying options.cas succeeds
// only when cas names the current version -- 0 only creates, and deleted
// or destroyed versions still count as current -- and a mismatch is a
// plain 400 whose body carries Vault's exact check-and-set message. A PUT
// carrying no options stays unconditional.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// putV2Raw sends one raw KV v2 data write to the fake, with or without a
// check-and-set version, and returns the status code and body.
func putV2Raw(t *testing.T, path string, cas *uint, data map[string]string) (int, string) {
	t.Helper()

	body := map[string]any{"data": data}
	if cas != nil {
		body["options"] = map[string]any{"cas": *cas}
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		t.Fatalf("encode body: %v", err)
	}

	req, err := http.NewRequest(http.MethodPut, os.Getenv("VAULT_ADDR")+"/v1/"+path, &buf)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp.StatusCode, string(b)
}

func TestFakeV2EnforcesCheckAndSet(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/x", map[string]string{"a": "1"})

	cas := func(n uint) *uint { return &n }

	//A stale version, and cas=0 against surviving history, are both the
	// check-and-set refusal, with Vault's message verbatim.
	for _, n := range []uint{0, 5} {
		status, body := putV2Raw(t, "secret/data/x", cas(n), map[string]string{"b": "2"})
		if status != http.StatusBadRequest {
			t.Errorf("cas=%d against version 1 = status %d, want 400", n, status)
		}
		if !strings.Contains(body, "check-and-set parameter did not match the current version") {
			t.Errorf("cas=%d body = %q, want Vault's check-and-set message", n, body)
		}
	}
	if states := fv.versionStates("secret/x"); len(states) != 1 {
		t.Fatalf("refused writes still appended: versions = %v", states)
	}

	//The current version is accepted, and a write with no options stays
	// unconditional.
	if status, body := putV2Raw(t, "secret/data/x", cas(1), map[string]string{"b": "2"}); status != http.StatusOK {
		t.Fatalf("cas=1 against version 1 = status %d (%s), want 200", status, body)
	}
	if status, body := putV2Raw(t, "secret/data/x", nil, map[string]string{"c": "3"}); status != http.StatusOK {
		t.Fatalf("unconditional write = status %d (%s), want 200", status, body)
	}
	if states := fv.versionStates("secret/x"); len(states) != 3 {
		t.Fatalf("versions = %v, want 3 after two accepted writes", states)
	}

	//Deleted and destroyed versions still count as current: cas=0 is
	// refused on a soft-deleted path, and the current number is accepted.
	fv.setV2("secret/gone", map[string]string{"old": "x"})
	fv.deleteV2("secret/gone", 1)
	if status, _ := putV2Raw(t, "secret/data/gone", cas(0), map[string]string{"new": "y"}); status != http.StatusBadRequest {
		t.Errorf("cas=0 against a soft-deleted version = status %d, want 400", status)
	}
	if status, body := putV2Raw(t, "secret/data/gone", cas(1), map[string]string{"new": "y"}); status != http.StatusOK {
		t.Errorf("cas=1 against a soft-deleted version = status %d (%s), want 200", status, body)
	}

	//A path with no history at all is exactly what cas=0 is for.
	if status, body := putV2Raw(t, "secret/data/fresh", cas(0), map[string]string{"n": "1"}); status != http.StatusOK {
		t.Errorf("cas=0 against an absent path = status %d (%s), want 200", status, body)
	}
}
