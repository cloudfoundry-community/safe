package cli

// End-to-end tests for cmdRekey (server.go) against a fake Vault that speaks
// the sys/rekey API. The unseal key the operation asks for is fed through
// prompt.SetReader, and KV traffic (for --persist) is delegated to the
// existing cliFakeVault.
//
// captureStdout mutates os.Stdout — do NOT add t.Parallel to any test in
// this file.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

// fakeRekeyVault answers the four sys/rekey requests a rekey makes: cancel,
// start, status, and update. Everything else falls through to the KV fake so
// --persist can write the new keys back into the Vault.
type fakeRekeyVault struct {
	mu sync.Mutex
	//required is how many current unseal keys the operation demands.
	required int
	//newKeys is what the completed rekey hands back.
	newKeys []string
	//startBody is the decoded body of the PUT that started the rekey.
	startBody map[string]any
	kv        *cliFakeVault
}

func (f *fakeRekeyVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/v1/sys/rekey/init" && r.Method == http.MethodDelete:
		_, _ = w.Write([]byte(`{}`))

	case r.URL.Path == "/v1/sys/rekey/init" && r.Method == http.MethodPut:
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.startBody = body
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{}`))

	case r.URL.Path == "/v1/sys/rekey/init" && r.Method == http.MethodGet:
		f.mu.Lock()
		required := f.required
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"started":  true,
			"nonce":    "test-nonce",
			"t":        1,
			"n":        1,
			"progress": 0,
			"required": required,
		})

	case r.URL.Path == "/v1/sys/rekey/update" && r.Method == http.MethodPut:
		f.mu.Lock()
		keys := append([]string(nil), f.newKeys...)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"complete":    true,
			"keys":        keys,
			"keys_base64": keys,
		})

	default:
		f.kv.ServeHTTP(w, r)
	}
}

// rekeyStart returns the recorded body of the PUT that began the rekey.
func (f *fakeRekeyVault) rekeyStart() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startBody
}

// newRekeyFake starts the fake, targets it via the environment, and queues
// one current unseal key on the prompt reader.
func newRekeyFake(t *testing.T, newKeys []string) *fakeRekeyVault {
	t.Helper()
	f := &fakeRekeyVault{
		required: 1,
		newKeys:  newKeys,
		kv:       &cliFakeVault{data: map[string]map[string]string{}},
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")
	prompt.SetReader(strings.NewReader("current-unseal-key\n"))
	t.Cleanup(func() { prompt.SetReader(nil) })
	return f
}

func TestCmdRekey_RekeysAndPrintsNumberedKeys(t *testing.T) {
	// No t.Parallel — captureStdout mutates os.Stdout.
	isolateHome(t)
	f := newRekeyFake(t, []string{"new-key-one"})
	c := rekeyCLI(t)
	c.opt.Rekey.NKeys = 1

	var err error
	out := captureStdout(t, func() {
		err = c.cmdRekey("rekey")
	})
	if err != nil {
		t.Fatalf("cmdRekey returned unexpected error: %v", err)
	}
	if !strings.Contains(out, "re-keyed") {
		t.Errorf("expected a re-key confirmation, got:\n%s", out)
	}
	if !strings.Contains(out, "Unseal key 1") || !strings.Contains(out, "new-key-one") {
		t.Errorf("expected the new key listed by number, got:\n%s", out)
	}

	start := f.rekeyStart()
	if start == nil {
		t.Fatal("no rekey was started on the Vault")
	}
	if got := start["secret_shares"]; got != float64(1) {
		t.Errorf("secret_shares: got %v, want 1", got)
	}
	if got := start["secret_threshold"]; got != float64(1) {
		t.Errorf("secret_threshold: got %v, want 1", got)
	}
}

func TestCmdRekey_GPGKeysArePassedAndLabelOutput(t *testing.T) {
	// No t.Parallel — captureStdout mutates os.Stdout.
	isolateHome(t)
	installFakeGPG(t)
	f := newRekeyFake(t, []string{"new-key-one"})
	c := rekeyCLI(t)
	c.opt.Rekey.GPG = []string{"alice@example.com"}

	var err error
	out := captureStdout(t, func() {
		err = c.cmdRekey("rekey")
	})
	if err != nil {
		t.Fatalf("cmdRekey returned unexpected error: %v", err)
	}
	if !strings.Contains(out, "Unseal key for") || !strings.Contains(out, "alice@example.com") {
		t.Errorf("expected the key labeled with its GPG owner, got:\n%s", out)
	}

	start := f.rekeyStart()
	if start == nil {
		t.Fatal("no rekey was started on the Vault")
	}
	pgp, ok := start["pgp_keys"].([]any)
	if !ok || len(pgp) != 1 {
		t.Fatalf("pgp_keys: got %v, want one entry", start["pgp_keys"])
	}
	want := base64.StdEncoding.EncodeToString([]byte(fakeGPGKeyBytes))
	if pgp[0] != want {
		t.Errorf("pgp_keys[0]: got %v, want %s", pgp[0], want)
	}
	if start["backup"] != true {
		t.Errorf("backup: got %v, want true when GPG keys are given", start["backup"])
	}
}

func TestCmdRekey_PersistSavesNewSealKeys(t *testing.T) {
	// No t.Parallel — captureStdout mutates os.Stdout.
	isolateHome(t)
	f := newRekeyFake(t, []string{"new-key-one"})
	c := rekeyCLI(t)
	c.opt.Rekey.NKeys = 1
	c.opt.Rekey.Persist = true

	var err error
	captureStdout(t, func() {
		err = c.cmdRekey("rekey")
	})
	if err != nil {
		t.Fatalf("cmdRekey returned unexpected error: %v", err)
	}

	saved := f.kv.get("secret/vault/seal/keys")
	if saved == nil {
		t.Fatal("the new seal keys were not persisted to secret/vault/seal/keys")
	}
	if saved["key1"] != "new-key-one" {
		t.Errorf("persisted key1: got %q, want %q", saved["key1"], "new-key-one")
	}
}
