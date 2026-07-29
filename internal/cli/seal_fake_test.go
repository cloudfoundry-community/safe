package cli

// A fake Vault that answers the seal-state endpoints: health, seal-status,
// seal, and unseal. The KV fake in vault_fake_test.go serves secrets only,
// and the commands that report or change seal state never read a secret.
//
// Tests that involve more than one target write their own ~/.saferc, so the
// helper hands back the server URL rather than setting VAULT_ADDR itself.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type fakeSealVault struct {
	mu     sync.Mutex
	sealed bool
	//seals and unseals count the requests that changed the seal state, so a
	// test can tell which of two Vaults a command acted on.
	seals   int
	unseals int
	url     string
	//rootToken is what initializing this Vault hands back.
	rootToken string
}

// newSealFake starts a fake Vault in the given seal state.
func newSealFake(t *testing.T, sealed bool) *fakeSealVault {
	t.Helper()
	f := &fakeSealVault{sealed: sealed, rootToken: "root-token"}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

// isSealed reports the current seal state.
func (f *fakeSealVault) isSealed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sealed
}

func (f *fakeSealVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")

	// A sealed Vault answers health with 503, which is how Sealed() tells the
	// two states apart.
	state := map[string]any{
		"type":        "shamir",
		"sealed":      f.sealed,
		"t":           1,
		"n":           1,
		"progress":    0,
		"nonce":       "",
		"version":     "1.0.0",
		"initialized": true,
	}

	switch {
	case r.URL.Path == "/v1/sys/health":
		if f.sealed {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = w.Write([]byte(`{}`))

	case r.URL.Path == "/v1/sys/seal-status":
		_ = json.NewEncoder(w).Encode(state)

	case r.URL.Path == "/v1/sys/seal" && r.Method == http.MethodPut:
		f.sealed = true
		f.seals++
		w.WriteHeader(http.StatusNoContent)

	case r.URL.Path == "/v1/sys/init" && r.Method == http.MethodPut:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys":        []string{"seal-key"},
			"keys_base64": []string{"seal-key"},
			"root_token":  f.rootToken,
		})

	case r.URL.Path == "/v1/sys/unseal" && r.Method == http.MethodPut:
		var body struct {
			Key   string `json:"key"`
			Reset bool   `json:"reset"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if !body.Reset {
			f.sealed = false
			f.unseals++
		}
		state["sealed"] = f.sealed
		_ = json.NewEncoder(w).Encode(state)

	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
	}
}

// writeSaferc writes a ~/.saferc under the isolated home.
func writeSaferc(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(os.Getenv("HOME"), ".saferc")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// twoTargets renders a config naming both Vaults, with alpha current. Neither
// uses Strongbox, so the commands take the single-address branch; the
// Strongbox flag is exercised on its own in the tests that care about it.
func twoTargets(alpha, beta *fakeSealVault) string {
	return `version: 1
current: alpha
vaults:
  alpha:
    url: ` + alpha.url + `
    token: token-alpha
    no_strongbox: true
  beta:
    url: ` + beta.url + `
    token: token-beta
    no_strongbox: true
`
}
