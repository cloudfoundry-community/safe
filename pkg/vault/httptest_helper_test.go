// Package vault_test provides a fake Vault HTTP server for black-box tests.
// The helper stands up a KV v1 backend (all secrets live under /secret/)
// and wires a *Vault to it via the vaultkv client's VaultURL field.
//
// Endpoints handled:
//
//	GET  /v1/sys/internal/ui/mounts — mount discovery (returns /secret/ as KV v1)
//	GET  /v1/auth/token/lookup-self — token validity check (200 OK)
//	GET  /v1/sys/mounts            — list mounts (used by IsMounted/PKI checks)
//	GET  /v1/secret/*              — read secret
//	POST /v1/secret/*              — write secret
//	DELETE /v1/secret/*            — delete secret
//	LIST /v1/secret/*              — list secrets (uses X-List-Method or PROPFIND-style)
package vault_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
	"github.com/cloudfoundry-community/vaultkv"
)

// fakeVault is an in-memory key-value store that mimics a Vault KV v1 backend.
type fakeVault struct {
	mu   sync.RWMutex
	data map[string]map[string]string // path → key → value

	// pki holds registered PKI mount names (for sys/mounts responses).
	pki map[string]bool

	// pkiIssueHandler, if non-nil, is called for POST /v1/<backend>/issue/<role>.
	pkiIssueHandler func(w http.ResponseWriter, r *http.Request)

	// pkiRevokeHandler, if non-nil, is called for POST /v1/<backend>/revoke.
	pkiRevokeHandler func(w http.ResponseWriter, r *http.Request)

	// seal models the sys/seal, sys/unseal, sys/init, and sys/seal-status
	// endpoints for Init/Seal/Unseal/Sealed/SealKeys tests.
	initialized bool
	sealed      bool
	threshold   int      // keys required to unseal
	shares      int      // total unseal keys
	progress    int      // keys submitted so far this unseal attempt
	rootToken   string   // returned by sys/init
	initKeys    []string // returned by sys/init

	// rekey models the sys/rekey/init and sys/rekey/update endpoints.
	rekeyActive   bool
	rekeyNonce    string
	rekeyRequired int      // existing keys needed to authorize the rekey
	rekeyProgress int      // existing keys submitted so far
	rekeyShares   int      // new key count to mint on completion
	rekeyNewKeys  []string // new keys returned on completion
}

func newFakeVault() *fakeVault {
	return &fakeVault{
		data:        make(map[string]map[string]string),
		pki:         make(map[string]bool),
		initialized: true,
	}
}

// set stores kv pairs at a secret path. Callers own the map.
func (f *fakeVault) set(path string, kv map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make(map[string]string, len(kv))
	for k, v := range kv {
		cp[k] = v
	}
	f.data[path] = cp
}

// get retrieves kv pairs for a path. Returns nil if absent.
func (f *fakeVault) get(path string) map[string]string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	kv := f.data[path]
	if kv == nil {
		return nil
	}
	cp := make(map[string]string, len(kv))
	for k, v := range kv {
		cp[k] = v
	}
	return cp
}

// del removes a secret path.
func (f *fakeVault) del(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, path)
}

// listUnder returns immediate children under prefix (relative paths).
// Paths that have deeper nesting appear as "child/" (folder) entries.
func (f *fakeVault) listUnder(prefix string) []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	prefix = strings.TrimRight(prefix, "/") + "/"
	seen := map[string]bool{}
	var out []string
	for p := range f.data {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rel := strings.TrimPrefix(p, prefix)
		// immediate child vs sub-folder
		parts := strings.SplitN(rel, "/", 2)
		entry := parts[0]
		if len(parts) == 2 {
			entry = parts[0] + "/"
		}
		if !seen[entry] {
			seen[entry] = true
			out = append(out, entry)
		}
	}
	return out
}

// sysMountsForListJSON returns payload used by Vault.Mounts (sys/mounts endpoint).
func (f *fakeVault) sysMountsForListJSON() []byte {
	f.mu.RLock()
	defer f.mu.RUnlock()
	type mountEntry struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		Config      any    `json:"config"`
	}
	mounts := map[string]mountEntry{
		"secret/": {Type: "kv", Config: map[string]any{}},
	}
	for name := range f.pki {
		mounts[name+"/"] = mountEntry{Type: "pki", Config: map[string]any{}}
	}
	b, _ := json.Marshal(mounts)
	return b
}

// uiMountsJSON returns the /sys/internal/ui/mounts payload used by IsKVv2Mount.
func (f *fakeVault) uiMountsJSON() []byte {
	f.mu.RLock()
	defer f.mu.RUnlock()
	type optEntry struct {
		Version string `json:"version"`
	}
	type secretMount struct {
		Type    string   `json:"type"`
		Options optEntry `json:"options"`
	}
	secretMap := map[string]secretMount{
		"secret/": {Type: "kv", Options: optEntry{Version: "1"}},
	}
	for name := range f.pki {
		secretMap[name+"/"] = secretMount{Type: "pki"}
	}
	payload := map[string]any{
		"data": map[string]any{
			"secret": secretMap,
		},
	}
	b, _ := json.Marshal(payload)
	return b
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
}

// ServeHTTP dispatches requests to the fake Vault server.
func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path // e.g. /v1/secret/foo

	switch {
	case p == "/v1/sys/internal/ui/mounts" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.uiMountsJSON())

	case p == "/v1/auth/token/lookup-self" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"test-token"}}`))

	case p == "/v1/sys/mounts" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.sysMountsForListJSON())

	case p == "/v1/sys/health",
		p == "/v1/sys/seal-status",
		p == "/v1/sys/init",
		p == "/v1/sys/seal",
		p == "/v1/sys/unseal",
		p == "/v1/sys/rekey/init",
		p == "/v1/sys/rekey/update":
		f.handleSys(w, r)

	case strings.HasPrefix(p, "/v1/secret/") || p == "/v1/secret":
		f.handleKV(w, r)

	default:
		// PKI issue / revoke
		f.handlePKI(w, r)
	}
}

func (f *fakeVault) handleKV(w http.ResponseWriter, r *http.Request) {
	// Strip /v1/secret prefix to get the subpath.
	subpath := strings.TrimPrefix(r.URL.Path, "/v1/secret")
	subpath = strings.Trim(subpath, "/")

	// LIST is sent as GET with ?list=true or as PROPFIND-alike.
	// vaultkv sends it as a GET with ?list=true query param for v1.
	isList := r.Method == "LIST" || r.URL.Query().Get("list") == "true"

	switch {
	case isList:
		prefix := "secret/" + subpath
		children := f.listUnder(prefix)
		if len(children) == 0 {
			jsonErr(w, http.StatusNotFound, "")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"keys": children,
			},
		})

	case r.Method == http.MethodGet:
		secretPath := "secret/" + subpath
		kv := f.get(secretPath)
		if kv == nil {
			jsonErr(w, http.StatusNotFound, "")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": kv,
		})

	case r.Method == http.MethodPost || r.Method == http.MethodPut:
		secretPath := "secret/" + subpath
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		kv := make(map[string]string)
		for k, v := range body {
			switch s := v.(type) {
			case string:
				kv[k] = s
			default:
				b, _ := json.Marshal(v)
				kv[k] = string(b)
			}
		}
		f.set(secretPath, kv)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete:
		secretPath := "secret/" + subpath
		f.del(secretPath)
		w.WriteHeader(http.StatusNoContent)

	default:
		jsonErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (f *fakeVault) handlePKI(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/v1/")

	// Check if path belongs to a registered PKI backend.
	for name := range f.pki {
		if strings.HasPrefix(p, name+"/issue/") && r.Method == http.MethodPost {
			if f.pkiIssueHandler != nil {
				f.pkiIssueHandler(w, r)
				return
			}
			jsonErr(w, http.StatusInternalServerError, "no pki issue handler registered")
			return
		}
		if strings.HasPrefix(p, name+"/revoke") && r.Method == http.MethodPost {
			if f.pkiRevokeHandler != nil {
				f.pkiRevokeHandler(w, r)
				return
			}
			jsonErr(w, http.StatusInternalServerError, "no pki revoke handler registered")
			return
		}
		// GET /v1/<backend>/ca/pem or similar
		if strings.HasPrefix(p, name+"/") && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("-----BEGIN CERTIFICATE-----\nFAKEPEM\n-----END CERTIFICATE-----\n"))
			return
		}
	}

	jsonErr(w, http.StatusNotFound, "not found")
}

// sealStateJSON renders the SealState payload shared by seal-status and unseal.
func (f *fakeVault) sealStateJSON() map[string]any {
	return map[string]any{
		"type":        "shamir",
		"sealed":      f.sealed,
		"t":           f.threshold,
		"n":           f.shares,
		"progress":    f.progress,
		"nonce":       "",
		"version":     "1.0.0",
		"initialized": f.initialized,
	}
}

// handleSys models the subset of sys/* endpoints used by the seal, unseal,
// init, and rekey flows. All state lives on the fakeVault under f.mu.
func (f *fakeVault) handleSys(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path

	writeJSON := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	switch {
	case p == "/v1/sys/health" && r.Method == http.MethodGet:
		// Status code alone drives Health(); body is decoded but unused.
		switch {
		case !f.initialized:
			w.WriteHeader(http.StatusNotImplemented) // 501 → uninitialized
		case f.sealed:
			w.WriteHeader(http.StatusServiceUnavailable) // 503 → sealed
		default:
			w.WriteHeader(http.StatusOK)
		}
		writeJSON(map[string]any{})

	case p == "/v1/sys/seal-status" && r.Method == http.MethodGet:
		writeJSON(f.sealStateJSON())

	case p == "/v1/sys/init" && r.Method == http.MethodGet:
		writeJSON(map[string]any{"initialized": f.initialized})

	case p == "/v1/sys/init" && r.Method == http.MethodPut:
		var conf struct {
			Shares    int `json:"secret_shares"`
			Threshold int `json:"secret_threshold"`
		}
		_ = json.NewDecoder(r.Body).Decode(&conf)
		f.initialized = true
		f.shares = conf.Shares
		f.threshold = conf.Threshold
		if f.rootToken == "" {
			f.rootToken = "root-test-token"
		}
		keys := f.initKeys
		if keys == nil {
			keys = make([]string, conf.Shares)
			for i := range keys {
				keys[i] = "init-key-" + string(rune('A'+i))
			}
		}
		writeJSON(map[string]any{
			"keys":        keys,
			"keys_base64": keys,
			"root_token":  f.rootToken,
		})

	case p == "/v1/sys/seal" && r.Method == http.MethodPut:
		f.sealed = true
		f.progress = 0
		w.WriteHeader(http.StatusNoContent)

	case p == "/v1/sys/unseal" && r.Method == http.MethodPut:
		var body struct {
			Key   string `json:"key"`
			Reset bool   `json:"reset"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Reset {
			f.progress = 0
			writeJSON(f.sealStateJSON())
			return
		}
		f.progress++
		if f.threshold > 0 && f.progress >= f.threshold {
			f.sealed = false
			f.progress = 0
		}
		writeJSON(f.sealStateJSON())

	case p == "/v1/sys/rekey/init" && r.Method == http.MethodDelete:
		f.rekeyActive = false
		f.rekeyProgress = 0
		w.WriteHeader(http.StatusNoContent)

	case p == "/v1/sys/rekey/init" && r.Method == http.MethodPut:
		var conf struct {
			Shares    int `json:"secret_shares"`
			Threshold int `json:"secret_threshold"`
		}
		_ = json.NewDecoder(r.Body).Decode(&conf)
		f.rekeyActive = true
		f.rekeyNonce = "rekey-nonce"
		f.rekeyProgress = 0
		f.rekeyShares = conf.Shares
		if f.rekeyRequired == 0 {
			f.rekeyRequired = f.threshold
		}
		w.WriteHeader(http.StatusNoContent)

	case p == "/v1/sys/rekey/init" && r.Method == http.MethodGet:
		writeJSON(map[string]any{
			"started":  f.rekeyActive,
			"nonce":    f.rekeyNonce,
			"t":        f.threshold,
			"n":        f.rekeyShares,
			"progress": f.rekeyProgress,
			"required": f.rekeyRequired,
			"backup":   false,
		})

	case p == "/v1/sys/rekey/update" && r.Method == http.MethodPut:
		f.rekeyProgress++
		if f.rekeyProgress >= f.rekeyRequired {
			keys := f.rekeyNewKeys
			if keys == nil {
				keys = make([]string, f.rekeyShares)
				for i := range keys {
					keys[i] = "rekey-key-" + string(rune('A'+i))
				}
			}
			f.rekeyActive = false
			f.rekeyProgress = 0
			writeJSON(map[string]any{
				"complete":    true,
				"keys":        keys,
				"keys_base64": keys,
				"nonce":       f.rekeyNonce,
			})
			return
		}
		writeJSON(map[string]any{
			"started":  true,
			"nonce":    f.rekeyNonce,
			"progress": f.rekeyProgress,
			"required": f.rekeyRequired,
		})

	default:
		jsonErr(w, http.StatusNotFound, "unhandled sys path: "+p)
	}
}

// newTestVault creates a fake Vault HTTP server and returns a configured
// *vault.Vault pointing at it, plus the fakeVault for state inspection.
// The server is closed at the end of t.
func newTestVault(t *testing.T) (*vault.Vault, *fakeVault) {
	t.Helper()
	fv := newFakeVault()
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}

	v, err := vault.NewVault(vault.VaultConfig{
		URL:   u.String(),
		Token: "test-token",
	})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	// Point the client at the test server URL exactly (NewVault may add a port).
	if err := v.SetURL(u.String()); err != nil {
		t.Fatalf("SetURL: %v", err)
	}

	return v, fv
}

// mustGetSecret calls fv.get and fatals if the path is absent.
func mustGetSecret(t *testing.T, fv *fakeVault, path string) map[string]string {
	t.Helper()
	kv := fv.get(path)
	if kv == nil {
		t.Fatalf("mustGetSecret: no secret at %q", path)
	}
	return kv
}

// secretAbsent fatals if a secret exists at path.
func secretAbsent(t *testing.T, fv *fakeVault, path string) {
	t.Helper()
	if kv := fv.get(path); kv != nil {
		t.Fatalf("secretAbsent: unexpected secret at %q: %v", path, kv)
	}
}

// assertSecretNotFound fatals if err is not a SecretNotFound error.
func assertSecretNotFound(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected SecretNotFound error, got nil")
	}
	if !vault.IsSecretNotFound(err) {
		t.Fatalf("expected SecretNotFound error, got: %v", err)
	}
}

// assertKeyNotFound fatals if err is not a KeyNotFound error.
func assertKeyNotFound(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected KeyNotFound error, got nil")
	}
	if !vault.IsKeyNotFound(err) {
		t.Fatalf("expected KeyNotFound error, got: %v", err)
	}
}

// suppress vaultkv import used only for type reference
var _ = vaultkv.KVVersion{}
