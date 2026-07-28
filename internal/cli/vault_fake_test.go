package cli

// A fake Vault that command handlers can actually reach. connect() builds its
// client from VAULT_ADDR and VAULT_TOKEN (cli.go), so an httptest server plus
// t.Setenv is enough to drive a command end to end without a real Vault.
//
// Call newCLIFake after isolateHome: isolateHome clears VAULT_ADDR and
// VAULT_TOKEN, which would undo the values set here.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// cliFakeVault serves a minimal KV v1 API: mount discovery plus GET, PUT,
// DELETE and LIST under /v1/secret/. Paths are stored verbatim, so a secret
// name containing a colon round-trips unchanged.
type cliFakeVault struct {
	mu   sync.Mutex
	data map[string]map[string]string
}

func (f *cliFakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts") {
		_, _ = w.Write([]byte(`{"data":{"secret/":{"type":"kv","options":{"version":"1"}}}}`))
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v1/secret/") {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case r.URL.Query().Get("list") == "true":
		keys := f.childrenOf(path)
		if len(keys) == 0 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"keys": keys}})

	case r.Method == http.MethodPut || r.Method == http.MethodPost:
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":["malformed body"]}`))
			return
		}
		f.data[path] = body
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete:
		delete(f.data, path)
		w.WriteHeader(http.StatusNoContent)

	default:
		kv, ok := f.data[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": kv})
	}
}

// childrenOf returns the immediate children of a directory, with a trailing
// slash on those that are themselves directories. Callers hold f.mu.
func (f *cliFakeVault) childrenOf(dir string) []string {
	seen := map[string]bool{}
	keys := []string{}
	for stored := range f.data {
		rest, ok := strings.CutPrefix(stored, dir+"/")
		if !ok {
			continue
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i+1]
		}
		if !seen[rest] {
			seen[rest] = true
			keys = append(keys, rest)
		}
	}
	return keys
}

// newCLIFake starts a fake Vault and points VAULT_ADDR and VAULT_TOKEN at it.
func newCLIFake(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := &cliFakeVault{data: map[string]map[string]string{}}
	srv := httptest.NewServer(fv)
	t.Cleanup(srv.Close)
	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")
	return fv
}

// set stores a secret at a literal Vault path.
func (f *cliFakeVault) set(path string, kv map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[path] = kv
}

// get returns the secret at a literal Vault path, or nil if it is absent.
func (f *cliFakeVault) get(path string) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data[path]
}
