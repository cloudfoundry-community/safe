package cli

// A fake Vault that command handlers can actually reach. connect() builds its
// client from VAULT_ADDR and VAULT_TOKEN (cli.go), so an httptest server plus
// t.Setenv is enough to drive a command end to end without a real Vault.
//
// Call newCLIFake after isolateHome: isolateHome clears VAULT_ADDR and
// VAULT_TOKEN, which would undo the values set here.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// cliFakeVault serves a minimal KV API: mount discovery plus GET, PUT, DELETE
// and LIST under /v1/secret/. Paths are stored verbatim, so a secret name
// containing a colon round-trips unchanged.
//
// It speaks either KV version. newCLIFake gives a version 1 mount, which is
// what most tests want; newCLIFakeV2 gives a version 2 mount, which keeps a
// version history per path and is the only way to reach the code behind
// versions, undelete, revert, and a versioned get. Real Vault defaults to
// version 2, so behaviour that only exists there was previously untestable.
type cliFakeVault struct {
	mu sync.Mutex
	//data is the version 1 store: path to key/value pairs.
	data map[string]map[string]string
	//versions is the version 2 store: path to its version history, oldest
	// first. Version N is at index N-1; entries are never removed, since a
	// destroyed version still occupies its number.
	versions map[string][]*fakeVersion
	v2       bool
	//log holds every request served, as "METHOD /path?query", oldest first.
	// What a command asks the Vault for is part of its behaviour: a listing
	// that reads each secret to find out whether it is there hands back
	// plaintext it never prints, and a flag that promises to skip a lookup
	// has to actually skip it. Neither shows up in the output.
	log []string
	//forbidMetadataGet names version 2 paths whose metadata GET (not list)
	// answers 403, for tests simulating a token without metadata-read
	// capability. See denyMetadataGet.
	forbidMetadataGet map[string]bool
}

// fakeVersion is one version of a version 2 secret. A version is alive until
// it is deleted, which is reversible, or destroyed, which is not.
type fakeVersion struct {
	data      map[string]string
	createdAt time.Time
	deletedAt *time.Time
	destroyed bool
}

func (f *cliFakeVault) kvVersion() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.v2 {
		return 2
	}
	return 1
}

// record notes one served request. It takes the lock and releases it before
// the handlers take it themselves.
func (f *cliFakeVault) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, r.Method+" "+r.URL.RequestURI())
}

// requests returns a copy of the log.
func (f *cliFakeVault) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

// forgetRequests empties the log, so one test can measure two commands.
func (f *cliFakeVault) forgetRequests() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = nil
}

func (f *cliFakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts") {
		//The client looks for the mount under data.secret; anything else
		// decodes to an empty map and is reported as version 1 by default.
		_, _ = fmt.Fprintf(w,
			`{"data":{"secret":{"secret/":{"type":"kv","options":{"version":"%d"}}}}}`,
			f.kvVersion())
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v1/secret/") {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
		return
	}

	if f.kvVersion() == 2 {
		f.serveV2(w, r)
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
