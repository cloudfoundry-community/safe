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
	"regexp"
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
	//forbidGet names paths whose read answers 403, for tests that need a
	// read to fail for a reason other than the secret not being there. See
	// denyGet.
	forbidGet map[string]bool
	//forbidDelete names paths whose DELETE answers 403, for tests that need
	// one path of a recursive delete to fail for a reason --force must not
	// swallow. See denyDelete.
	forbidDelete map[string]bool
	//forbidPut names paths whose write answers 403, for tests that need one
	// write of a parallel batch to fail while its siblings land. See denyPut.
	forbidPut map[string]bool

	// gate, when non-nil, parks every request matching its pattern before
	// dispatch. Installed by holdRequests. The pointer itself is guarded by
	// f.mu, but parking happens on the gate's own lock -- never f.mu -- so a
	// parked request can never deadlock the fake against itself.
	gate *requestGate

	// t is the test that built this fakeVault, captured so holdRequests can
	// register a Cleanup that force-releases a gate nobody ever tripped.
	t *testing.T
}

// requestGate parks the first `need` matching requests until all of them
// have arrived, then releases every one of them at once by closing release.
// Closing a channel wakes every blocked receiver at once, so the gate needs
// no separate condition variable; `mu` only protects the bookkeeping
// (arrived, tripped) around that close, independent of the cliFakeVault's
// f.mu, so a goroutine parked in park (blocked on <-release) holds no lock
// ServeHTTP needs elsewhere.
type requestGate struct {
	pattern *regexp.Regexp
	need    int

	mu      sync.Mutex
	arrived int
	tripped bool
	release chan struct{}
}

// holdRequests installs a gate so requests whose logged "METHOD path[?query]"
// line matches pattern park until n of them are concurrently in flight, then
// releases them all and closes the returned channel.
//
// n <= 0 trips the gate immediately, so every match passes straight
// through. Replacing an existing gate first force-releases any requests
// still parked on it, so a second call never orphans a waiter.
//
// A test that never drives n matching requests concurrently would park its
// handler goroutines on `release` forever, which would in turn hang
// httptest.Server.Close() in t.Cleanup past the test's own deadline. To
// keep that failure mode bounded, holdRequests registers its own
// t.Cleanup that force-releases this gate if it never tripped.
func (f *cliFakeVault) holdRequests(n int, pattern string) <-chan struct{} {
	g := &requestGate{
		pattern: regexp.MustCompile(pattern),
		need:    n,
		release: make(chan struct{}),
	}
	if n <= 0 {
		g.tripped = true
		close(g.release)
	}

	f.mu.Lock()
	prev := f.gate
	f.gate = g
	f.mu.Unlock()

	if prev != nil {
		prev.forceRelease()
	}
	if f.t != nil {
		f.t.Cleanup(g.forceRelease)
	}

	return g.release
}

// forceRelease closes release if the gate has not already tripped,
// unblocking any goroutines parked in park. Safe to call more than once,
// concurrently, and from any goroutine.
func (g *requestGate) forceRelease() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.tripped {
		g.tripped = true
		close(g.release)
	}
}

// park blocks the calling goroutine until `need` goroutines have called
// park (tripping the gate) or forceRelease has fired, whichever comes first.
func (g *requestGate) park() {
	g.mu.Lock()
	if !g.tripped {
		g.arrived++
		if g.arrived >= g.need {
			g.tripped = true
			close(g.release)
		}
	}
	g.mu.Unlock()

	<-g.release
}

// denyGet makes a read of path answer 403, simulating a token without read
// capability on it. A secret that is absent and a secret that cannot be
// looked at are different answers, and commands that treat "not there" as
// permission to proceed have to tell them apart.
func (f *cliFakeVault) denyGet(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forbidGet == nil {
		f.forbidGet = map[string]bool{}
	}
	f.forbidGet[path] = true
}

// denyPut makes a write of path answer 403, so one write of a parallel
// batch can fail while the writes beside it land.
func (f *cliFakeVault) denyPut(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forbidPut == nil {
		f.forbidPut = map[string]bool{}
	}
	f.forbidPut[path] = true
}

// denyDelete makes a DELETE of path answer 403, so one path of a recursive
// delete can fail for a reason other than the secret not being there.
func (f *cliFakeVault) denyDelete(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forbidDelete == nil {
		f.forbidDelete = map[string]bool{}
	}
	f.forbidDelete[path] = true
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

	// Copy the gate pointer out under f.mu, then park (if it matches) on the
	// gate's own lock. Parking never happens while holding f.mu, so a parked
	// request cannot block any other request's dispatch or logging.
	f.mu.Lock()
	gate := f.gate
	f.mu.Unlock()
	if gate != nil && gate.pattern.MatchString(r.Method+" "+r.URL.RequestURI()) {
		gate.park()
	}

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
		if f.forbidPut[path] {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(w, `{"errors":["permission denied: %s"]}`, path)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":["malformed body"]}`))
			return
		}
		f.data[path] = body
		w.WriteHeader(http.StatusNoContent)

	case r.Method == http.MethodDelete:
		if f.forbidDelete[path] {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(w, `{"errors":["permission denied: %s"]}`, path)
			return
		}
		delete(f.data, path)
		w.WriteHeader(http.StatusNoContent)

	default:
		if f.forbidGet[path] {
			// The denied path rides in the body so a test collecting
			// several failures can tell them apart: vaultkv folds the
			// body's errors array into ErrForbidden's message.
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(w, `{"errors":["permission denied: %s"]}`, path)
			return
		}
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
	fv := &cliFakeVault{data: map[string]map[string]string{}, t: t}
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
