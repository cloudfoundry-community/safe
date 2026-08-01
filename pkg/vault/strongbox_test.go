// Strongbox asks the strongbox agent beside the Vault for the seal state of
// every node. The agent's port is fixed: StrongboxURL keeps only the host of
// the Vault URL and always appends :8484, so the only way to stand in for it
// is to actually listen there. The test binds 127.0.0.1:8484 -- the host a
// fake Vault answers on -- and skips if the port is taken, rather than fail
// on a machine that runs a real strongbox or anything else there.
//
// The subtests share that one listener and must not run in parallel with
// each other; there is only one port 8484.

package vault_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestStrongbox(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:8484")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.1:8484, the one port Strongbox calls: %s", err)
	}

	//The handler swaps per subtest; the mutex keeps the swap and the serving
	// goroutine's read apart.
	var mu sync.Mutex
	var respond func(w http.ResponseWriter)
	serve := func(fn func(w http.ResponseWriter)) {
		mu.Lock()
		defer mu.Unlock()
		respond = fn
	}

	srv := &httptest.Server{
		Listener: ln,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/strongbox" {
				http.NotFound(w, r)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			respond(w)
		})},
	}
	srv.Start()
	t.Cleanup(srv.Close)

	//The fake Vault also answers on 127.0.0.1, so the strongbox derived from
	// its URL is the server above.
	v, _ := newTestVault(t)

	t.Run("reports each node's seal state", func(t *testing.T) {
		serve(func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"10.0.0.1":"sealed","10.0.0.2":"unsealed"}`))
		})

		m, err := v.Strongbox()
		if err != nil {
			t.Fatalf("Strongbox: %v", err)
		}
		if len(m) != 2 || m["10.0.0.1"] != "sealed" || m["10.0.0.2"] != "unsealed" {
			t.Errorf("Strongbox = %v, want the two nodes and their states", m)
		}
	})

	t.Run("a non-200 answer names the code and the URL", func(t *testing.T) {
		serve(func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		_, err := v.Strongbox()
		if err == nil {
			t.Fatal("Strongbox returned nil for a 500")
		}
		for _, want := range []string{"500", "http://127.0.0.1:8484/strongbox"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should mention %q", err, want)
			}
		}
	})

	t.Run("an unparseable answer is an error", func(t *testing.T) {
		serve(func(w http.ResponseWriter) {
			_, _ = w.Write([]byte("not json"))
		})

		if _, err := v.Strongbox(); err == nil {
			t.Fatal("Strongbox returned nil for a body that is not JSON")
		}
	})
}
