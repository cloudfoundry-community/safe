package vault_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// The request log is the measuring instrument for every request-count
// regression test in this suite: it records "METHOD /v1/<path>[?query]"
// per request.
func TestFakeVaultCountsRequests(t *testing.T) {
	v, fv := newTestVault(t)
	fv.set("secret/a", map[string]string{"k": "v"})

	if _, err := v.Read("secret/a"); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if _, err := v.List("secret"); err != nil {
		t.Fatalf("List: %v", err)
	}

	if got := fv.requestCount(`^GET /v1/secret/a$`); got != 1 {
		t.Errorf("data reads = %d, want 1", got)
	}
	if got := fv.requestCount(`^GET /v1/sys/internal/ui/mounts`); got != 1 {
		t.Errorf("mount lookups = %d, want 1", got)
	}
	// v1 LIST arrives as ?list=true; the query must be visible in the log.
	if got := fv.requestCount(`^GET /v1/secret\?list=true$`); got != 1 {
		t.Errorf("list requests with query = %d, want 1", got)
	}

	fv.resetRequestLog()
	if got := fv.requestCount(`.`); got != 0 {
		t.Errorf("after reset, %d requests logged, want 0", got)
	}
}

// A 404 from Vault must not cost safe's client its keep-alive connection:
// reading a missing secret in between two successful reads must not open a
// second TCP connection. fv's request log has no visibility into
// connections, and newTestVault offers no ConnState hook, so this test
// builds its own server directly on the fakeVault handler and chains a
// ConnState counter before Start() -- assigning ConnState after NewServer
// would clobber httptest's own hook, which Close depends on.
func TestSafeKeepsConnectionAliveAcrossNotFound(t *testing.T) {
	fv := newFakeVault()
	fv.t = t
	fv.set("secret/a", map[string]string{"k": "v"})

	srv := httptest.NewUnstartedServer(fv)
	var newConns atomic.Int64
	base := srv.Config.ConnState
	srv.Config.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew {
			newConns.Add(1)
		}
		if base != nil {
			base(c, s)
		}
	}
	srv.Start()
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
	if err := v.SetURL(u.String()); err != nil {
		t.Fatalf("SetURL: %v", err)
	}

	if _, err := v.Read("secret/a"); err != nil {
		t.Fatalf("Read secret/a (1st): %v", err)
	}
	if _, err := v.Read("secret/missing"); !vault.IsNotFound(err) {
		t.Fatalf("Read secret/missing: want IsNotFound, got %v", err)
	}
	if _, err := v.Read("secret/a"); err != nil {
		t.Fatalf("Read secret/a (2nd): %v", err)
	}

	if got := newConns.Load(); got != 1 {
		t.Errorf("requests used %d connections, want 1", got)
	}
}
