package vault_test

// Curl hands a request straight to the Vault API, so what it sends is the
// whole of its behaviour. These tests stand up a server that records the
// request line and read it back, rather than asserting on the response.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// recorded is one request a curlServer received.
type recorded struct {
	method string
	path   string
	query  url.Values
	body   string
}

// newCurlVault starts a server that records every request and answers 200,
// and returns a Vault pointed at it alongside the recording.
func newCurlVault(t *testing.T) (*vault.Vault, *recorded) {
	t.Helper()
	got := &recorded{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.method = r.Method
		got.path = r.URL.Path
		got.query = r.URL.Query()
		got.body = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	v, err := vault.NewVault(vault.VaultConfig{URL: srv.URL, Token: "test-token"})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	if err := v.SetURL(srv.URL); err != nil {
		t.Fatalf("SetURL: %v", err)
	}
	return v, got
}

// A query value that is itself a URL holds a pair of slashes that the path
// rules would collapse, and it has to arrive as it was written.
func TestCurlKeepsSlashesInAQueryValue(t *testing.T) {
	t.Parallel()
	v, got := newCurlVault(t)

	res, err := v.Curl("GET", "/sys/x?u=http://example.com/a/b", nil)
	if err != nil {
		t.Fatalf("Curl: %v", err)
	}
	_ = res.Body.Close()

	if u := got.query.Get("u"); u != "http://example.com/a/b" {
		t.Errorf("u = %q, want the URL as written", u)
	}
}

// A trailing slash is dropped from a path and has to be kept in a query.
func TestCurlKeepsATrailingSlashInAQueryValue(t *testing.T) {
	t.Parallel()
	v, got := newCurlVault(t)

	res, err := v.Curl("GET", "/sys/x?dir=foo/", nil)
	if err != nil {
		t.Fatalf("Curl: %v", err)
	}
	_ = res.Body.Close()

	if d := got.query.Get("dir"); d != "foo/" {
		t.Errorf("dir = %q, want foo/", d)
	}
}

// The path is still canonicalized: repeated slashes collapse and a trailing
// one is dropped, whether or not a query follows it.
func TestCurlCanonicalizesThePath(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		uri  string
		want string
	}{
		{"a plain path", "/secret/handshake", "/v1/secret/handshake"},
		{"repeated slashes", "/secret//deep///thing", "/v1/secret/deep/thing"},
		{"a trailing slash", "/secret/dir/", "/v1/secret/dir"},
		{"no leading slash", "secret/handshake", "/v1/secret/handshake"},
		{"a path before a query", "/secret/dir/?list=true", "/v1/secret/dir"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, got := newCurlVault(t)

			res, err := v.Curl("GET", tc.uri, nil)
			if err != nil {
				t.Fatalf("Curl: %v", err)
			}
			_ = res.Body.Close()

			if got.path != tc.want {
				t.Errorf("asked for %q, want %q", got.path, tc.want)
			}
		})
	}
}

// The query survives the path being canonicalized alongside it.
func TestCurlSendsTheQueryWithACanonicalizedPath(t *testing.T) {
	t.Parallel()
	v, got := newCurlVault(t)

	res, err := v.Curl("GET", "/secret//dir/?list=true", nil)
	if err != nil {
		t.Fatalf("Curl: %v", err)
	}
	_ = res.Body.Close()

	if got.path != "/v1/secret/dir" {
		t.Errorf("asked for %q, want /v1/secret/dir", got.path)
	}
	if l := got.query.Get("list"); l != "true" {
		t.Errorf("list = %q, want true", l)
	}
}

func TestCurlSendsTheMethodAndBody(t *testing.T) {
	t.Parallel()
	v, got := newCurlVault(t)

	res, err := v.Curl("PUT", "/secret/handshake", []byte(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("Curl: %v", err)
	}
	_ = res.Body.Close()

	if got.method != "PUT" {
		t.Errorf("method = %q, want PUT", got.method)
	}
	if got.body != `{"k":"v"}` {
		t.Errorf("body = %q, want the JSON it was given", got.body)
	}
}

func TestCurlRejectsAQueryItCannotParse(t *testing.T) {
	t.Parallel()
	v, _ := newCurlVault(t)

	if _, err := v.Curl("GET", "/sys/x?%zz=1", nil); err == nil {
		t.Fatal("expected an error for a query that does not parse")
	}
}
