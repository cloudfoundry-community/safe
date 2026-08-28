package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConnectReusesClientForSameTarget(t *testing.T) {
	isolateHome(t)
	t.Cleanup(resetConnectCache)
	resetConnectCache()
	t.Setenv("VAULT_ADDR", "https://127.0.0.1:1")
	t.Setenv("VAULT_TOKEN", "tok")
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "SAFE_ALL_PROXY", "safe_all_proxy", "NO_PROXY", "no_proxy", "VAULT_CACERT", "VAULT_NAMESPACE", "VAULT_SKIP_VERIFY"} {
		t.Setenv(k, "")
	}

	a, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr: %v", err)
	}
	b, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr (second): %v", err)
	}
	if a != b {
		t.Error("same target produced two clients; chained commands rebuild the transport")
	}

	t.Setenv("VAULT_TOKEN", "other")
	c, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr (new token): %v", err)
	}
	if c == a {
		t.Error("token change did not produce a fresh client")
	}

	t.Setenv("SAFE_ALL_PROXY", "socks5://127.0.0.1:2")
	d, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr (proxy change): %v", err)
	}
	if d == c {
		t.Error("proxy change did not produce a fresh client")
	}
}

// TestConnectCacheKeyHashesCACertContent proves the cache keys VAULT_CACERT
// on the file's content, not its path: rc.Apply writes a fresh temp CA file
// per invocation (pkg/rc/config.go:348-354), so keying on the path would
// mean the cache never hits for exactly the targets it should help.
func TestConnectCacheKeyHashesCACertContent(t *testing.T) {
	isolateHome(t)
	t.Cleanup(resetConnectCache)
	resetConnectCache()
	t.Setenv("VAULT_ADDR", "https://127.0.0.1:1")
	t.Setenv("VAULT_TOKEN", "tok")
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "SAFE_ALL_PROXY", "safe_all_proxy", "NO_PROXY", "no_proxy", "VAULT_NAMESPACE", "VAULT_SKIP_VERIFY"} {
		t.Setenv(k, "")
	}

	dir := t.TempDir()
	pathA1 := filepath.Join(dir, "ca-a-1.pem")
	pathA2 := filepath.Join(dir, "ca-a-2.pem")
	pathB := filepath.Join(dir, "ca-b.pem")
	contentA := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	contentB := []byte("-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n")

	if err := os.WriteFile(pathA1, contentA, 0o600); err != nil {
		t.Fatalf("write %s: %v", pathA1, err)
	}
	if err := os.WriteFile(pathA2, contentA, 0o600); err != nil {
		t.Fatalf("write %s: %v", pathA2, err)
	}
	if err := os.WriteFile(pathB, contentB, 0o600); err != nil {
		t.Fatalf("write %s: %v", pathB, err)
	}

	t.Setenv("VAULT_CACERT", pathA1)
	a, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr (CA content A, path 1): %v", err)
	}

	t.Setenv("VAULT_CACERT", pathA2)
	b, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr (CA content A, path 2): %v", err)
	}
	if a != b {
		t.Error("same CA content at a different path produced a fresh client; the cache key must hash content, not path")
	}

	t.Setenv("VAULT_CACERT", pathB)
	c, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr (CA content B): %v", err)
	}
	if c == b {
		t.Error("different CA content did not produce a fresh client")
	}

	t.Setenv("VAULT_CACERT", "")
	d, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr (no CA cert): %v", err)
	}
	if d == c {
		t.Error("dropping VAULT_CACERT did not produce a fresh client")
	}
}

// TestConnectCacheRestoresMutatedToken proves a cache hit re-syncs the
// cached client's auth token with VAULT_TOKEN before handing it back.
// cmdAuth blanks the shared client's token via SetAuthToken("") so login
// attempts do not send a stale token (internal/cli/target.go), which does
// not change any input the cache key covers, so without this guard the
// `auth status` sub-path would get back a client that sends no token and
// report a working token as invalid.
func TestConnectCacheRestoresMutatedToken(t *testing.T) {
	isolateHome(t)
	t.Cleanup(resetConnectCache)
	resetConnectCache()
	t.Setenv("VAULT_ADDR", "https://127.0.0.1:1")
	t.Setenv("VAULT_TOKEN", "tok")
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "SAFE_ALL_PROXY", "safe_all_proxy", "NO_PROXY", "no_proxy", "VAULT_CACERT", "VAULT_NAMESPACE", "VAULT_SKIP_VERIFY"} {
		t.Setenv(k, "")
	}

	a, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr: %v", err)
	}

	a.Client().Client.SetAuthToken("")

	b, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr (after SetAuthToken mutation): %v", err)
	}
	if got := b.Client().Client.AuthToken; got != "tok" {
		t.Errorf("cached client auth token = %q, want %q (VAULT_TOKEN)", got, "tok")
	}
}

// TestConnectCacheRevalidatesMutatedURL proves a cache hit re-checks the
// cached client's live URL against VAULT_ADDR before handing it back. safe
// unseal/seal mutate a shared client's URL via SetURL to walk cluster nodes
// (internal/cli/server.go), which does not change any input the cache key
// covers, so without this guard a later call would return a client still
// pointed at whatever node it last visited.
func TestConnectCacheRevalidatesMutatedURL(t *testing.T) {
	isolateHome(t)
	t.Cleanup(resetConnectCache)
	resetConnectCache()
	t.Setenv("VAULT_ADDR", "https://127.0.0.1:1")
	t.Setenv("VAULT_TOKEN", "tok")
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "SAFE_ALL_PROXY", "safe_all_proxy", "NO_PROXY", "no_proxy", "VAULT_CACERT", "VAULT_NAMESPACE", "VAULT_SKIP_VERIFY"} {
		t.Setenv(k, "")
	}

	a, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr: %v", err)
	}

	if err := a.SetURL("https://127.0.0.1:2"); err != nil {
		t.Fatalf("SetURL: %v", err)
	}

	b, err := connectOrErr(true)
	if err != nil {
		t.Fatalf("connectOrErr (after SetURL mutation): %v", err)
	}
	if b == a {
		t.Error("a cached client whose URL was mutated via SetURL was handed back instead of rebuilt")
	}
	if got := b.Client().Client.VaultURL.String(); got != "https://127.0.0.1:1" {
		t.Errorf("rebuilt client URL = %q, want https://127.0.0.1:1 (VAULT_ADDR)", got)
	}
}
