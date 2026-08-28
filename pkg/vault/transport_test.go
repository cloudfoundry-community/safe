package vault_test

import (
	"net/http"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func TestTransportIsTuned(t *testing.T) {
	// NewVault consults the proxy environment; a developer shell with
	// SAFE_ALL_PROXY=ssh+socks5://... would dial a tunnel here.
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "SAFE_ALL_PROXY", "safe_all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	v, err := vault.NewVault(vault.VaultConfig{URL: "https://127.0.0.1:1", Token: "x"})
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	tr, ok := v.Client().Client.Client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", v.Client().Client.Client.Transport)
	}
	if tr.TLSClientConfig.ClientSessionCache == nil {
		t.Error("no TLS session cache: every handshake is a full handshake")
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("HTTP/2 not enabled")
	}
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("no TLS handshake timeout")
	}
	if tr.DialContext == nil {
		t.Error("no dialer: no dial timeout, no TCP keepalive")
	}
	if tr.IdleConnTimeout == 0 {
		t.Error("idle connections never expire")
	}
}
