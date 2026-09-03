package rc

import (
	"path/filepath"
	"testing"
)

// The bytes safe writes to ~/.saferc and ~/.svtoken are consumed by other
// tools (Genesis reads ~/.svtoken) and by earlier safe releases. They must
// not drift when the YAML library changes.
func TestWriteGoldenBytes(t *testing.T) {
	home := setHome(t)
	c := Config{
		Version: 1,
		Current: "prod",
		Vaults: map[string]*Vault{
			"prod": {
				URL:        "https://vault.prod:8200",
				Token:      "prod-token",
				CACerts:    []string{"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"},
				SkipVerify: true,
				Namespace:  "ns",
			},
			"dev": {URL: "http://127.0.0.1:8200", Token: ""},
		},
		Options: Options{ManageVaultToken: false},
	}
	if err := c.write(); err != nil {
		t.Fatalf("write: %s", err)
	}

	wantRC := `version: 1
current: prod
vaults:
  dev:
    url: http://127.0.0.1:8200
    token: ""
  prod:
    url: https://vault.prod:8200
    token: prod-token
    ca_certs:
    - |
      -----BEGIN CERTIFICATE-----
      MIIB
      -----END CERTIFICATE-----
    skip_verify: true
    namespace: ns
options:
  manage_vault_token: false
`
	if got := readFile(t, filepath.Join(home, ".saferc")); got != wantRC {
		t.Errorf(".saferc bytes changed:\n--- got\n%s--- want\n%s", got, wantRC)
	}

	wantSV := `vault: https://vault.prod:8200
token: prod-token
skip_verify: true
ca_certs: |
  -----BEGIN CERTIFICATE-----
  MIIB
  -----END CERTIFICATE-----
namespace: ns
`
	if got := readFile(t, filepath.Join(home, ".svtoken")); got != wantSV {
		t.Errorf(".svtoken bytes changed:\n--- got\n%s--- want\n%s", got, wantSV)
	}
}
