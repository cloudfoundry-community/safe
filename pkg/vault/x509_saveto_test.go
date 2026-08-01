package vault_test

// X509.SaveTo (x509.go) is how every x509 command persists a certificate:
// it renders the certificate as a secret and writes it at the given path.
// It had no coverage. Verified against the fake Vault from
// httptest_helper_test.go: a CA lands with its serial and CRL beside the
// certificate, a leaf without them, and a write the Vault refuses surfaces
// as an error instead of vanishing.

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// TestSaveToWritesCASecret verifies saving a CA stores certificate, key,
// and combined entries plus the CA-only serial and crl entries, and that
// the stored certificate is the CA's own.
func TestSaveToWritesCASecret(t *testing.T) {
	t.Parallel()

	v, fv := newTestVault(t)
	ca := signingCA(t)

	if err := ca.SaveTo(v, "secret/x509/ca", false); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	kv := mustGetSecret(t, fv, "secret/x509/ca")
	for _, key := range []string{"certificate", "key", "combined", "serial", "crl"} {
		if kv[key] == "" {
			t.Errorf("stored CA secret has no %q entry", key)
		}
	}

	block, _ := pem.Decode([]byte(kv["certificate"]))
	if block == nil {
		t.Fatal("stored certificate is not a PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse stored certificate: %v", err)
	}
	if got, want := cert.Subject.CommonName, ca.Certificate.Subject.CommonName; got != want {
		t.Errorf("stored certificate CN = %q; want %q", got, want)
	}
}

// TestSaveToLeafOmitsCAEntries verifies a certificate that is not a CA is
// stored without the serial and crl entries only an authority carries.
func TestSaveToLeafOmitsCAEntries(t *testing.T) {
	t.Parallel()

	v, fv := newTestVault(t)
	ca := signingCA(t)
	leaf, err := vault.NewCertificate("CN=leaf", []string{"leaf"},
		[]string{"server_auth"}, "", vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	if err := ca.Sign(leaf, time.Hour); err != nil {
		t.Fatalf("sign leaf: %v", err)
	}

	if err := leaf.SaveTo(v, "secret/x509/leaf", false); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	kv := mustGetSecret(t, fv, "secret/x509/leaf")
	for _, key := range []string{"certificate", "key", "combined"} {
		if kv[key] == "" {
			t.Errorf("stored leaf secret has no %q entry", key)
		}
	}
	for _, key := range []string{"serial", "crl"} {
		if _, ok := kv[key]; ok {
			t.Errorf("stored leaf secret has a %q entry; only a CA should", key)
		}
	}
}

// TestSaveToSurfacesWriteErrors verifies a path the Vault cannot be written
// at — here the path:key notation Write rejects — comes back as an error
// and leaves nothing behind.
func TestSaveToSurfacesWriteErrors(t *testing.T) {
	t.Parallel()

	v, fv := newTestVault(t)
	ca := signingCA(t)

	if err := ca.SaveTo(v, "secret/x509/ca:certificate", false); err == nil {
		t.Fatal("expected an error writing to a path:key path, got nil")
	}
	secretAbsent(t, fv, "secret/x509/ca")
}
