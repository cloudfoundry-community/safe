// FindSigningCA picks the authority for every x509 command that signs:
// named explicitly with --signed-by it must exist and be a CA; left unnamed,
// a self-signed certificate answers for itself, and otherwise the `ca`
// sibling is tried - but only accepted when it actually signed the
// certificate, since renewing under a stranger would silently change the
// issuer.

package vault_test

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// reparse swaps the in-memory template for the certificate as signed.
// FindSigningCA checks signatures from the parsed fields, and every
// certificate it meets in earnest was read back out of the Vault, where
// those fields are always filled in.
func reparse(t *testing.T, x *vault.X509) {
	t.Helper()
	parsed, err := x509.ParseCertificate(x.Certificate.Raw)
	if err != nil {
		t.Fatalf("parse the signed certificate: %v", err)
	}
	x.Certificate = parsed
}

// caNamed builds a self-signed CA. ed25519 keeps the many certificates
// these tests mint cheap.
func caNamed(t *testing.T, cn string) *vault.X509 {
	t.Helper()
	ca, err := vault.NewCertificate("CN="+cn, []string{cn},
		[]string{"key_cert_sign", "crl_sign"}, "",
		vault.KeySpec{Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	ca.MakeCA()
	if err := ca.Sign(ca, 24*time.Hour); err != nil {
		t.Fatalf("self-sign %s: %v", cn, err)
	}
	reparse(t, ca)
	return ca
}

// leafSignedBy builds a non-CA certificate signed by the given authority.
func leafSignedBy(t *testing.T, ca *vault.X509) *vault.X509 {
	t.Helper()
	leaf, err := vault.NewCertificate("CN=leaf", []string{"leaf"},
		[]string{"digital_signature"}, "",
		vault.KeySpec{Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	if err := ca.Sign(leaf, 24*time.Hour); err != nil {
		t.Fatalf("sign the leaf: %v", err)
	}
	reparse(t, leaf)
	return leaf
}

// writeCert stores a certificate where the Vault under test can read it.
func writeCert(t *testing.T, v *vault.Vault, path string, x *vault.X509) {
	t.Helper()
	s, err := x.Secret(false)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	if err := v.Write(path, s); err != nil {
		t.Fatalf("Write %s: %v", path, err)
	}
}

// A certificate named as its own authority signs itself; nothing is read.
func TestFindSigningCANamedAsItself(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)
	ca := caNamed(t, "self")

	got, path, err := v.FindSigningCA(ca, "secret/ca", "secret/ca")
	if err != nil {
		t.Fatalf("FindSigningCA: %v", err)
	}
	if got != ca || path != "secret/ca" {
		t.Errorf("returned %v at %q, want the certificate itself at secret/ca", got, path)
	}
}

func TestFindSigningCAReadsANamedAuthority(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)
	ca := caNamed(t, "authority")
	leaf := leafSignedBy(t, ca)
	writeCert(t, v, "secret/ca", ca)

	got, path, err := v.FindSigningCA(leaf, "secret/leaf", "secret/ca")
	if err != nil {
		t.Fatalf("FindSigningCA: %v", err)
	}
	if path != "secret/ca" {
		t.Errorf("path = %q, want secret/ca", path)
	}
	if cn := got.Certificate.Subject.CommonName; cn != "authority" {
		t.Errorf("returned CN %q, want authority", cn)
	}
}

func TestFindSigningCARefusesANamedNonCA(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)
	ca := caNamed(t, "authority")
	leaf := leafSignedBy(t, ca)
	writeCert(t, v, "secret/notca", leafSignedBy(t, ca))

	_, _, err := v.FindSigningCA(leaf, "secret/leaf", "secret/notca")
	if err == nil {
		t.Fatal("FindSigningCA accepted a plain certificate as an authority")
	}
	if !strings.Contains(err.Error(), "secret/notca is not a certificate authority") {
		t.Errorf("error %q should name secret/notca as no authority", err)
	}
}

func TestFindSigningCAReportsAMissingNamedAuthority(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)
	ca := caNamed(t, "authority")
	leaf := leafSignedBy(t, ca)

	_, _, err := v.FindSigningCA(leaf, "secret/leaf", "secret/absent")
	if err == nil {
		t.Fatal("FindSigningCA returned nil for an authority that is not there")
	}
	assertSecretNotFound(t, err)
}

// With no authority named, a self-signed certificate is its own.
func TestFindSigningCAKeepsASelfSignedCert(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)
	ca := caNamed(t, "self")

	got, path, err := v.FindSigningCA(ca, "secret/ca", "")
	if err != nil {
		t.Fatalf("FindSigningCA: %v", err)
	}
	if got != ca || path != "secret/ca" {
		t.Errorf("returned %v at %q, want the certificate itself at secret/ca", got, path)
	}
}

// With no authority named, the `ca` sibling that signed the certificate is
// the guess that gets accepted.
func TestFindSigningCAFindsTheCASibling(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)
	ca := caNamed(t, "sibling")
	leaf := leafSignedBy(t, ca)
	writeCert(t, v, "secret/x/ca", ca)

	got, path, err := v.FindSigningCA(leaf, "secret/x/cert", "")
	if err != nil {
		t.Fatalf("FindSigningCA: %v", err)
	}
	if path != "secret/x/ca" {
		t.Errorf("path = %q, want secret/x/ca", path)
	}
	if cn := got.Certificate.Subject.CommonName; cn != "sibling" {
		t.Errorf("returned CN %q, want sibling", cn)
	}
}

func TestFindSigningCAWithNoSiblingToGuess(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)
	ca := caNamed(t, "authority")
	leaf := leafSignedBy(t, ca)

	_, _, err := v.FindSigningCA(leaf, "secret/x/cert", "")
	if err == nil {
		t.Fatal("FindSigningCA guessed an authority out of nothing")
	}
	if !strings.Contains(err.Error(), "no signing authority provided and no 'ca' sibling found") {
		t.Errorf("error %q should say no authority was found", err)
	}
}

// A sibling that is not the issuer is rejected: signing under it would hand
// back a certificate with a different issuer than it went in with.
func TestFindSigningCARefusesAStrangerSibling(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)
	issuer := caNamed(t, "issuer")
	stranger := caNamed(t, "stranger")
	leaf := leafSignedBy(t, issuer)
	writeCert(t, v, "secret/x/ca", stranger)

	_, _, err := v.FindSigningCA(leaf, "secret/x/cert", "")
	if err == nil {
		t.Fatal("FindSigningCA accepted a sibling that did not sign the certificate")
	}
	if !strings.Contains(err.Error(), "--signed-by") {
		t.Errorf("error %q should point at --signed-by", err)
	}
}

// A CA rotated to a fresh key (what `safe x509 reissue secret/env/ca`
// ordinarily does) keeps its Subject; every leaf issued under the old key no
// longer verifies against the new one cryptographically, but the sibling is
// still the right authority to renew or reissue under. FindSigningCA has to
// accept it, or the ordinary rotation workflow is blocked for every leaf
// underneath.
func TestFindSigningCAAcceptsARotatedSibling(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)
	oldCA := caNamed(t, "authority")
	newCA := caNamed(t, "authority") // same subject, fresh key: a rotation
	leaf := leafSignedBy(t, oldCA)
	writeCert(t, v, "secret/x/ca", newCA)

	got, path, err := v.FindSigningCA(leaf, "secret/x/cert", "")
	if err != nil {
		t.Fatalf("FindSigningCA: %v", err)
	}
	if path != "secret/x/ca" {
		t.Errorf("path = %q, want secret/x/ca", path)
	}
	if !bytes.Equal(got.Certificate.Raw, newCA.Certificate.Raw) {
		t.Error("FindSigningCA did not return the current (rotated) sibling")
	}
}

func TestFindSigningCARefusesANonCASibling(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)
	ca := caNamed(t, "authority")
	leaf := leafSignedBy(t, ca)
	writeCert(t, v, "secret/x/ca", leafSignedBy(t, ca))

	_, _, err := v.FindSigningCA(leaf, "secret/x/cert", "")
	if err == nil {
		t.Fatal("FindSigningCA accepted a plain certificate sibling as an authority")
	}
	if !strings.Contains(err.Error(), "secret/x/ca is not a certificate authority") {
		t.Errorf("error %q should name secret/x/ca as no authority", err)
	}
}
