package vault_test

// A certificate's serial number is what a revocation list refers to it by,
// so it has to belong to the certificate. Signing handed out the CA's own
// counter by reference, which meant the number a signed certificate reported
// changed under it the next time the CA signed anything — and a revocation
// entry recorded from it changed with it.

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// signLeaf issues a certificate from ca.
func signLeaf(t *testing.T, ca *vault.X509, cn string) *vault.X509 {
	t.Helper()
	leaf, err := vault.NewCertificate("CN="+cn, []string{cn},
		[]string{"server_auth"}, "", vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate(%s): %v", cn, err)
	}
	if err := ca.Sign(leaf, time.Hour); err != nil {
		t.Fatalf("sign %s: %v", cn, err)
	}
	return leaf
}

// derSerial reads the serial number out of the signed bytes, which is the
// number anyone verifying the certificate will see.
func derSerial(t *testing.T, x *vault.X509) *big.Int {
	t.Helper()
	cert, err := x509.ParseCertificate(x.Certificate.Raw)
	if err != nil {
		t.Fatalf("parse the signed certificate: %v", err)
	}
	return cert.SerialNumber
}

// Issuing a second certificate leaves the first one's serial alone.
func TestASignedCertificateKeepsItsSerialNumber(t *testing.T) {
	ca := signingCA(t)
	first := signLeaf(t, ca, "first")
	want := derSerial(t, first)

	signLeaf(t, ca, "second")

	if got := first.Certificate.SerialNumber; got.Cmp(want) != 0 {
		t.Errorf("the first certificate reports serial %s after a second was issued, want %s", got, want)
	}
}

// Two certificates from one authority get two different numbers.
func TestOneCAIssuesDistinctSerialNumbers(t *testing.T) {
	ca := signingCA(t)
	first := signLeaf(t, ca, "first")
	second := signLeaf(t, ca, "second")

	if first.Certificate.SerialNumber.Cmp(second.Certificate.SerialNumber) == 0 {
		t.Errorf("both certificates report serial %s", first.Certificate.SerialNumber)
	}
}

// A revocation names the certificate it was recorded for, and goes on naming
// it after the CA issues more.
func TestARevocationEntryKeepsNamingTheRevokedCertificate(t *testing.T) {
	ca := signingCA(t)
	revoked := signLeaf(t, ca, "revoked")
	want := derSerial(t, revoked)

	ca.Revoke(revoked)
	later := signLeaf(t, ca, "later")

	entries := ca.CRL.RevokedCertificateEntries
	if len(entries) != 1 {
		t.Fatalf("the CRL holds %d entries, want 1", len(entries))
	}
	if got := entries[0].SerialNumber; got.Cmp(want) != 0 {
		t.Errorf("the CRL now names serial %s, want %s", got, want)
	}
	if entries[0].SerialNumber.Cmp(later.Certificate.SerialNumber) == 0 {
		t.Error("the CRL names the certificate issued after the revocation")
	}
}
