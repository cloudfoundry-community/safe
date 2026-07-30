package vault_test

// RFC 5280 asks a CA to number each CRL it publishes above the last, and
// safe publishes a new one every time it writes a CA back. The number never
// moved: every CRL safe ever wrote was number one, so a relying party that
// keeps the highest-numbered CRL it has seen had no reason to take a later
// one, including the one carrying a revocation.

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// signingCA builds a self-signed CA that can sign certificates and CRLs.
func signingCA(t *testing.T) *vault.X509 {
	t.Helper()
	ca, err := vault.NewCertificate("CN=crl-ca", []string{"crl-ca"},
		[]string{"key_cert_sign", "crl_sign"}, "",
		vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	ca.MakeCA()
	if err := ca.Sign(ca, 24*time.Hour); err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	return ca
}

// publish writes the CA out and returns the number of the CRL it published,
// along with the secret it wrote.
func publish(t *testing.T, ca *vault.X509) (int64, *vault.Secret) {
	t.Helper()
	s, err := ca.Secret(false)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	block, _ := pem.Decode([]byte(s.Get("crl")))
	if block == nil {
		t.Fatal("the CA secret holds no CRL")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	return crl.Number.Int64(), s
}

// Successive publications of one CA carry rising numbers, starting at one.
func TestEachPublishedCRLIsNumberedAboveTheLast(t *testing.T) {
	ca := signingCA(t)

	for want := int64(1); want <= 3; want++ {
		if got, _ := publish(t, ca); got != want {
			t.Fatalf("CRL number %d, want %d", got, want)
		}
	}
}

// The sequence survives a trip through the Vault: safe reads the CA back
// between commands, so the number has to come off the stored CRL rather than
// out of a counter held in memory.
func TestTheCRLNumberContinuesAcrossAReadBack(t *testing.T) {
	ca := signingCA(t)

	_, s := publish(t, ca)
	reread, err := s.X509(true)
	if err != nil {
		t.Fatalf("read the CA back: %v", err)
	}

	if got, _ := publish(t, reread); got != 2 {
		t.Errorf("CRL number after a read-back is %d, want 2", got)
	}
}

// The point of the numbering: the CRL that carries a revocation outranks the
// one published before it.
func TestARevocationPublishesAHigherNumberedCRL(t *testing.T) {
	ca := signingCA(t)
	leaf, err := vault.NewCertificate("CN=leaf", []string{"leaf"},
		[]string{"server_auth"}, "", vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	if err := ca.Sign(leaf, time.Hour); err != nil {
		t.Fatalf("sign leaf: %v", err)
	}

	before, _ := publish(t, ca)
	ca.Revoke(leaf)
	after, s := publish(t, ca)

	if after <= before {
		t.Errorf("CRL number went %d -> %d, want it to rise", before, after)
	}
	if !s.Has("crl") {
		t.Fatal("the CA secret holds no CRL")
	}
}
