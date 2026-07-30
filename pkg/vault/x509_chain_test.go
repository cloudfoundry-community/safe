package vault_test

// A certificate attribute can hold the issuers above the certificate as well
// as the certificate itself, and safe reads them: `x509 show` lists them under
// "via". Writing the secret back kept only the leading certificate, so every
// command that saves a certificate — issuing under a CA, revoking, renewing,
// regenerating a revocation list — silently dropped the rest of the chain.

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// chained builds an intermediate CA below a root and returns it as safe would
// read it back from a secret whose certificate attribute holds both.
func chained(t *testing.T) (*vault.X509, *vault.X509) {
	t.Helper()

	root := signingCA(t)
	inter, err := vault.NewCertificate("CN=inter", []string{"inter"},
		[]string{"key_cert_sign", "crl_sign"}, "",
		vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	inter.MakeCA()
	if err := root.Sign(inter, 24*time.Hour); err != nil {
		t.Fatalf("sign the intermediate: %v", err)
	}

	s, err := inter.Secret(false)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	rootPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: root.Certificate.Raw,
	}))
	if err := s.Set("certificate", s.Get("certificate")+rootPEM, false); err != nil {
		t.Fatalf("append the root: %v", err)
	}

	read, err := s.X509(true)
	if err != nil {
		t.Fatalf("read the chained secret back: %v", err)
	}
	return read, root
}

// certificates returns the subjects of every certificate in a PEM bundle, in
// the order they appear.
func certificates(t *testing.T, bundle string) []string {
	t.Helper()

	subjects := []string{}
	rest := []byte(bundle)
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse a certificate out of the bundle: %v", err)
		}
		subjects = append(subjects, c.Subject.CommonName)
	}
	return subjects
}

// Saving a certificate keeps the issuers stored with it.
func TestSavingACertificateKeepsItsChain(t *testing.T) {
	inter, _ := chained(t)

	s, err := inter.Secret(false)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}

	got := certificates(t, s.Get("certificate"))
	want := []string{"inter", "crl-ca"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("certificate holds %v, want %v", got, want)
	}
}

// The combined attribute carries the same chain, since it is the certificate
// attribute with the key appended.
func TestTheCombinedAttributeKeepsTheChainToo(t *testing.T) {
	inter, _ := chained(t)

	s, err := inter.Secret(false)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}

	got := certificates(t, s.Get("combined"))
	want := []string{"inter", "crl-ca"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("combined holds %v, want %v", got, want)
	}
	if !strings.Contains(s.Get("combined"), "PRIVATE KEY") {
		t.Error("combined lost the private key")
	}
}

// A certificate stored on its own still writes out on its own.
func TestSavingACertificateWithNoChainAddsNothing(t *testing.T) {
	ca := signingCA(t)

	s, err := ca.Secret(false)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}

	got := certificates(t, s.Get("certificate"))
	if len(got) != 1 || got[0] != "crl-ca" {
		t.Errorf("certificate holds %v, want [crl-ca]", got)
	}
}
