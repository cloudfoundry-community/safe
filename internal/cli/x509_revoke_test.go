package cli

// Revocation happens against a certificate authority: the CA's revocation
// list is the only place a revoked serial number is recorded, and a serial
// number only identifies a certificate within the authority that issued it.
// Neither of those was checked. Naming a path that holds an ordinary
// certificate crashed, and naming a real CA that never signed the certificate
// quietly wrote somebody else's serial onto its list.

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// newCA builds a self-signed certificate authority.
func newCA(t *testing.T, cn string) *vault.X509 {
	t.Helper()
	ca, err := vault.NewCertificate("CN="+cn, []string{cn},
		[]string{"key_cert_sign", "crl_sign"}, "",
		vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate(%s): %v", cn, err)
	}
	ca.MakeCA()
	if err := ca.Sign(ca, 24*time.Hour); err != nil {
		t.Fatalf("self-sign %s: %v", cn, err)
	}
	return ca
}

// newLeaf builds a certificate signed by ca.
func newLeaf(t *testing.T, ca *vault.X509, cn string) *vault.X509 {
	t.Helper()
	leaf, err := vault.NewCertificate("CN="+cn, []string{cn},
		[]string{"server_auth"}, "",
		vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate(%s): %v", cn, err)
	}
	if err := ca.Sign(leaf, time.Hour); err != nil {
		t.Fatalf("sign %s: %v", cn, err)
	}
	return leaf
}

// storeCert writes a certificate to the fake Vault the way safe would.
func storeCert(t *testing.T, fv *cliFakeVault, path string, x *vault.X509) {
	t.Helper()
	s, err := x.Secret(false)
	if err != nil {
		t.Fatalf("Secret for %s: %v", path, err)
	}
	kv := map[string]string{}
	for _, k := range s.Keys() {
		kv[k] = s.Get(k)
	}
	fv.set(path, kv)
}

// revokedSerials returns the serial numbers on the CRL stored at path.
func revokedSerials(t *testing.T, fv *cliFakeVault, path string) []string {
	t.Helper()
	block, _ := pem.Decode([]byte(fv.get(path)["crl"]))
	if block == nil {
		t.Fatalf("%s holds no CRL", path)
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("parse CRL at %s: %v", path, err)
	}
	serials := []string{}
	for _, entry := range crl.RevokedCertificateEntries {
		serials = append(serials, entry.SerialNumber.String())
	}
	return serials
}

// A path holding an ordinary certificate has no revocation list. Reading one
// out of it used to dereference a nil pointer and take the process down.
func TestRevokeAgainstANonCARefusesInsteadOfCrashing(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	ca := newCA(t, "real-ca")
	storeCert(t, fv, "secret/leaf", newLeaf(t, ca, "leaf"))
	storeCert(t, fv, "secret/other", newLeaf(t, ca, "other"))

	c := newX509CLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/leaf"

	err := c.cmdX509Revoke("x509 revoke", "secret/other")
	if err == nil {
		t.Fatal("revoke against a non-CA = nil, want an error")
	}
	if !strings.Contains(err.Error(), "secret/leaf is not a certificate authority") {
		t.Errorf("error = %q, want it to name secret/leaf as not a CA", err)
	}
}

// The same nil revocation list is reachable through a validation run.
func TestValidateRevokedAgainstANonCARefusesInsteadOfCrashing(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	ca := newCA(t, "real-ca")
	storeCert(t, fv, "secret/leaf", newLeaf(t, ca, "leaf"))
	storeCert(t, fv, "secret/other", newLeaf(t, ca, "other"))

	for _, tc := range []struct {
		name string
		set  func(c *CLI)
	}{
		{"--revoked", func(c *CLI) { c.opt.X509.Validate.Revoked = true }},
		{"--not-revoked", func(c *CLI) { c.opt.X509.Validate.NotRevoked = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newX509CLI(t)
			c.opt.X509.Validate.SignedBy = "secret/leaf"
			tc.set(c)

			err := c.cmdX509Validate("x509 validate", "secret/other")
			if err == nil {
				t.Fatal("validate against a non-CA = nil, want an error")
			}
			if !strings.Contains(err.Error(), "secret/leaf is not a certificate authority") {
				t.Errorf("error = %q, want it to name secret/leaf as not a CA", err)
			}
		})
	}
}

// An authority brought in from somewhere else has a certificate that says it
// is a CA but carries no revocation list, since safe writes one only when it
// writes the CA. Revoking against it started a list rather than walking one
// that is not there.
func TestRevokeAgainstACAThatHasNoStoredCRL(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	ca := newCA(t, "imported")
	leaf := newLeaf(t, ca, "leaf")
	want := leaf.Certificate.SerialNumber.String()
	storeCert(t, fv, "secret/leaf", leaf)
	storeCert(t, fv, "secret/ca", ca)

	stored := fv.get("secret/ca")
	delete(stored, "crl")
	fv.set("secret/ca", stored)

	c := newX509CLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/ca"

	if err := c.cmdX509Revoke("x509 revoke", "secret/leaf"); err != nil {
		t.Fatalf("revoke against a CA with no stored CRL: %v", err)
	}

	got := revokedSerials(t, fv, "secret/ca")
	if len(got) != 1 || got[0] != want {
		t.Errorf("CRL holds %v, want [%s]", got, want)
	}
}

// The certificate the CA did issue still revokes, by its own serial number.
func TestRevokeRecordsTheSerialOfACertificateTheCASigned(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	ca := newCA(t, "ours")
	leaf := newLeaf(t, ca, "leaf")
	want := leaf.Certificate.SerialNumber.String()
	storeCert(t, fv, "secret/leaf", leaf)
	storeCert(t, fv, "secret/ca", ca)

	c := newX509CLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/ca"

	if err := c.cmdX509Revoke("x509 revoke", "secret/leaf"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	got := revokedSerials(t, fv, "secret/ca")
	if len(got) != 1 || got[0] != want {
		t.Errorf("CRL holds %v, want [%s]", got, want)
	}
}
