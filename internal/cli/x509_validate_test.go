package cli

// Fixtures and helpers live in x509_revoke_test.go.
//
// 'safe x509 validate --signed-by' checks a signature and, with --revoked or
// --not-revoked, reads a revocation list. Both come off the CA's certificate;
// neither touches its private key. Reading the CA as though it needed one
// turned away every authority whose key is kept somewhere other than beside
// its certificate.

import (
	"strings"
	"testing"
)

// certOnly stores just the certificate of x, the way an authority looks when
// its private key is held offline or by someone else.
func certOnly(t *testing.T, fv *cliFakeVault, path string, kv map[string]string) {
	t.Helper()
	delete(kv, "key")
	delete(kv, "combined")
	fv.set(path, kv)
}

// keylessCA writes ca to path with its key stripped, and returns the leaf it
// signed, stored at leafPath.
func keylessCA(t *testing.T, fv *cliFakeVault, path, leafPath string) {
	t.Helper()
	ca := newCA(t, "offline-root")
	leaf := newLeaf(t, ca, "leaf")
	storeCert(t, fv, path, ca)
	storeCert(t, fv, leafPath, leaf)
	certOnly(t, fv, path, fv.get(path))
}

// The headline case: a CA with no key on hand still validates a signature.
func TestValidateSignedByACAWithNoStoredKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	keylessCA(t, fv, "secret/root", "secret/leaf")

	c := newX509CLI(t)
	c.opt.X509.Validate.SignedBy = "secret/root"

	if err := c.cmdX509Validate("x509 validate", "secret/leaf"); err != nil {
		t.Errorf("validate against a key-less CA: %v", err)
	}
}

// A revocation check reads the CA's list, which is stored beside its
// certificate rather than derived from its key.
func TestValidateNotRevokedAgainstACAWithNoStoredKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	keylessCA(t, fv, "secret/root", "secret/leaf")

	c := newX509CLI(t)
	c.opt.X509.Validate.SignedBy = "secret/root"
	c.opt.X509.Validate.NotRevoked = true

	if err := c.cmdX509Validate("x509 validate", "secret/leaf"); err != nil {
		t.Errorf("validate --not-revoked against a key-less CA: %v", err)
	}
}

// A certificate the CA did not sign is still turned away.
func TestValidateSignedByStillRejectsAForeignCertificate(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	keylessCA(t, fv, "secret/root", "secret/leaf")
	storeCert(t, fv, "secret/elsewhere", newLeaf(t, newCA(t, "other-root"), "elsewhere"))

	c := newX509CLI(t)
	c.opt.X509.Validate.SignedBy = "secret/root"

	err := c.cmdX509Validate("x509 validate", "secret/elsewhere")
	if err == nil {
		t.Fatal("validate of a foreign certificate = nil, want an error")
	}
	if !strings.Contains(err.Error(), "was not signed by secret/root") {
		t.Errorf("error = %q, want it to say the certificate was not signed by secret/root", err)
	}
}

// The certificate under validation is still read with its key: the default
// check is that the key matches the certificate.
func TestValidateStillRequiresTheKeyOfTheCertificateItChecks(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	keylessCA(t, fv, "secret/root", "secret/leaf")
	certOnly(t, fv, "secret/leaf", fv.get("secret/leaf"))

	c := newX509CLI(t)
	c.opt.X509.Validate.SignedBy = "secret/root"

	err := c.cmdX509Validate("x509 validate", "secret/leaf")
	if err == nil {
		t.Fatal("validate of a key-less certificate = nil, want an error")
	}
	if !strings.Contains(err.Error(), "missing the `key` attribute") {
		t.Errorf("error = %q, want it to name the missing key attribute", err)
	}
}
