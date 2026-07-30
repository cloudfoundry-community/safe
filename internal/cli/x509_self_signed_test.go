package cli

// A certificate that signed itself is renewed and reissued by signing itself
// again, and the way that is recognised is by checking the certificate's
// signature against its own key. Both commands rewrite the certificate before
// looking, including the algorithm that signature was made with, so the check
// was run against a field the command had already replaced.

import (
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// newSelfSigned builds an ordinary certificate that signed itself.
func newSelfSigned(t *testing.T, cn string) *vault.X509 {
	t.Helper()

	x, err := vault.NewCertificate("CN="+cn, []string{cn},
		[]string{"server_auth"}, "",
		vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate(%s): %v", cn, err)
	}
	if err := x.Sign(x, time.Hour); err != nil {
		t.Fatalf("self-sign %s: %v", cn, err)
	}
	return x
}

// Reissuing clears the signature algorithm so that signing can derive one
// from the new key, which left nothing to check the old signature with.
func TestReissueRecognisesASelfSignedCertificate(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	self := newSelfSigned(t, "solo")
	storeCert(t, fv, "secret/solo/cert", self)
	beforeKey := fv.get("secret/solo/cert")["key"]

	c := newX509CLI(t)
	if err := c.cmdX509Reissue("x509 reissue", "secret/solo/cert"); err != nil {
		t.Fatalf("reissue a self-signed certificate: %v", err)
	}

	x, err := readStoredX509(t, fv, "secret/solo/cert")
	if err != nil {
		t.Fatalf("read the reissued certificate: %v", err)
	}
	if x.Certificate.Issuer.CommonName != "solo" {
		t.Errorf("issuer = %q, want solo", x.Certificate.Issuer.CommonName)
	}
	if fv.get("secret/solo/cert")["key"] == beforeKey {
		t.Error("the key was not regenerated")
	}
}

// The same certificate sitting next to an unrelated authority is still
// recognised as self-signed rather than handed to the sibling.
func TestReissueDoesNotHandASelfSignedCertToASibling(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/solo/cert", newSelfSigned(t, "solo"))
	storeCert(t, fv, "secret/solo/ca", newCA(t, "stranger"))

	c := newX509CLI(t)
	if err := c.cmdX509Reissue("x509 reissue", "secret/solo/cert"); err != nil {
		t.Fatalf("reissue a self-signed certificate: %v", err)
	}

	x, err := readStoredX509(t, fv, "secret/solo/cert")
	if err != nil {
		t.Fatalf("read the reissued certificate: %v", err)
	}
	if got := x.Certificate.Issuer.CommonName; got != "solo" {
		t.Errorf("issuer = %q, want solo", got)
	}
}

// Renewing overwrites the algorithm only when one is asked for, and asking
// for a different one used to make the certificate look as though something
// else had signed it.
func TestRenewRecognisesASelfSignedCertificateUnderANewAlgorithm(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/solo/cert", newSelfSigned(t, "solo"))

	//An RSA key signs with SHA512 unless told otherwise, so asking for
	// SHA256 is asking for something the stored signature was not made with.
	c := newX509CLI(t)
	c.opt.X509.Renew.SigAlgorithm = "sha256-rsa"
	if err := c.cmdX509Renew("x509 renew", "secret/solo/cert"); err != nil {
		t.Fatalf("renew a self-signed certificate: %v", err)
	}

	x, err := readStoredX509(t, fv, "secret/solo/cert")
	if err != nil {
		t.Fatalf("read the renewed certificate: %v", err)
	}
	if got := x.Certificate.Issuer.CommonName; got != "solo" {
		t.Errorf("issuer = %q, want solo", got)
	}
	if got := x.Certificate.SignatureAlgorithm.String(); !strings.Contains(got, "SHA256") {
		t.Errorf("signature algorithm = %s, want the requested SHA256", got)
	}
}

// A certificate an authority signed still finds that authority when it is
// named as a sibling.
func TestReissueUnderTheSiblingThatSignedItWorks(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	signer := newCA(t, "signer")
	storeCert(t, fv, "secret/x/leaf", newLeaf(t, signer, "leaf"))
	storeCert(t, fv, "secret/x/ca", signer)

	c := newX509CLI(t)
	if err := c.cmdX509Reissue("x509 reissue", "secret/x/leaf"); err != nil {
		t.Fatalf("reissue under the sibling that signed it: %v", err)
	}

	x, err := readStoredX509(t, fv, "secret/x/leaf")
	if err != nil {
		t.Fatalf("read the reissued certificate: %v", err)
	}
	if got := x.Certificate.Issuer.CommonName; got != "signer" {
		t.Errorf("issuer = %q, want signer", got)
	}
}
