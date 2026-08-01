package cli

// Renewing and reissuing take the signing authority from --signed-by, and
// with no flag they guess the 'ca' sibling of the certificate's own path.
// The guess was taken on trust: whatever sat at that path signed the
// certificate again, giving it a new issuer without saying so.

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// readStoredX509 parses the certificate stored at path back out of the fake.
func readStoredX509(t *testing.T, fv *cliFakeVault, path string) (*vault.X509, error) {
	t.Helper()

	s := vault.NewSecret()
	for k, v := range fv.get(path) {
		if err := s.Set(k, v, false); err != nil {
			t.Fatalf("rebuild the secret at %s: %v", path, err)
		}
	}
	return s.X509(false)
}

// The sibling holds an authority, but not the one that issued the
// certificate.
func TestRenewRefusesASiblingCAThatDidNotSignIt(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	signer := newCA(t, "signer")
	stranger := newCA(t, "stranger")

	storeCert(t, fv, "secret/x/leaf", newLeaf(t, signer, "leaf"))
	storeCert(t, fv, "secret/x/ca", stranger)
	before := fv.get("secret/x/leaf")["certificate"]

	c := newX509CLI(t)
	err := c.cmdX509Renew("x509 renew", "secret/x/leaf")
	if err == nil {
		t.Fatal("renew under an unrelated sibling = nil, want an error")
	}
	if !strings.Contains(err.Error(), "secret/x/ca did not sign secret/x/leaf") {
		t.Errorf("error = %q, want it to say the sibling did not sign the certificate", err)
	}
	if !strings.Contains(err.Error(), "--signed-by") {
		t.Errorf("error = %q, want it to point at --signed-by", err)
	}
	if fv.get("secret/x/leaf")["certificate"] != before {
		t.Error("the certificate was reissued anyway")
	}
}

// Reissuing guesses the same way and refuses the same way.
func TestReissueRefusesASiblingCAThatDidNotSignIt(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	signer := newCA(t, "signer")

	storeCert(t, fv, "secret/x/leaf", newLeaf(t, signer, "leaf"))
	storeCert(t, fv, "secret/x/ca", newCA(t, "stranger"))

	c := newX509CLI(t)
	err := c.cmdX509Reissue("x509 reissue", "secret/x/leaf")
	if err == nil {
		t.Fatal("reissue under an unrelated sibling = nil, want an error")
	}
	if !strings.Contains(err.Error(), "secret/x/ca did not sign secret/x/leaf") {
		t.Errorf("error = %q, want it to say the sibling did not sign the certificate", err)
	}
}

// Naming the authority is how a certificate moves to a new one, so an
// explicit --signed-by is still taken at its word.
func TestRenewUnderANamedAuthorityThatDidNotSignItIsAllowed(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	signer := newCA(t, "signer")

	storeCert(t, fv, "secret/x/leaf", newLeaf(t, signer, "leaf"))
	storeCert(t, fv, "secret/new/ca", newCA(t, "new-authority"))

	c := newX509CLI(t)
	c.opt.X509.Renew.SignedBy = "secret/new/ca"
	if err := c.cmdX509Renew("x509 renew", "secret/x/leaf"); err != nil {
		t.Fatalf("renew under a named authority: %v", err)
	}

	x, err := readStoredX509(t, fv, "secret/x/leaf")
	if err != nil {
		t.Fatalf("read the renewed certificate: %v", err)
	}
	if got := x.Certificate.Issuer.CommonName; got != "new-authority" {
		t.Errorf("issuer = %q, want new-authority", got)
	}
}

// The sibling that did sign it renews it, which is the whole point of the
// guess.
func TestRenewUnderTheSiblingThatSignedItWorks(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	signer := newCA(t, "signer")

	storeCert(t, fv, "secret/x/leaf", newLeaf(t, signer, "leaf"))
	storeCert(t, fv, "secret/x/ca", signer)

	c := newX509CLI(t)
	if err := c.cmdX509Renew("x509 renew", "secret/x/leaf"); err != nil {
		t.Fatalf("renew under the sibling that signed it: %v", err)
	}

	x, err := readStoredX509(t, fv, "secret/x/leaf")
	if err != nil {
		t.Fatalf("read the renewed certificate: %v", err)
	}
	if got := x.Certificate.Issuer.CommonName; got != "signer" {
		t.Errorf("issuer = %q, want signer", got)
	}
}

// A --signed-by that spells the certificate's own path differently (a
// trailing slash) names the same secret. The authority and the certificate
// being reissued are then the same underlying record, so saving the
// authority separately from the reissued certificate is a second, redundant
// write to that record — and, because the CA object read a second time
// under the differently-spelled path is not the same in-memory copy as the
// certificate being reissued, its serial counter increment never reaches
// what finally gets saved. One write, not two.
func TestReissueSkipsRedundantSaveWhenSignedByAliasesItself(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "root"))

	c := newX509CLI(t)
	c.opt.X509.Reissue.SignedBy = "secret/ca/"

	fv.forgetRequests()
	if err := c.cmdX509Reissue("x509 reissue", "secret/ca"); err != nil {
		t.Fatalf("reissue under an aliased signed-by: %v", err)
	}

	writes := 0
	for _, r := range fv.requests() {
		if r == "PUT /v1/secret/ca" {
			writes++
		}
	}
	if writes != 1 {
		t.Errorf("writes to secret/ca = %d, want 1", writes)
	}
}

// The same aliasing collapses to one write for renew too.
func TestRenewSkipsRedundantSaveWhenSignedByAliasesItself(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "root"))

	c := newX509CLI(t)
	c.opt.X509.Renew.SignedBy = "/secret/ca"

	fv.forgetRequests()
	if err := c.cmdX509Renew("x509 renew", "secret/ca"); err != nil {
		t.Fatalf("renew under an aliased signed-by: %v", err)
	}

	writes := 0
	for _, r := range fv.requests() {
		if r == "PUT /v1/secret/ca" {
			writes++
		}
	}
	if writes != 1 {
		t.Errorf("writes to secret/ca = %d, want 1", writes)
	}
}
