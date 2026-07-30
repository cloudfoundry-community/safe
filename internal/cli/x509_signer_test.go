package cli

// Signing needs a certificate authority. Nothing checked that the path named
// as one held one, so safe would sign with an ordinary certificate and write
// the result out without complaint. What comes back is a certificate every
// relying party rejects, and the first sign of trouble is a handshake failing
// somewhere else.

import (
	"strings"
	"testing"
	"time"
)

// Issuing under a path that holds an ordinary certificate.
func TestIssueSignedByANonCARefuses(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	ca := newCA(t, "real")
	storeCert(t, fv, "secret/leaf", newLeaf(t, ca, "leaf"))

	c := newX509CLI(t)
	c.opt.X509.Issue.Name = []string{"new.example.com"}
	c.opt.X509.Issue.SignedBy = "secret/leaf"

	err := c.cmdX509Issue("x509 issue", "secret/new")
	if err == nil {
		t.Fatal("issue signed by a non-CA = nil, want an error")
	}
	if !strings.Contains(err.Error(), "secret/leaf is not a certificate authority") {
		t.Errorf("error = %q, want it to name secret/leaf as not a CA", err)
	}
	if len(fv.get("secret/new")) != 0 {
		t.Error("the certificate was written anyway")
	}
}

// Renewing and reissuing read the authority through the same helper, whether
// it was named on the command line or found beside the certificate.
func TestRenewAndReissueRefuseANonCASigner(t *testing.T) {
	for _, tc := range []struct {
		name     string
		signedBy string
		want     string
	}{
		{"--signed-by names a plain certificate", "secret/other", "secret/other"},
		{"the sibling ca is a plain certificate", "", "secret/x/ca"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			fv := newCLIFake(t)
			ca := newCA(t, "real")
			storeCert(t, fv, "secret/x/leaf", newLeaf(t, ca, "leaf"))
			storeCert(t, fv, "secret/x/ca", newLeaf(t, ca, "not-a-ca"))
			storeCert(t, fv, "secret/other", newLeaf(t, ca, "other"))
			before := fv.get("secret/x/leaf")["certificate"]

			c := newX509CLI(t)
			c.opt.X509.Renew.SignedBy = tc.signedBy
			err := c.cmdX509Renew("x509 renew", "secret/x/leaf")
			if err == nil {
				t.Fatal("renew signed by a non-CA = nil, want an error")
			}
			if !strings.Contains(err.Error(), tc.want+" is not a certificate authority") {
				t.Errorf("error = %q, want it to name %s as not a CA", err, tc.want)
			}
			if fv.get("secret/x/leaf")["certificate"] != before {
				t.Error("the certificate was rewritten anyway")
			}

			c = newX509CLI(t)
			c.opt.X509.Reissue.SignedBy = tc.signedBy
			err = c.cmdX509Reissue("x509 reissue", "secret/x/leaf")
			if err == nil {
				t.Fatal("reissue signed by a non-CA = nil, want an error")
			}
			if !strings.Contains(err.Error(), tc.want+" is not a certificate authority") {
				t.Errorf("error = %q, want it to name %s as not a CA", err, tc.want)
			}
		})
	}
}

// A certificate that signed itself still renews itself, which is the one case
// where the signer is not a certificate authority on purpose.
func TestASelfSignedCertificateStillRenewsItself(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	self := newCA(t, "self")
	self.Certificate.IsCA = false
	self.Certificate.BasicConstraintsValid = false
	if err := self.Sign(self, time.Hour); err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	storeCert(t, fv, "secret/self", self)

	c := newX509CLI(t)
	if err := c.cmdX509Renew("x509 renew", "secret/self"); err != nil {
		t.Fatalf("renew a self-signed certificate: %v", err)
	}
}

// An authority signs as it always did.
func TestIssueUnderARealCAStillWorks(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "real"))

	c := newX509CLI(t)
	c.opt.X509.Issue.Name = []string{"new.example.com"}
	c.opt.X509.Issue.SignedBy = "secret/ca"

	if err := c.cmdX509Issue("x509 issue", "secret/new"); err != nil {
		t.Fatalf("issue under a real CA: %v", err)
	}
	if len(fv.get("secret/new")) == 0 {
		t.Error("nothing was written")
	}
}
