package cli

// Issuing writes the new certificate over whatever the destination path held,
// and it writes the signing authority back too, to record the serial number it
// handed out. Naming the authority as the destination did both, in that order:
// the authority was saved and then replaced by the certificate it had just
// signed.

import (
	"strings"
	"testing"
)

// The authority's key, serial number, and revocation list all go with it.
func TestIssueRefusesToOverwriteItsOwnSigningCA(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "root"))
	before := fv.get("secret/ca")

	c := newX509CLI(t)
	c.opt.X509.Issue.Name = []string{"leaf.example.com"}
	c.opt.X509.Issue.SignedBy = "secret/ca"

	err := c.cmdX509Issue("x509 issue", "secret/ca")
	if err == nil {
		t.Fatal("issue onto its own CA = nil, want an error")
	}
	if !strings.Contains(err.Error(), "secret/ca") {
		t.Errorf("error = %q, want it to name secret/ca", err)
	}

	after := fv.get("secret/ca")
	for _, attr := range []string{"certificate", "key", "serial", "crl"} {
		if after[attr] != before[attr] {
			t.Errorf("the CA's %s attribute changed", attr)
		}
	}
}

// A trailing slash on the signing authority's path names the same secret,
// so the refusal has to fire for it too.
func TestIssueRefusesToOverwriteItsOwnSigningCATrailingSlash(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "root"))
	before := fv.get("secret/ca")

	c := newX509CLI(t)
	c.opt.X509.Issue.Name = []string{"leaf.example.com"}
	c.opt.X509.Issue.SignedBy = "secret/ca/"

	err := c.cmdX509Issue("x509 issue", "secret/ca")
	if err == nil {
		t.Fatal("issue onto its own CA (trailing slash) = nil, want an error")
	}

	after := fv.get("secret/ca")
	for _, attr := range []string{"certificate", "key", "serial", "crl"} {
		if after[attr] != before[attr] {
			t.Errorf("the CA's %s attribute changed", attr)
		}
	}
}

// A leading slash on the destination names the same secret too.
func TestIssueRefusesToOverwriteItsOwnSigningCALeadingSlash(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "root"))
	before := fv.get("secret/ca")

	c := newX509CLI(t)
	c.opt.X509.Issue.Name = []string{"leaf.example.com"}
	c.opt.X509.Issue.SignedBy = "secret/ca"

	err := c.cmdX509Issue("x509 issue", "/secret/ca")
	if err == nil {
		t.Fatal("issue onto its own CA (leading slash) = nil, want an error")
	}

	after := fv.get("secret/ca")
	for _, attr := range []string{"certificate", "key", "serial", "crl"} {
		if after[attr] != before[attr] {
			t.Errorf("the CA's %s attribute changed", attr)
		}
	}
}

// Issuing somewhere else under the same authority is untouched.
func TestIssueUnderACAWritesBothPaths(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "root"))
	before := fv.get("secret/ca")["serial"]

	c := newX509CLI(t)
	c.opt.X509.Issue.Name = []string{"leaf.example.com"}
	c.opt.X509.Issue.SignedBy = "secret/ca"

	if err := c.cmdX509Issue("x509 issue", "secret/leaf"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(fv.get("secret/leaf")) == 0 {
		t.Error("the certificate was not written")
	}
	if fv.get("secret/ca")["serial"] == before {
		t.Errorf("the CA's serial number stayed at %s", before)
	}
}
