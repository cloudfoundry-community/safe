package cli

// --no-clobber asks x509 issue to leave a certificate that is already there
// alone. Deciding that rests on a read, and a read answers three different
// ways: the secret is there, the secret is not there, or it could not be
// looked at. Only the second is permission to go ahead and write.

import (
	"strings"
	"testing"
)

func TestIssueNoClobberLeavesAnExistingCertificateAlone(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/x/leaf", newLeaf(t, newCA(t, "signer"), "leaf"))
	before := fv.get("secret/x/leaf")["certificate"]

	c := newX509CLI(t)
	c.opt.SkipIfExists = true
	c.opt.X509.Issue.Name = []string{"leaf.example.com"}

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdX509Issue("x509 issue", "secret/x/leaf")
	})
	if err != nil {
		t.Fatalf("issue with --no-clobber over an existing certificate: %v", err)
	}
	if fv.get("secret/x/leaf")["certificate"] != before {
		t.Error("the certificate was overwritten")
	}
	if !strings.Contains(stderr, "secret/x/leaf") {
		t.Errorf("stderr = %q, want it to name the path left alone", stderr)
	}
}

func TestIssueNoClobberWritesWhenNothingIsThere(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newX509CLI(t)
	c.opt.SkipIfExists = true
	c.opt.X509.Issue.Name = []string{"leaf.example.com"}

	if err := c.cmdX509Issue("x509 issue", "secret/x/leaf"); err != nil {
		t.Fatalf("issue with --no-clobber onto an empty path: %v", err)
	}
	if fv.get("secret/x/leaf")["certificate"] == "" {
		t.Error("nothing was issued")
	}
}

// A read that fails because the token may not look at the path says nothing
// about whether a certificate is there. Treating it as absence would write
// over one that is.
func TestIssueNoClobberSurfacesAReadFailure(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.denyGet("secret/x/leaf")

	c := newX509CLI(t)
	c.opt.SkipIfExists = true
	c.opt.X509.Issue.Name = []string{"leaf.example.com"}

	err := c.cmdX509Issue("x509 issue", "secret/x/leaf")
	if err == nil {
		t.Fatal("issue with --no-clobber over an unreadable path = nil, want an error")
	}
	for _, r := range fv.requests() {
		if strings.HasPrefix(r, "PUT ") {
			t.Errorf("wrote %q after a read it could not make sense of", r)
		}
	}
}
