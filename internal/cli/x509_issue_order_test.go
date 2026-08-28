package cli

// x509 issue and reissue generate their key while the signing CA is being
// fetched, which reorders the observable edges: flag problems the command
// can see without the Vault -- a bad key spec, a malformed subject -- are
// refused before any CA request goes out, and reissue announces the key
// generation before the CA fetch can say anything. These tests pin the
// request budget and those orderings; the overlap itself is proven in
// pkg/vault, where the generation seam lives.

import (
	"strings"
	"testing"
)

// indexOfRequest finds the first logged request containing frag, or -1.
func indexOfRequest(reqs []string, frag string) int {
	for i, r := range reqs {
		if strings.Contains(r, frag) {
			return i
		}
	}
	return -1
}

func countRequests(reqs []string, frag string) int {
	n := 0
	for _, r := range reqs {
		if strings.Contains(r, frag) {
			n++
		}
	}
	return n
}

func TestIssueRequestBudgetAndOrderWithSignedBy(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "authority"))

	c := newX509CLI(t)
	c.opt.X509.Issue.SignedBy = "secret/ca"
	c.opt.X509.Issue.Name = []string{"leaf.example.com"}
	c.opt.X509.Issue.Type = "ed25519"

	if err := c.cmdX509Issue("x509 issue", "secret/x/leaf"); err != nil {
		t.Fatalf("issue: %v", err)
	}

	reqs := fv.requests()
	if got := countRequests(reqs, "GET /v1/secret/ca"); got != 1 {
		t.Errorf("CA reads = %d, want exactly 1\nlog: %q", got, reqs)
	}
	caGet := indexOfRequest(reqs, "GET /v1/secret/ca")
	caPut := indexOfRequest(reqs, "POST /v1/secret/ca")
	if caPut < 0 {
		caPut = indexOfRequest(reqs, "PUT /v1/secret/ca")
	}
	certPut := indexOfRequest(reqs, "/v1/secret/x/leaf")
	if caGet < 0 || caPut < 0 || certPut < 0 {
		t.Fatalf("missing requests: CA GET %d, CA write %d, cert write %d\nlog: %q",
			caGet, caPut, certPut, reqs)
	}
	if !(caGet < caPut && caPut < certPut) {
		t.Errorf("request order: CA GET %d, CA write %d, cert write %d; want read, then CA write, then cert write\nlog: %q",
			caGet, caPut, certPut, reqs)
	}
}

func TestIssueKeySpecErrorPrecedesTheCARead(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "authority"))

	c := newX509CLI(t)
	c.opt.X509.Issue.SignedBy = "secret/ca"
	c.opt.X509.Issue.Name = []string{"leaf.example.com"}
	c.opt.X509.Issue.Bits = 3000

	err := c.cmdX509Issue("x509 issue", "secret/x/leaf")
	if err == nil || !strings.Contains(err.Error(), "RSA key strength") {
		t.Fatalf("err = %v, want the key-spec refusal", err)
	}
	if n := countRequests(fv.requests(), "/v1/secret/ca"); n != 0 {
		t.Errorf("the CA was read %d times on the way to a key-spec error; want 0\nlog: %q",
			n, fv.requests())
	}
}

func TestIssueMalformedSubjectPrecedesTheCARead(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "authority"))

	c := newX509CLI(t)
	c.opt.X509.Issue.SignedBy = "secret/ca"
	c.opt.X509.Issue.Name = []string{"leaf.example.com"}
	c.opt.X509.Issue.Subject = "banana"

	err := c.cmdX509Issue("x509 issue", "secret/x/leaf")
	if err == nil || !strings.Contains(err.Error(), "malformed subject") {
		t.Fatalf("err = %v, want the malformed-subject refusal", err)
	}
	if n := countRequests(fv.requests(), "/v1/secret/ca"); n != 0 {
		t.Errorf("the CA was read %d times on the way to a subject error; want 0\nlog: %q",
			n, fv.requests())
	}
}

func TestReissueKeySpecErrorPrecedesTheCAFetch(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	signer := newCA(t, "signer")
	storeCert(t, fv, "secret/x/leaf", newLeaf(t, signer, "leaf"))
	storeCert(t, fv, "secret/x/ca", signer)

	c := newX509CLI(t)
	c.opt.X509.Reissue.Bits = 3000

	err := c.cmdX509Reissue("x509 reissue", "secret/x/leaf")
	if err == nil || !strings.Contains(err.Error(), "RSA key strength") {
		t.Fatalf("err = %v, want the key-spec refusal", err)
	}
	if n := countRequests(fv.requests(), "/v1/secret/x/ca"); n != 0 {
		t.Errorf("the sibling CA was read %d times on the way to a key-spec error; want 0\nlog: %q",
			n, fv.requests())
	}
}

func TestReissueAnnouncesKeygenBeforeTheCAFetchAnswers(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	//A leaf whose sibling `ca` secret does not exist: FindSigningCA fails,
	// but the key generation announcement has already been made by then.
	storeCert(t, fv, "secret/x/leaf", newLeaf(t, newCA(t, "signer"), "leaf"))

	c := newX509CLI(t)

	var err error
	stdout := captureStdout(t, func() {
		err = c.cmdX509Reissue("x509 reissue", "secret/x/leaf")
	})
	if err == nil || !strings.Contains(err.Error(), "no 'ca' sibling found") {
		t.Fatalf("err = %v, want the missing-sibling refusal", err)
	}
	if !strings.Contains(stdout, "Generating new") {
		t.Errorf("stdout = %q, want the key generation announced before the CA fetch failed", stdout)
	}
}
