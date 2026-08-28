package cli

// x509 issue takes several destination paths in one invocation: one CA
// read, one CA write carrying one CRL re-sign and the whole batch's serial
// reservation, and one certificate write per path. These tests pin the
// request budget, the CA-write-before-cert-writes ordering, serial
// uniqueness, the per-path subject default, and what happens when part of
// the batch cannot be written. The keygen/fetch overlap itself is proven
// in pkg/vault, where the generation seam lives.

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
)

// storedLeafCert parses the certificate the fake holds at path.
func storedLeafCert(t *testing.T, fv *cliFakeVault, path string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(fv.get(path)["certificate"]))
	if block == nil {
		t.Fatalf("%s holds no certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse the certificate at %s: %v", path, err)
	}
	return cert
}

// storedCASerial parses the hex serial counter the fake holds at path.
func storedCASerial(t *testing.T, fv *cliFakeVault, path string) *big.Int {
	t.Helper()
	serial, ok := new(big.Int).SetString(fv.get(path)["serial"], 16)
	if !ok {
		t.Fatalf("%s holds no parseable serial (%q)", path, fv.get(path)["serial"])
	}
	return serial
}

// batchIssueCLI builds a CLI issuing an ed25519 fleet under secret/ca.
func batchIssueCLI(t *testing.T) *CLI {
	t.Helper()
	c := newX509CLI(t)
	c.opt.X509.Issue.SignedBy = "secret/ca"
	c.opt.X509.Issue.Name = []string{"fleet.example.com"}
	c.opt.X509.Issue.Type = "ed25519"
	return c
}

// Four paths cost one CA read, one CA write, and four certificate writes —
// and the CA write lands before any certificate carrying a reserved serial
// does, so a crash mid-batch burns numbers instead of duplicating them.
func TestBatchIssueRequestBudgetAndOrder(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "authority"))

	c := batchIssueCLI(t)
	paths := []string{"secret/x/a", "secret/x/b", "secret/x/c", "secret/x/d"}
	if err := c.cmdX509Issue("x509 issue", paths...); err != nil {
		t.Fatalf("batch issue: %v", err)
	}

	reqs := fv.requests()
	if got := countRequests(reqs, "GET /v1/secret/ca"); got != 1 {
		t.Errorf("CA reads = %d, want exactly 1\nlog: %q", got, reqs)
	}
	caPut := indexOfRequest(reqs, "PUT /v1/secret/ca")
	if caPut < 0 {
		caPut = indexOfRequest(reqs, "POST /v1/secret/ca")
	}
	if caPut < 0 {
		t.Fatalf("no CA write in the log: %q", reqs)
	}
	if got := countRequests(reqs, "PUT /v1/secret/ca") + countRequests(reqs, "POST /v1/secret/ca"); got != 1 {
		t.Errorf("CA writes = %d, want exactly 1\nlog: %q", got, reqs)
	}
	for _, path := range paths {
		if got := countRequests(reqs, "/v1/"+path); got != 1 {
			t.Errorf("requests touching %s = %d, want exactly 1 (the write)\nlog: %q", path, got, reqs)
		}
		if idx := indexOfRequest(reqs, "/v1/"+path); idx < caPut {
			t.Errorf("the write to %s (index %d) landed before the CA write (index %d)\nlog: %q",
				path, idx, caPut, reqs)
		}
	}
}

// Each certificate gets its own serial, in increasing order, and the
// persisted counter rests on the highest one handed out.
func TestBatchIssueSerialsAreDistinctAndAccountedFor(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "authority"))
	before := storedCASerial(t, fv, "secret/ca")

	c := batchIssueCLI(t)
	paths := []string{"secret/x/a", "secret/x/b", "secret/x/c", "secret/x/d"}
	if err := c.cmdX509Issue("x509 issue", paths...); err != nil {
		t.Fatalf("batch issue: %v", err)
	}

	prev := before
	for _, path := range paths {
		serial := storedLeafCert(t, fv, path).SerialNumber
		if serial.Cmp(prev) <= 0 {
			t.Errorf("%s carries serial %s, want above %s", path, serial, prev)
		}
		prev = serial
	}
	if counter := storedCASerial(t, fv, "secret/ca"); counter.Cmp(prev) != 0 {
		t.Errorf("the persisted CA counter is %s, want the highest issued serial %s", counter, prev)
	}
}

// The same destination twice would race one certificate's write against
// the other's, so it is refused before anything is read or generated.
func TestBatchIssueRefusesADuplicateDestination(t *testing.T) {
	isolateHome(t)
	c := batchIssueCLI(t)

	err := c.cmdX509Issue("x509 issue", "secret/x/a", "secret/x/b", "/secret/x//a")
	if err == nil {
		t.Fatal("issuing twice to one path = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "same path") || !strings.Contains(err.Error(), "secret/x/a") {
		t.Errorf("error = %q, want it to name secret/x/a as a repeated destination", err)
	}
}

// Two spellings of one path that only differ by a backslash escape must
// still be caught: Canonicalize does not unescape, but ParsePath (and
// therefore v.Write) does, so both spellings land on the same secret.
func TestBatchIssueRefusesAnEscapeAliasedDuplicateDestination(t *testing.T) {
	isolateHome(t)
	c := batchIssueCLI(t)

	err := c.cmdX509Issue("x509 issue", `secret/x/a\\b`, `secret/x/a\b`)
	if err == nil {
		t.Fatal("issuing to two escape-spellings of one path = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "same path") {
		t.Errorf("error = %q, want the same-path refusal", err)
	}
}

// An escape-aliased spelling of the signing authority must be refused the
// same way a byte-identical spelling would be.
func TestBatchIssueRefusesAnEscapeAliasedSigningAuthority(t *testing.T) {
	isolateHome(t)
	c := batchIssueCLI(t)
	c.opt.X509.Issue.SignedBy = `secret/ca\\x`

	err := c.cmdX509Issue("x509 issue", "secret/x/a", `secret/ca\x`)
	if err == nil {
		t.Fatal("issuing onto an escape-aliased CA path = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "signing authority") {
		t.Errorf("error = %q, want the signing-authority refusal", err)
	}
}

// The signing authority stays protected as a destination anywhere in the
// batch, not just in the first position.
func TestBatchIssueRefusesTheCAAnywhereInTheBatch(t *testing.T) {
	isolateHome(t)
	c := batchIssueCLI(t)

	err := c.cmdX509Issue("x509 issue", "secret/x/a", "secret/ca/")
	if err == nil {
		t.Fatal("issuing onto the CA mid-batch = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "signing authority") {
		t.Errorf("error = %q, want the signing-authority refusal", err)
	}
}

// A self-signed batch has no CA to account to: no reads at all, one write
// per certificate.
func TestBatchIssueSelfSignedMakesNoCARequests(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newX509CLI(t)
	c.opt.X509.Issue.Name = []string{"fleet.example.com"}
	c.opt.X509.Issue.Type = "ed25519"
	if err := c.cmdX509Issue("x509 issue", "secret/x/a", "secret/x/b"); err != nil {
		t.Fatalf("self-signed batch: %v", err)
	}

	reqs := fv.requests()
	if got := countRequests(reqs, "GET /v1/secret/"); got != 0 {
		t.Errorf("a self-signed batch made %d reads, want 0\nlog: %q", got, reqs)
	}
	for _, path := range []string{"secret/x/a", "secret/x/b"} {
		if len(fv.get(path)) == 0 {
			t.Errorf("nothing was written to %s", path)
		}
		self := storedLeafCert(t, fv, path)
		if self.Issuer.CommonName != self.Subject.CommonName {
			t.Errorf("%s is not self-signed: issuer %q, subject %q",
				path, self.Issuer.CommonName, self.Subject.CommonName)
		}
	}
}

// When --no-clobber skips every path there is nothing to issue, so the CA
// is neither read nor written: no CRL bump, no burned serials.
func TestBatchIssueAllSkippedTouchesNothing(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	signer := newCA(t, "authority")
	storeCert(t, fv, "secret/ca", signer)
	storeCert(t, fv, "secret/x/a", newLeaf(t, signer, "a"))
	storeCert(t, fv, "secret/x/b", newLeaf(t, signer, "b"))
	serialBefore := fv.get("secret/ca")["serial"]

	c := batchIssueCLI(t)
	c.opt.SkipIfExists = true

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdX509Issue("x509 issue", "secret/x/a", "secret/x/b")
	})
	if err != nil {
		t.Fatalf("all-skipped batch: %v", err)
	}
	for _, path := range []string{"secret/x/a", "secret/x/b"} {
		if !strings.Contains(stderr, path) {
			t.Errorf("stderr = %q, want it to name %s as left alone", stderr, path)
		}
	}

	reqs := fv.requests()
	if got := countRequests(reqs, "/v1/secret/ca"); got != 0 {
		t.Errorf("the CA was touched %d times with nothing to issue, want 0\nlog: %q", got, reqs)
	}
	for _, r := range reqs {
		if strings.HasPrefix(r, "PUT ") || strings.HasPrefix(r, "POST ") {
			t.Errorf("wrote %q with every path skipped", r)
		}
	}
	if fv.get("secret/ca")["serial"] != serialBefore {
		t.Error("the CA's serial counter moved with nothing issued")
	}
}

// One path already taken narrows the batch, not the whole run: the CA is
// still read and written once, and only the free path gets a certificate.
func TestBatchIssueNoClobberSkipsOnlyTheTakenPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	signer := newCA(t, "authority")
	storeCert(t, fv, "secret/ca", signer)
	storeCert(t, fv, "secret/x/a", newLeaf(t, signer, "a"))
	before := fv.get("secret/x/a")["certificate"]
	serialBefore := storedCASerial(t, fv, "secret/ca")

	c := batchIssueCLI(t)
	c.opt.SkipIfExists = true

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdX509Issue("x509 issue", "secret/x/a", "secret/x/b")
	})
	if err != nil {
		t.Fatalf("half-skipped batch: %v", err)
	}
	if !strings.Contains(stderr, "secret/x/a") {
		t.Errorf("stderr = %q, want it to name secret/x/a as left alone", stderr)
	}
	if fv.get("secret/x/a")["certificate"] != before {
		t.Error("the existing certificate was overwritten")
	}
	if len(fv.get("secret/x/b")) == 0 {
		t.Error("nothing was written to the free path")
	}
	reqs := fv.requests()
	if got := countRequests(reqs, "GET /v1/secret/ca"); got != 1 {
		t.Errorf("CA reads = %d, want exactly 1\nlog: %q", got, reqs)
	}
	want := new(big.Int).Add(serialBefore, big.NewInt(1))
	if counter := storedCASerial(t, fv, "secret/ca"); counter.Cmp(want) != 0 {
		t.Errorf("the CA counter rests at %s, want %s: one serial for one certificate", counter, want)
	}
}

// A certificate write that fails mid-batch names its path, and the writes
// beside it stand and are reported — the CA write has already landed, so
// every serial that did go out is accounted for.
func TestBatchIssueOneFailedWriteNamesItAndReportsTheRest(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "authority"))
	before := storedCASerial(t, fv, "secret/ca")
	fv.denyPut("secret/x/b")

	c := batchIssueCLI(t)

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdX509Issue("x509 issue", "secret/x/a", "secret/x/b", "secret/x/c")
	})
	if err == nil {
		t.Fatal("a batch with a denied write = nil, want an error")
	}
	if !strings.Contains(err.Error(), "secret/x/b") {
		t.Errorf("error = %q, want it to name the path that failed", err)
	}
	for _, path := range []string{"secret/x/a", "secret/x/c"} {
		if len(fv.get(path)) == 0 {
			t.Errorf("the write to %s did not stand", path)
		}
		if !strings.Contains(stderr, path) {
			t.Errorf("stderr = %q, want the successful write to %s reported", stderr, path)
		}
	}
	want := new(big.Int).Add(before, big.NewInt(3))
	if counter := storedCASerial(t, fv, "secret/ca"); counter.Cmp(want) != 0 {
		t.Errorf("the CA counter rests at %s, want %s: the CA write lands before any certificate write", counter, want)
	}
}

// With no --subject, each certificate's subject defaults to its own path's
// basename — that is what tells a SAN-identical fleet apart.
func TestBatchIssueSubjectDefaultsToThePathBasename(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "authority"))

	c := batchIssueCLI(t)
	if err := c.cmdX509Issue("x509 issue", "secret/x/alpha", "secret/x/beta"); err != nil {
		t.Fatalf("batch issue: %v", err)
	}

	for path, cn := range map[string]string{
		"secret/x/alpha": "alpha",
		"secret/x/beta":  "beta",
	} {
		cert := storedLeafCert(t, fv, path)
		if cert.Subject.CommonName != cn {
			t.Errorf("%s carries CN=%s, want CN=%s", path, cert.Subject.CommonName, cn)
		}
		if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "fleet.example.com" {
			t.Errorf("%s carries SANs %v, want the shared fleet.example.com", path, cert.DNSNames)
		}
	}
}

// A basename default must unescape an escaped path segment, not carry a
// stray backslash into the subject.
func TestBatchIssueSubjectBasenameUnescapesTheStrayBackslash(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "authority"))

	c := batchIssueCLI(t)
	if err := c.cmdX509Issue("x509 issue", "secret/x/alpha", `secret/x/a\^2`); err != nil {
		t.Fatalf("batch issue: %v", err)
	}

	if cn := storedLeafCert(t, fv, "secret/x/a^2").Subject.CommonName; cn != "a^2" {
		t.Errorf(`CN = %s, want the unescaped basename a^2`, cn)
	}
}

// Two destinations that share a basename get identical subjects and SANs,
// which defeats the reason the basename default exists: warn about it the
// same way an explicit --subject over several paths already does.
func TestBatchIssueWarnsWhenBasenamesCollide(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "authority"))

	c := batchIssueCLI(t)
	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdX509Issue("x509 issue", "secret/a/leaf", "secret/b/leaf")
	})
	if err != nil {
		t.Fatalf("batch issue with colliding basenames: %v", err)
	}
	if !strings.Contains(stderr, "leaf") {
		t.Errorf("stderr = %q, want a warning naming the shared basename leaf", stderr)
	}
	for _, path := range []string{"secret/a/leaf", "secret/b/leaf"} {
		if cn := storedLeafCert(t, fv, path).Subject.CommonName; cn != "leaf" {
			t.Errorf("%s carries CN=%s, want the shared basename leaf", path, cn)
		}
	}
}

// A single path keeps the old default: the first --name, not the basename.
func TestSinglePathSubjectStillDefaultsToTheFirstName(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "authority"))

	c := batchIssueCLI(t)
	if err := c.cmdX509Issue("x509 issue", "secret/x/leaf"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cn := storedLeafCert(t, fv, "secret/x/leaf").Subject.CommonName; cn != "fleet.example.com" {
		t.Errorf("a single path carries CN=%s, want the first --name fleet.example.com", cn)
	}
}

// An explicit --subject over several paths stamps the same subject on all
// of them, which defeats the per-path default — say so, and do it anyway.
func TestBatchIssueExplicitSubjectAppliesEverywhereAndWarns(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "authority"))

	c := batchIssueCLI(t)
	c.opt.X509.Issue.Subject = "CN=shared.example.com"

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdX509Issue("x509 issue", "secret/x/a", "secret/x/b")
	})
	if err != nil {
		t.Fatalf("batch issue with --subject: %v", err)
	}
	if !strings.Contains(stderr, "--subject") {
		t.Errorf("stderr = %q, want a warning about the shared --subject", stderr)
	}
	for _, path := range []string{"secret/x/a", "secret/x/b"} {
		if cn := storedLeafCert(t, fv, path).Subject.CommonName; cn != "shared.example.com" {
			t.Errorf("%s carries CN=%s, want the explicit shared.example.com", path, cn)
		}
	}
}
