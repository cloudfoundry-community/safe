package cli

// Fixtures and helpers live in x509_revoke_test.go.

import (
	"strings"
	"testing"
)

// A CA that never issued the certificate cannot revoke it, and saying it did
// is worse than a no-op: safe numbers the certificates each of its CAs issues
// from one, so a serial borrowed from another CA collides with one of this
// CA's own certificates and revokes that instead.
func TestRevokeRefusesACertificateTheCADidNotSign(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	ours := newCA(t, "ours")
	theirs := newCA(t, "theirs")
	storeCert(t, fv, "secret/ours", ours)
	storeCert(t, fv, "secret/theirs/leaf", newLeaf(t, theirs, "leaf"))

	c := newX509CLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/ours"

	err := c.cmdX509Revoke("x509 revoke", "secret/theirs/leaf")
	if err == nil {
		t.Fatal("revoke of a foreign certificate = nil, want an error")
	}
	if !strings.Contains(err.Error(), "was not signed by") {
		t.Errorf("error = %q, want it to say the certificate was not signed by the CA", err)
	}
	if got := revokedSerials(t, fv, "secret/ours"); len(got) != 0 {
		t.Errorf("CRL holds %v, want nothing revoked", got)
	}
}

// The collision is not hypothetical, and this pins the premise: two CAs
// issuing their first certificate hand out the same serial number, because
// safe counts from one per authority rather than picking at random. Should
// that ever change, the reasoning above is worth revisiting.
func TestTwoCAsIssueTheSameFirstSerial(t *testing.T) {
	mine := newLeaf(t, newCA(t, "ours"), "mine").Certificate.SerialNumber.String()
	yours := newLeaf(t, newCA(t, "theirs"), "yours").Certificate.SerialNumber.String()

	if mine != yours {
		t.Errorf("first serials are %s and %s, want them equal", mine, yours)
	}
}
