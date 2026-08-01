package vault_test

// X509.Subject, Issuer, and IntermediarySubject render distinguished names
// through formatSubject (x509.go), and that rendering is what `x509 show`
// and `x509 validate` print for a certificate and what error messages name
// a signer by. None of it was covered. The contract: fields appear as
// key=value pairs in cn, c, st, l, o, ou order, absent fields are left out,
// and the result is a subject string safe's own ParseSubject accepts.

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// TestSubjectRendersAllFieldsInOrder verifies every supported field of a
// distinguished name comes back, in the fixed cn,c,st,l,o,ou order.
func TestSubjectRendersAllFieldsInOrder(t *testing.T) {
	t.Parallel()

	c, err := vault.NewCertificate("/cn=foo.example/c=US/st=NY/l=Buffalo/o=Stark & Wayne/ou=R&D",
		[]string{"foo.example"}, []string{"server_auth"}, "",
		vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}

	want := "cn=foo.example,c=US,st=NY,l=Buffalo,o=Stark & Wayne,ou=R&D"
	if got := c.Subject(); got != want {
		t.Errorf("Subject() = %q; want %q", got, want)
	}
}

// TestSubjectOmitsAbsentFields verifies fields the name does not carry
// leave no trace — no empty pairs, no stray separators.
func TestSubjectOmitsAbsentFields(t *testing.T) {
	t.Parallel()

	c, err := vault.NewCertificate("CN=only-a-name",
		[]string{"only-a-name"}, []string{"server_auth"}, "",
		vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}

	if got := c.Subject(); got != "cn=only-a-name" {
		t.Errorf("Subject() = %q; want %q", got, "cn=only-a-name")
	}
}

// TestSubjectRoundTripsThroughParseSubject verifies the rendered subject is
// accepted by ParseSubject and comes back as the same name, so a subject
// safe prints can be handed straight back to `x509 issue`.
func TestSubjectRoundTripsThroughParseSubject(t *testing.T) {
	t.Parallel()

	c, err := vault.NewCertificate("/cn=round.trip/c=US/o=Stark & Wayne",
		[]string{"round.trip"}, []string{"server_auth"}, "",
		vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}

	name, err := vault.ParseSubject(c.Subject())
	if err != nil {
		t.Fatalf("ParseSubject(%q): %v", c.Subject(), err)
	}
	reparsed := vault.X509{Certificate: &x509.Certificate{Subject: name}}
	if got := reparsed.Subject(); got != c.Subject() {
		t.Errorf("round-tripped subject = %q; want %q", got, c.Subject())
	}
}

// TestIssuerNamesTheSigningCA verifies Issuer() renders the subject of the
// CA that signed the certificate, not the certificate's own.
func TestIssuerNamesTheSigningCA(t *testing.T) {
	t.Parallel()

	ca := signingCA(t)
	leaf, err := vault.NewCertificate("CN=leaf", []string{"leaf"},
		[]string{"server_auth"}, "", vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("NewCertificate: %v", err)
	}
	if err := ca.Sign(leaf, time.Hour); err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate.Raw)
	if err != nil {
		t.Fatalf("parse the signed leaf: %v", err)
	}
	leaf.Certificate = parsed

	if got := leaf.Issuer(); got != ca.Subject() {
		t.Errorf("Issuer() = %q; want the CA's subject %q", got, ca.Subject())
	}
	if got := leaf.Subject(); got != "cn=leaf" {
		t.Errorf("Subject() = %q; want %q", got, "cn=leaf")
	}
}

// TestIntermediarySubjectNamesTheChain verifies IntermediarySubject renders
// the subject of the n-th certificate read from the chain stored alongside
// the leading one — what `x509 show` lists under "via".
func TestIntermediarySubjectNamesTheChain(t *testing.T) {
	t.Parallel()

	inter, root := chained(t)

	if got, want := inter.IntermediarySubject(0), root.Subject(); got != want {
		t.Errorf("IntermediarySubject(0) = %q; want %q", got, want)
	}
}
