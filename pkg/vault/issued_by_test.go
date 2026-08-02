// IssuedBy answers whether an authority is the one a certificate came in
// under. FindSigningCA vets its guessed sibling with that question, and
// renewing or reissuing under a named authority needs the same answer to
// tell an ordinary renewal from one that moves the certificate somewhere
// else, so the two ask it the same way.

package vault_test

import (
	"testing"
)

func TestIssuedByRecognizesTheIssuingAuthority(t *testing.T) {
	t.Parallel()
	ca := caNamed(t, "authority")
	leaf := leafSignedBy(t, ca)

	if !leaf.IssuedBy(ca) {
		t.Error("IssuedBy = false for the authority that signed the certificate")
	}
}

func TestIssuedByRejectsAStranger(t *testing.T) {
	t.Parallel()
	issuer := caNamed(t, "issuer")
	stranger := caNamed(t, "stranger")
	leaf := leafSignedBy(t, issuer)

	if leaf.IssuedBy(stranger) {
		t.Error("IssuedBy = true for an authority that never signed the certificate")
	}
}

// Rotating a CA replaces its key but keeps its Subject, so the rotated
// authority is still the one every leaf underneath came in under. A
// signature check would say otherwise and block the ordinary rotation
// workflow.
func TestIssuedBySurvivesACAKeyRotation(t *testing.T) {
	t.Parallel()
	oldCA := caNamed(t, "authority")
	rotated := caNamed(t, "authority") // same subject, fresh key
	leaf := leafSignedBy(t, oldCA)

	if !leaf.IssuedBy(rotated) {
		t.Error("IssuedBy = false after a CA key rotation")
	}
}

func TestIssuedByHoldsForASelfSignedCertificate(t *testing.T) {
	t.Parallel()
	ca := caNamed(t, "self")

	if !ca.IssuedBy(ca) {
		t.Error("IssuedBy = false for a self-signed certificate against itself")
	}
}

// Nothing is not an authority. Callers reach this with whatever
// FindSigningCA handed back, so it must answer rather than panic.
func TestIssuedByRejectsANilAuthority(t *testing.T) {
	t.Parallel()
	leaf := leafSignedBy(t, caNamed(t, "authority"))

	if leaf.IssuedBy(nil) {
		t.Error("IssuedBy = true for a nil authority")
	}
}
