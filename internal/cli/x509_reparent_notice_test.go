package cli

// An authority named with --signed-by that did not issue the certificate
// re-parents it: the certificate comes back under an issuer it did not go in
// with. That is allowed on purpose, since naming an authority is how a
// certificate moves to a new one -- but the guessed-sibling check refuses
// with a message that names --signed-by, so a user can arrive here by
// following advice about a certificate they only meant to renew. It happens
// out loud or not at all.

import (
	"strings"
	"testing"
)

func TestRenewUnderANamedStrangerAnnouncesTheReparenting(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/x/leaf", newLeaf(t, newCA(t, "signer"), "leaf"))
	storeCert(t, fv, "secret/new/ca", newCA(t, "new-authority"))

	c := newX509CLI(t)
	c.opt.X509.Renew.SignedBy = "secret/new/ca"

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdX509Renew("x509 renew", "secret/x/leaf")
	})
	if err != nil {
		t.Fatalf("renew under a named authority: %v", err)
	}
	for _, want := range []string{"secret/new/ca", "signer", "new-authority"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to mention %q", stderr, want)
		}
	}
}

func TestReissueUnderANamedStrangerAnnouncesTheReparenting(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/x/leaf", newLeaf(t, newCA(t, "signer"), "leaf"))
	storeCert(t, fv, "secret/new/ca", newCA(t, "new-authority"))

	c := newX509CLI(t)
	c.opt.X509.Reissue.SignedBy = "secret/new/ca"

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdX509Reissue("x509 reissue", "secret/x/leaf")
	})
	if err != nil {
		t.Fatalf("reissue under a named authority: %v", err)
	}
	for _, want := range []string{"secret/new/ca", "signer", "new-authority"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to mention %q", stderr, want)
		}
	}
}

// Naming the authority that did issue it is an ordinary renewal. Warning
// about that one would train the warning out of anyone who reads it.
func TestRenewUnderTheNamedIssuerSaysNothing(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	signer := newCA(t, "signer")
	storeCert(t, fv, "secret/x/leaf", newLeaf(t, signer, "leaf"))
	storeCert(t, fv, "secret/real/ca", signer)

	c := newX509CLI(t)
	c.opt.X509.Renew.SignedBy = "secret/real/ca"

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdX509Renew("x509 renew", "secret/x/leaf")
	})
	if err != nil {
		t.Fatalf("renew under the issuing authority: %v", err)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Errorf("stderr = %q, want nothing said", stderr)
	}
}

// Reissuing a CA under itself rotates its key. The certificate is its own
// authority, so nothing moves anywhere.
func TestReissueOfASelfSignedCAUnderItselfSaysNothing(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, "secret/ca", newCA(t, "root"))

	c := newX509CLI(t)
	c.opt.X509.Reissue.SignedBy = "secret/ca"

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdX509Reissue("x509 reissue", "secret/ca")
	})
	if err != nil {
		t.Fatalf("reissue a CA under itself: %v", err)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Errorf("stderr = %q, want nothing said", stderr)
	}
}
