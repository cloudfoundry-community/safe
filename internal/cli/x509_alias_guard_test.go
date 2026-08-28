package cli

// A signing authority and the certificate being reissued or renewed can name
// one Vault secret with two different spellings, since a name may carry an
// escaped caret or colon. Recognising that they are the same record is what
// decides whether the certificate signs itself or is signed by a separately
// read copy of itself -- and saving that separate copy back is a second write
// to the record the certificate is about to overwrite, which drops the
// authority's serial counter back to where it stood before.

import (
	"strings"
	"testing"
)

// putsTo counts the writes the fake served for one stored path, whatever
// spelling reached it.
func putsTo(t *testing.T, fv *cliFakeVault) int {
	t.Helper()
	n := 0
	for _, r := range fv.requests() {
		if strings.HasPrefix(r, "PUT ") || strings.HasPrefix(r, "POST ") {
			n++
		}
	}
	return n
}

// `secret/x/ca^b` and `secret/x/ca\^b` are the same secret: ParsePath
// unescapes the caret in the second and leaves the first alone, because `b`
// is not a version number.
const (
	aliasPlain   = `secret/x/ca^b`
	aliasEscaped = `secret/x/ca\^b`
)

func TestReissueSelfSignsThroughAnEscapedAlias(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, aliasPlain, newCA(t, "aliased"))
	fv.forgetRequests()

	c := newX509CLI(t)
	c.opt.X509.Reissue.SignedBy = aliasEscaped
	if err := c.cmdX509Reissue("x509 reissue", aliasPlain); err != nil {
		t.Fatalf("reissue through an escaped alias: %v", err)
	}

	if got := putsTo(t, fv); got != 1 {
		t.Errorf("writes = %d, want 1: the authority and the certificate are one record\n%v",
			got, fv.requests())
	}

	x, err := readStoredX509(t, fv, aliasPlain)
	if err != nil {
		t.Fatalf("read the reissued certificate: %v", err)
	}
	if !x.Certificate.IsCA {
		t.Error("the stored record is no longer a certificate authority")
	}
	if got := x.Certificate.Issuer.CommonName; got != "aliased" {
		t.Errorf("issuer = %q, want aliased", got)
	}
}

func TestRenewSelfSignsThroughAnEscapedAlias(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	storeCert(t, fv, aliasPlain, newCA(t, "aliased"))
	fv.forgetRequests()

	c := newX509CLI(t)
	c.opt.X509.Renew.SignedBy = aliasEscaped
	if err := c.cmdX509Renew("x509 renew", aliasPlain); err != nil {
		t.Fatalf("renew through an escaped alias: %v", err)
	}

	if got := putsTo(t, fv); got != 1 {
		t.Errorf("writes = %d, want 1: the authority and the certificate are one record\n%v",
			got, fv.requests())
	}

	x, err := readStoredX509(t, fv, aliasPlain)
	if err != nil {
		t.Fatalf("read the renewed certificate: %v", err)
	}
	if !x.Certificate.IsCA {
		t.Error("the stored record is no longer a certificate authority")
	}
}
