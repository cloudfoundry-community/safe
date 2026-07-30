package vault_test

// Signing a certificate with itself after its key has been replaced — what
// reissuing a self-signed certificate does — signed with the new key but left
// the old public key on the certificate acting as the issuer. The result said
// it was self-signed, and carried a signature only the discarded key could
// account for.

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// reissued replaces x's key and signs it with itself, the way `x509 reissue`
// does for a certificate that has no separate authority.
func reissued(t *testing.T, x *vault.X509) {
	t.Helper()

	key, err := vault.GenerateKey(vault.KeySpec{Algorithm: "rsa", Bits: 2048})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	x.PrivateKey = key
	x.Certificate.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
	if err := x.Sign(x, time.Hour); err != nil {
		t.Fatalf("self-sign with the new key: %v", err)
	}
	parsed, err := x509.ParseCertificate(x.Certificate.Raw)
	if err != nil {
		t.Fatalf("parse the signed certificate: %v", err)
	}
	x.Certificate = parsed
}

// The signature has to verify against the key the certificate now carries.
func TestAReissuedSelfSignedCertificateVerifiesAgainstItself(t *testing.T) {
	ca := signingCA(t)
	reissued(t, ca)

	if err := ca.Certificate.CheckSignatureFrom(ca.Certificate); err != nil {
		t.Errorf("the reissued certificate does not verify against itself: %v", err)
	}
}

// A self-signed certificate names its own key as the authority that signed
// it, so the two identifiers have to agree.
func TestAReissuedSelfSignedCertificateNamesItsOwnKey(t *testing.T) {
	ca := signingCA(t)
	reissued(t, ca)

	if string(ca.Certificate.AuthorityKeyId) != string(ca.Certificate.SubjectKeyId) {
		t.Error("the authority key identifier does not name the certificate's own key")
	}
}

// The certificate carries the key that replaced the old one.
func TestAReissuedSelfSignedCertificateCarriesTheNewKey(t *testing.T) {
	ca := signingCA(t)
	before := marshalPublic(t, ca.Certificate.PublicKey)
	reissued(t, ca)

	after := marshalPublic(t, ca.Certificate.PublicKey)
	if after == before {
		t.Error("the certificate still carries the old public key")
	}
	if after != marshalPublic(t, ca.PrivateKey.Public()) {
		t.Error("the certificate does not carry the key stored beside it")
	}
}

// marshalPublic renders a public key in a form two of them can be compared in.
func marshalPublic(t *testing.T, key any) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal a %T: %v", key, err)
	}
	return string(der)
}
