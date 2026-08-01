// White-box tests for the unexported rsakey() function (rsa.go).
package vault

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// TestRSAKeyPrivatePEMValid verifies rsakey() produces a valid PKCS#1 RSA
// private key PEM block that can be parsed back.
func TestRSAKeyPrivatePEMValid(t *testing.T) {
	t.Parallel()

	priv, _, err := rsakey(2048)
	if err != nil {
		t.Fatalf("rsakey(2048) error: %v", err)
	}

	block, rest := pem.Decode([]byte(priv))
	if block == nil {
		t.Fatal("private key: pem.Decode returned nil block")
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		t.Errorf("private key: unexpected trailing data after PEM block: %q", rest)
	}
	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("PEM type = %q; want RSA PRIVATE KEY", block.Type)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKCS1PrivateKey: %v", err)
	}
	if err := key.Validate(); err != nil {
		t.Errorf("rsa.PrivateKey.Validate: %v", err)
	}
	if got := key.N.BitLen(); got != 2048 {
		t.Errorf("key size = %d bits; want 2048", got)
	}
}

// TestRSAKeyPublicMatchesPrivate verifies the public key PEM is a PKIX
// PUBLIC KEY block holding the public half of the private key.
func TestRSAKeyPublicMatchesPrivate(t *testing.T) {
	t.Parallel()

	priv, pub, err := rsakey(2048)
	if err != nil {
		t.Fatalf("rsakey(2048) error: %v", err)
	}

	pubBlock, _ := pem.Decode([]byte(pub))
	if pubBlock == nil {
		t.Fatal("public key: pem.Decode returned nil block")
	}
	if pubBlock.Type != "PUBLIC KEY" {
		t.Errorf("PEM type = %q; want PUBLIC KEY", pubBlock.Type)
	}

	parsedPub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKIXPublicKey: %v", err)
	}
	rsaPub, ok := parsedPub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T; want *rsa.PublicKey", parsedPub)
	}

	privBlock, _ := pem.Decode([]byte(priv))
	privKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	if !rsaPub.Equal(&privKey.PublicKey) {
		t.Error("public key does not match the private key's public half")
	}
}
