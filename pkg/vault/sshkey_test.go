// White-box tests for the unexported sshkey() function (ssh.go).
package vault

import (
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestSSHKeyPrivatePEMValid verifies sshkey() produces a valid PKCS#1 RSA
// private key PEM block that can be parsed back.
func TestSSHKeyPrivatePEMValid(t *testing.T) {
	t.Parallel()

	priv, _, _, err := sshkey(2048)
	if err != nil {
		t.Fatalf("sshkey(2048) error: %v", err)
	}

	block, rest := pem.Decode([]byte(priv))
	if block == nil {
		t.Fatal("private key: pem.Decode returned nil block")
	}
	if len(rest) > 0 && len(strings.TrimSpace(string(rest))) > 0 {
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
}

// TestSSHKeyPublicAuthorizedKeyFormat verifies the public key is a valid
// authorized_keys line parseable by golang.org/x/crypto/ssh.
func TestSSHKeyPublicAuthorizedKeyFormat(t *testing.T) {
	t.Parallel()

	_, pub, _, err := sshkey(2048)
	if err != nil {
		t.Fatalf("sshkey(2048) error: %v", err)
	}

	// ssh.MarshalAuthorizedKey output is "type base64key\n"; ParseAuthorizedKey
	// expects exactly that format.
	parsed, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(pub))
	if parseErr != nil {
		t.Fatalf("ssh.ParseAuthorizedKey: %v (got %q)", parseErr, pub)
	}
	if parsed.Type() != "ssh-rsa" {
		t.Errorf("public key type = %q; want ssh-rsa", parsed.Type())
	}
}

// TestSSHKeyFingerprintColonHex verifies the fingerprint uses the legacy
// MD5 colon-hex format (xx:xx:...:xx, 16 pairs).
func TestSSHKeyFingerprintColonHex(t *testing.T) {
	t.Parallel()

	_, _, fp, err := sshkey(2048)
	if err != nil {
		t.Fatalf("sshkey(2048) error: %v", err)
	}

	// Pattern: 16 lowercase hex pairs separated by colons.
	pattern := regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){15}$`)
	if !pattern.MatchString(fp) {
		t.Errorf("fingerprint %q does not match MD5 colon-hex pattern", fp)
	}
}

// TestSSHKeyFieldsNonEmpty verifies all three return values are non-empty
// strings for a valid bit count.
func TestSSHKeyFieldsNonEmpty(t *testing.T) {
	t.Parallel()

	priv, pub, fp, err := sshkey(2048)
	if err != nil {
		t.Fatalf("sshkey(2048) error: %v", err)
	}
	if priv == "" {
		t.Error("private key is empty")
	}
	if pub == "" {
		t.Error("public key is empty")
	}
	if fp == "" {
		t.Error("fingerprint is empty")
	}
}

// TestSSHKeyPublicMatchesPrivate verifies the public key embedded in the
// authorized key line matches the public part of the private key.
func TestSSHKeyPublicMatchesPrivate(t *testing.T) {
	t.Parallel()

	priv, pub, _, err := sshkey(2048)
	if err != nil {
		t.Fatalf("sshkey(2048) error: %v", err)
	}

	// Re-derive the public key from the private key and compare marshaled form.
	block, _ := pem.Decode([]byte(priv))
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	derivedPub, err := ssh.NewPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	derived := string(ssh.MarshalAuthorizedKey(derivedPub))
	if derived != pub {
		t.Errorf("public key mismatch:\ngot:  %q\nwant: %q", pub, derived)
	}
}
