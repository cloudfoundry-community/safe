// Black-box tests for Secret.RSAKey and Secret.SSHKey (secret.go), the two
// generators that store a keypair in a secret. Between them they also cover
// the keypair() helper both methods share: RSAKey stores no fingerprint,
// SSHKey does, and both refuse to clobber existing keys when asked not to.
package vault_test

import (
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
	"golang.org/x/crypto/ssh"
)

// TestRSAKeyStoresPrivateAndPublicOnly verifies RSAKey stores the keypair
// under 'private' and 'public', and — unlike SSHKey — no fingerprint.
func TestRSAKeyStoresPrivateAndPublicOnly(t *testing.T) {
	t.Parallel()

	s := vault.NewSecret()
	if err := s.RSAKey(2048, false); err != nil {
		t.Fatalf("RSAKey(2048): %v", err)
	}

	if !s.Has("private") {
		t.Error("secret has no 'private' key")
	}
	if !s.Has("public") {
		t.Error("secret has no 'public' key")
	}
	if s.Has("fingerprint") {
		t.Error("RSAKey stored a 'fingerprint'; only SSHKey should")
	}
}

// TestRSAKeyStoredPairMatches verifies the stored private and public halves
// parse and belong to each other, at the requested size.
func TestRSAKeyStoredPairMatches(t *testing.T) {
	t.Parallel()

	s := vault.NewSecret()
	if err := s.RSAKey(2048, false); err != nil {
		t.Fatalf("RSAKey(2048): %v", err)
	}

	privBlock, _ := pem.Decode([]byte(s.Get("private")))
	if privBlock == nil {
		t.Fatal("'private' is not a PEM block")
	}
	priv, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("parse 'private': %v", err)
	}
	if got := priv.N.BitLen(); got != 2048 {
		t.Errorf("key size = %d bits; want 2048", got)
	}

	pubBlock, _ := pem.Decode([]byte(s.Get("public")))
	if pubBlock == nil {
		t.Fatal("'public' is not a PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("parse 'public': %v", err)
	}
	if !priv.PublicKey.Equal(pub) {
		t.Error("'public' does not match the public half of 'private'")
	}
}

// TestSSHKeyStoresKeypairWithFingerprint verifies SSHKey stores 'private',
// an authorized_keys-format 'public', and an MD5 colon-hex 'fingerprint'.
func TestSSHKeyStoresKeypairWithFingerprint(t *testing.T) {
	t.Parallel()

	s := vault.NewSecret()
	if err := s.SSHKey(2048, false); err != nil {
		t.Fatalf("SSHKey(2048): %v", err)
	}

	if !s.Has("private") {
		t.Error("secret has no 'private' key")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.Get("public"))); err != nil {
		t.Errorf("'public' is not an authorized_keys line: %v", err)
	}

	pattern := regexp.MustCompile(`^[0-9a-f]{2}(?::[0-9a-f]{2}){15}$`)
	if fp := s.Get("fingerprint"); !pattern.MatchString(fp) {
		t.Errorf("fingerprint %q does not match MD5 colon-hex pattern", fp)
	}
}

// TestKeypairRefusesToClobber verifies that with skipIfExists set, an
// existing 'private', 'public', or 'fingerprint' entry survives and the
// generator reports the collision instead of overwriting.
func TestKeypairRefusesToClobber(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		existing string
		generate func(s *vault.Secret) error
	}{
		{"rsa private", "private", func(s *vault.Secret) error { return s.RSAKey(2048, true) }},
		{"rsa public", "public", func(s *vault.Secret) error { return s.RSAKey(2048, true) }},
		{"ssh fingerprint", "fingerprint", func(s *vault.Secret) error { return s.SSHKey(2048, true) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := vault.NewSecret()
			if err := s.Set(tt.existing, "keep-me", false); err != nil {
				t.Fatalf("seed %q: %v", tt.existing, err)
			}
			if err := tt.generate(s); err == nil {
				t.Fatalf("expected an error for existing %q, got nil", tt.existing)
			}
			if got := s.Get(tt.existing); got != "keep-me" {
				t.Errorf("%q was clobbered: %q", tt.existing, got)
			}
		})
	}
}
