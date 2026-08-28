// Black-box tests for Secret.Format transforms and Secret.Password (secret.go).
package vault_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
	"github.com/tredoe/osutil/user/crypt/md5_crypt"
	"github.com/tredoe/osutil/user/crypt/sha256_crypt"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
)

// buildFormatSecret is a helper that returns a Secret containing key "src" with
// the given value.
func buildFormatSecret(t *testing.T, srcVal string) *vault.Secret {
	t.Helper()
	s := vault.NewSecret()
	if err := s.Set("src", srcVal, false); err != nil {
		t.Fatalf("buildFormatSecret Set: %v", err)
	}
	return s
}

// --- base64 ---

func TestSecretFormat_Base64RoundTrip(t *testing.T) {
	t.Parallel()

	s := buildFormatSecret(t, "hello, vault!")
	if err := s.Format("src", "dst", "base64", false); err != nil {
		t.Fatalf("Format base64: %v", err)
	}

	encoded := s.Get("dst")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64.Decode: %v (got %q)", err, encoded)
	}
	if string(decoded) != "hello, vault!" {
		t.Errorf("round-trip mismatch: got %q, want %q", string(decoded), "hello, vault!")
	}
}

func TestSecretFormat_Base64EmptyInput(t *testing.T) {
	t.Parallel()

	s := buildFormatSecret(t, "")
	if err := s.Format("src", "dst", "base64", false); err != nil {
		t.Fatalf("Format base64 empty: %v", err)
	}
	encoded := s.Get("dst")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64.Decode: %v", err)
	}
	if string(decoded) != "" {
		t.Errorf("decoded = %q; want empty", string(decoded))
	}
}

func TestSecretFormat_Base64SkipIfExists(t *testing.T) {
	t.Parallel()

	s := buildFormatSecret(t, "value")
	if err := s.Set("dst", "already-here", false); err != nil {
		t.Fatalf("Set dst: %v", err)
	}
	err := s.Format("src", "dst", "base64", true)
	if err == nil {
		t.Fatal("Format base64 skipIfExists=true with existing dst: expected error, got nil")
	}
	// dst must remain unchanged.
	if s.Get("dst") != "already-here" {
		t.Errorf("dst mutated despite skipIfExists=true: got %q", s.Get("dst"))
	}
}

// --- bcrypt ---

func TestSecretFormat_BcryptVerifiable(t *testing.T) {
	t.Parallel()

	const password = "hunter2"
	s := buildFormatSecret(t, password)
	if err := s.Format("src", "dst", "bcrypt", false); err != nil {
		t.Fatalf("Format bcrypt: %v", err)
	}

	hash := s.Get("dst")
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		t.Errorf("bcrypt.CompareHashAndPassword failed: %v (hash=%q)", err, hash)
	}
}

func TestSecretFormat_BcryptDefaultCost(t *testing.T) {
	t.Parallel()

	s := buildFormatSecret(t, "hunter2")
	if err := s.Format("src", "dst", "bcrypt", false); err != nil {
		t.Fatalf("Format bcrypt: %v", err)
	}

	// The cost is embedded in the hash, so the default is pinned here: a
	// change to it shows up as a different prefix.
	hash := s.Get("dst")
	if !strings.HasPrefix(hash, "$2a$12$") {
		t.Errorf("bcrypt hash cost prefix = %q, want $2a$12$", hash)
	}
}

func TestSecretFormat_BcryptChosenCost(t *testing.T) {
	t.Parallel()

	const password = "hunter2"
	s := buildFormatSecret(t, password)
	if err := s.FormatWithCost("src", "dst", "bcrypt", 10, false); err != nil {
		t.Fatalf("FormatWithCost bcrypt cost 10: %v", err)
	}

	hash := s.Get("dst")
	if !strings.HasPrefix(hash, "$2a$10$") {
		t.Errorf("bcrypt hash cost prefix = %q, want $2a$10$", hash)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		t.Errorf("bcrypt.CompareHashAndPassword failed: %v (hash=%q)", err, hash)
	}
}

func TestSecretFormat_BcryptCostBelowMinimumError(t *testing.T) {
	t.Parallel()

	s := buildFormatSecret(t, "hunter2")
	err := s.FormatWithCost("src", "dst", "bcrypt", 9, false)
	if err == nil {
		t.Fatal("FormatWithCost bcrypt cost 9: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "10") {
		t.Errorf("error %q does not name the minimum cost of 10", err)
	}
	if s.Has("dst") {
		t.Errorf("dst was written despite the cost error: %q", s.Get("dst"))
	}
}

func TestSecretFormat_BcryptSkipIfExists(t *testing.T) {
	t.Parallel()

	s := buildFormatSecret(t, "pass")
	if err := s.Set("dst", "existing-hash", false); err != nil {
		t.Fatalf("Set dst: %v", err)
	}
	err := s.Format("src", "dst", "bcrypt", true)
	if err == nil {
		t.Fatal("Format bcrypt skipIfExists=true: expected error, got nil")
	}
	if s.Get("dst") != "existing-hash" {
		t.Errorf("dst mutated despite skipIfExists=true: got %q", s.Get("dst"))
	}
}

// --- crypt-md5 ---

func TestSecretFormat_CryptMD5Verifiable(t *testing.T) {
	t.Parallel()

	const password = "testpass"
	s := buildFormatSecret(t, password)
	if err := s.Format("src", "dst", "crypt-md5", false); err != nil {
		t.Fatalf("Format crypt-md5: %v", err)
	}

	hash := s.Get("dst")
	if !strings.HasPrefix(hash, "$1$") {
		t.Errorf("crypt-md5 hash missing $1$ prefix: %q", hash)
	}

	c := md5_crypt.New()
	if err := c.Verify(hash, []byte(password)); err != nil {
		t.Errorf("crypt-md5 verify failed: %v (hash=%q)", err, hash)
	}
}

func TestSecretFormat_CryptMD5SkipIfExists(t *testing.T) {
	t.Parallel()

	s := buildFormatSecret(t, "pass")
	if err := s.Set("dst", "old", false); err != nil {
		t.Fatalf("Set dst: %v", err)
	}
	err := s.Format("src", "dst", "crypt-md5", true)
	if err == nil {
		t.Fatal("Format crypt-md5 skipIfExists=true: expected error, got nil")
	}
	if s.Get("dst") != "old" {
		t.Errorf("dst mutated despite skipIfExists=true: got %q", s.Get("dst"))
	}
}

// --- crypt-sha256 ---

func TestSecretFormat_CryptSHA256Verifiable(t *testing.T) {
	t.Parallel()

	const password = "sha256pass"
	s := buildFormatSecret(t, password)
	if err := s.Format("src", "dst", "crypt-sha256", false); err != nil {
		t.Fatalf("Format crypt-sha256: %v", err)
	}

	hash := s.Get("dst")
	if !strings.HasPrefix(hash, "$5$") {
		t.Errorf("crypt-sha256 hash missing $5$ prefix: %q", hash)
	}

	c := sha256_crypt.New()
	if err := c.Verify(hash, []byte(password)); err != nil {
		t.Errorf("crypt-sha256 verify failed: %v (hash=%q)", err, hash)
	}
}

func TestSecretFormat_CryptSHA256SkipIfExists(t *testing.T) {
	t.Parallel()

	s := buildFormatSecret(t, "pass")
	if err := s.Set("dst", "old", false); err != nil {
		t.Fatalf("Set dst: %v", err)
	}
	err := s.Format("src", "dst", "crypt-sha256", true)
	if err == nil {
		t.Fatal("Format crypt-sha256 skipIfExists=true: expected error, got nil")
	}
	if s.Get("dst") != "old" {
		t.Errorf("dst mutated: got %q", s.Get("dst"))
	}
}

// --- crypt-sha512 ---

func TestSecretFormat_CryptSHA512Verifiable(t *testing.T) {
	t.Parallel()

	const password = "sha512pass"
	s := buildFormatSecret(t, password)
	if err := s.Format("src", "dst", "crypt-sha512", false); err != nil {
		t.Fatalf("Format crypt-sha512: %v", err)
	}

	hash := s.Get("dst")
	if !strings.HasPrefix(hash, "$6$") {
		t.Errorf("crypt-sha512 hash missing $6$ prefix: %q", hash)
	}

	c := sha512_crypt.New()
	if err := c.Verify(hash, []byte(password)); err != nil {
		t.Errorf("crypt-sha512 verify failed: %v (hash=%q)", err, hash)
	}
}

func TestSecretFormat_CryptSHA512SkipIfExists(t *testing.T) {
	t.Parallel()

	s := buildFormatSecret(t, "pass")
	if err := s.Set("dst", "old", false); err != nil {
		t.Fatalf("Set dst: %v", err)
	}
	err := s.Format("src", "dst", "crypt-sha512", true)
	if err == nil {
		t.Fatal("Format crypt-sha512 skipIfExists=true: expected error, got nil")
	}
	if s.Get("dst") != "old" {
		t.Errorf("dst mutated: got %q", s.Get("dst"))
	}
}

// --- missing source key ---

func TestSecretFormat_MissingSourceKeyError(t *testing.T) {
	t.Parallel()

	transforms := []string{"base64", "bcrypt", "crypt-md5", "crypt-sha256", "crypt-sha512"}
	for _, fmtType := range transforms {
		fmtType := fmtType
		t.Run(fmtType, func(t *testing.T) {
			t.Parallel()
			s := vault.NewSecret()
			err := s.Format("nosuchkey", "dst", fmtType, false)
			if err == nil {
				t.Errorf("Format(%q) with missing source key: expected error, got nil", fmtType)
			}
		})
	}
}

// --- unknown format type ---

func TestSecretFormat_UnknownFormatTypeError(t *testing.T) {
	t.Parallel()

	s := buildFormatSecret(t, "val")
	err := s.Format("src", "dst", "rot13", false)
	if err == nil {
		t.Fatal("Format with unknown type: expected error, got nil")
	}
}

// --- Password ---

func TestSecretPassword_LengthHonored(t *testing.T) {
	t.Parallel()

	lengths := []int{8, 16, 32, 64}
	for _, n := range lengths {
		n := n
		t.Run("", func(t *testing.T) {
			t.Parallel()
			s := vault.NewSecret()
			if err := s.Password("pw", n, "a-zA-Z0-9", false); err != nil {
				t.Fatalf("Password(%d): %v", n, err)
			}
			got := s.Get("pw")
			if len(got) != n {
				t.Errorf("password length = %d, want %d (got %q)", len(got), n, got)
			}
		})
	}
}

func TestSecretPassword_PolicyApplied(t *testing.T) {
	t.Parallel()

	s := vault.NewSecret()
	if err := s.Password("pw", 64, "a-z", false); err != nil {
		t.Fatalf("Password: %v", err)
	}
	pw := s.Get("pw")
	for i, ch := range pw {
		if ch < 'a' || ch > 'z' {
			t.Errorf("char[%d] = %q not in [a-z] (policy a-z)", i, ch)
		}
	}
}

func TestSecretPassword_SkipIfExists(t *testing.T) {
	t.Parallel()

	s := vault.NewSecret()
	if err := s.Set("pw", "original", false); err != nil {
		t.Fatalf("Set: %v", err)
	}
	err := s.Password("pw", 16, "a-z", true)
	if err == nil {
		t.Fatal("Password skipIfExists=true with existing key: expected error, got nil")
	}
	if s.Get("pw") != "original" {
		t.Errorf("pw mutated despite skipIfExists=true: got %q", s.Get("pw"))
	}
}

func TestSecretPassword_NewKeyWithSkipIfExistsSucceeds(t *testing.T) {
	t.Parallel()

	s := vault.NewSecret()
	if err := s.Password("pw", 16, "a-zA-Z0-9", true); err != nil {
		t.Fatalf("Password on new key with skipIfExists=true: %v", err)
	}
	if !s.Has("pw") {
		t.Error("key 'pw' not present after Password call")
	}
	if len(s.Get("pw")) != 16 {
		t.Errorf("password length = %d, want 16", len(s.Get("pw")))
	}
}
