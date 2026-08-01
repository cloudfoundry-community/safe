// Black-box tests for Secret.DHParam (secret.go), which shells out to
// openssl to generate Diffie-Hellman parameters and stores them under
// 'dhparam-pem'. The unexported genDHParam bit validation has its own
// white-box tests in dhparam_test.go; here the concern is what ends up in
// the secret. 1024 bits is the smallest size DHParam accepts and keeps
// generation fast.
package vault_test

import (
	"encoding/pem"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// TestDHParamStoresPEM verifies DHParam stores a parseable DH PARAMETERS
// PEM block under 'dhparam-pem'.
func TestDHParamStoresPEM(t *testing.T) {
	t.Parallel()

	s := vault.NewSecret()
	if err := s.DHParam(1024, false); err != nil {
		t.Fatalf("DHParam(1024): %v", err)
	}

	block, _ := pem.Decode([]byte(s.Get("dhparam-pem")))
	if block == nil {
		t.Fatal("'dhparam-pem' is not a PEM block")
	}
	if block.Type != "DH PARAMETERS" {
		t.Errorf("PEM type = %q; want DH PARAMETERS", block.Type)
	}
}

// TestDHParamRejectsInvalidBits verifies an unsupported bit count is
// reported as an error and nothing is stored.
func TestDHParamRejectsInvalidBits(t *testing.T) {
	t.Parallel()

	s := vault.NewSecret()
	if err := s.DHParam(512, false); err == nil {
		t.Fatal("expected an error for 512 bits, got nil")
	}
	if !s.Empty() {
		t.Errorf("secret is not empty after a failed DHParam: %v", s.Keys())
	}
}

// TestDHParamRefusesToClobber verifies that with skipIfExists set, an
// existing 'dhparam-pem' entry survives and the collision is reported.
func TestDHParamRefusesToClobber(t *testing.T) {
	t.Parallel()

	s := vault.NewSecret()
	if err := s.Set("dhparam-pem", "keep-me", false); err != nil {
		t.Fatalf("seed 'dhparam-pem': %v", err)
	}
	if err := s.DHParam(1024, true); err == nil {
		t.Fatal("expected an error for an existing 'dhparam-pem', got nil")
	}
	if got := s.Get("dhparam-pem"); got != "keep-me" {
		t.Errorf("'dhparam-pem' was clobbered: %q", got)
	}
}
