// Read never hands back a nil *Secret. Callers that tolerate a not-found
// error go on to use the value, and every Secret accessor dereferences the
// receiver, so a nil here is a segfault one call later.
package vault_test

import (
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// TestReadNeverReturnsNilOnKeyNotFound pins the invariant for a missing key
// within an existing secret, which is the case that used to return nil.
func TestReadNeverReturnsNilOnKeyNotFound(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/myapp", map[string]string{"user": "admin"})

	s, err := v.Read("secret/myapp:missing")
	assertKeyNotFound(t, err)
	if s == nil {
		t.Fatal("Read returned a nil *Secret alongside KeyNotFound")
	}
	if !s.Empty() {
		t.Errorf("secret should be empty, has keys %v", s.Keys())
	}
}

// TestReadNeverReturnsNilOnSecretNotFound pins the same invariant for a
// missing secret, so the two not-found branches stay consistent.
func TestReadNeverReturnsNilOnSecretNotFound(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	s, err := v.Read("secret/does-not-exist")
	assertSecretNotFound(t, err)
	if s == nil {
		t.Fatal("Read returned a nil *Secret alongside SecretNotFound")
	}
	if !s.Empty() {
		t.Errorf("secret should be empty, has keys %v", s.Keys())
	}
}

// TestReadNilFreeSecretIsUsable walks the shape that crashed: tolerate the
// not-found error, then keep using the secret.
func TestReadNilFreeSecretIsUsable(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/myapp", map[string]string{"user": "admin"})

	s, err := v.Read("secret/myapp:missing")
	if err != nil && !vault.IsNotFound(err) {
		t.Fatalf("Read: %v", err)
	}
	if s.Has("anything") {
		t.Error("empty secret should not report a key")
	}
	if err := s.Set("added", "value", false); err != nil {
		t.Fatalf("Set on the returned secret: %v", err)
	}
}
