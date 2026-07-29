package vault

// The sentences safe uses for "cannot read that" live here, so that the
// commands which walk version history themselves — revert and undelete — can
// say what a read would say without having to return what a read returns.
//
// The split matters: those commands' errors travel into the tree walk, and a
// walk error answering to IsNotFound is discarded by the skip-if-exists check
// in MoveCopyTree. Sharing wording is safe; sharing the kind is not.

import (
	"errors"
	"testing"
)

func TestSecretNotFoundMessage(t *testing.T) {
	const want = "no secret exists at path `secret/a`"

	if got := SecretNotFoundMessage("secret/a"); got != want {
		t.Errorf("SecretNotFoundMessage = %q, want %q", got, want)
	}
	if got := NewSecretNotFoundError("secret/a").Error(); got != want {
		t.Errorf("NewSecretNotFoundError = %q, want %q", got, want)
	}
}

func TestVersionNotFoundMessageMatchesItsConstructor(t *testing.T) {
	for _, state := range []string{"", "deleted", "destroyed"} {
		want := VersionNotFoundMessage("secret/a", 2, state)
		if got := NewVersionNotFoundError("secret/a", 2, state).Error(); got != want {
			t.Errorf("state %q: constructor = %q, message = %q", state, got, want)
		}
	}
}

// A message on its own is just a message. Wrapping one in errors.New must not
// produce something IsNotFound answers for.
func TestSharedMessagesCarryNoKind(t *testing.T) {
	for _, err := range []error{
		errors.New(SecretNotFoundMessage("secret/a")),
		errors.New(VersionNotFoundMessage("secret/a", 2, "destroyed")),
	} {
		if IsNotFound(err) {
			t.Errorf("IsNotFound(%q) = true, want false", err)
		}
	}
}
