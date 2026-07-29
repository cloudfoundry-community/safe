package vault

// A version-not-found error narrows the wording of a secret-not-found error
// without changing its kind. Callers branch on IsNotFound and IsSecretNotFound
// to decide whether a path is absent — `exists` turns it into an exit code,
// and gen, uuid, ssh, rsa and dhparam all treat it as "nothing here yet, carry
// on and create it". If the narrowed error stopped answering to those, a
// missing version would start looking like a hard failure.

import "testing"

func TestVersionNotFoundIsStillASecretNotFound(t *testing.T) {
	for _, state := range []string{"", "deleted", "destroyed"} {
		err := NewVersionNotFoundError("secret/a", 2, state)
		if !IsSecretNotFound(err) {
			t.Errorf("IsSecretNotFound(%q) = false, want true", err)
		}
		if !IsNotFound(err) {
			t.Errorf("IsNotFound(%q) = false, want true", err)
		}
		if IsKeyNotFound(err) {
			t.Errorf("IsKeyNotFound(%q) = true, want false", err)
		}
	}
}

func TestVersionNotFoundMessage(t *testing.T) {
	cases := []struct {
		name    string
		state   string
		message string
	}{
		{
			name:    "never created",
			state:   "",
			message: "no version 2 of secret `secret/a` exists",
		},
		{
			name:    "deleted",
			state:   "deleted",
			message: "version 2 of secret `secret/a` has been deleted",
		},
		{
			name:    "destroyed",
			state:   "destroyed",
			message: "version 2 of secret `secret/a` has been destroyed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NewVersionNotFoundError("secret/a", 2, tc.state).Error()
			if got != tc.message {
				t.Errorf("Error() = %q, want %q", got, tc.message)
			}
		})
	}
}
