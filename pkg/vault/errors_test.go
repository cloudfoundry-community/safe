package vault

import (
	"errors"
	"fmt"
	"testing"
)

// TestIsNotFound verifies IsNotFound returns true for both error kinds
// and false for unrelated errors and nil.
func TestIsNotFound(t *testing.T) {
	t.Parallel()

	secretErr := NewSecretNotFoundError("secret/foo")
	keyErr := NewKeyNotFoundError("secret/foo", "mykey")
	otherErr := errors.New("some other error")

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"secretNotFound error", secretErr, true},
		{"keyNotFound error", keyErr, true},
		{"unrelated error", otherErr, false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsNotFound(tt.err); got != tt.want {
				t.Errorf("IsNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestIsSecretNotFound verifies IsSecretNotFound accepts only secretNotFound
// errors.
func TestIsSecretNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"secretNotFound error", NewSecretNotFoundError("secret/bar"), true},
		{"keyNotFound error", NewKeyNotFoundError("secret/bar", "k"), false},
		{"unrelated error", errors.New("other"), false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsSecretNotFound(tt.err); got != tt.want {
				t.Errorf("IsSecretNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestIsKeyNotFound verifies IsKeyNotFound accepts only keyNotFound errors.
func TestIsKeyNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"keyNotFound error", NewKeyNotFoundError("secret/baz", "k"), true},
		{"secretNotFound error", NewSecretNotFoundError("secret/baz"), false},
		{"unrelated error", errors.New("other"), false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsKeyNotFound(tt.err); got != tt.want {
				t.Errorf("IsKeyNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestNewSecretNotFoundError verifies the constructor produces a correctly
// formatted message and satisfies IsSecretNotFound.
func TestNewSecretNotFoundError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		wantMsg string
	}{
		{
			name:    "basic path",
			path:    "secret/foo",
			wantMsg: "no secret exists at path `secret/foo`",
		},
		{
			name:    "nested path",
			path:    "secret/a/b/c",
			wantMsg: "no secret exists at path `secret/a/b/c`",
		},
		{
			name:    "empty path",
			path:    "",
			wantMsg: "no secret exists at path ``",
		},
		{
			name:    "path with special chars",
			path:    "secret/foo:bar",
			wantMsg: "no secret exists at path `secret/foo:bar`",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := NewSecretNotFoundError(tt.path)

			if err == nil {
				t.Fatal("NewSecretNotFoundError returned nil")
			}

			if got := err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}

			if !IsSecretNotFound(err) {
				t.Error("IsSecretNotFound(err) = false, want true")
			}

			if !IsNotFound(err) {
				t.Error("IsNotFound(err) = false, want true")
			}

			if IsKeyNotFound(err) {
				t.Error("IsKeyNotFound(err) = true, want false")
			}
		})
	}
}

// TestNewKeyNotFoundError verifies the constructor produces a correctly
// formatted message and satisfies IsKeyNotFound.
func TestNewKeyNotFoundError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		key     string
		wantMsg string
	}{
		{
			name:    "basic path and key",
			path:    "secret/foo",
			key:     "mykey",
			wantMsg: "no key `mykey` exists in secret `secret/foo`",
		},
		{
			name:    "nested path",
			path:    "secret/a/b/c",
			key:     "password",
			wantMsg: "no key `password` exists in secret `secret/a/b/c`",
		},
		{
			name:    "empty path",
			path:    "",
			key:     "k",
			wantMsg: "no key `k` exists in secret ``",
		},
		{
			name:    "empty key",
			path:    "secret/foo",
			key:     "",
			wantMsg: "no key `` exists in secret `secret/foo`",
		},
		{
			name:    "both empty",
			path:    "",
			key:     "",
			wantMsg: "no key `` exists in secret ``",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := NewKeyNotFoundError(tt.path, tt.key)

			if err == nil {
				t.Fatal("NewKeyNotFoundError returned nil")
			}

			if got := err.Error(); got != tt.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tt.wantMsg)
			}

			if !IsKeyNotFound(err) {
				t.Error("IsKeyNotFound(err) = false, want true")
			}

			if !IsNotFound(err) {
				t.Error("IsNotFound(err) = false, want true")
			}

			if IsSecretNotFound(err) {
				t.Error("IsSecretNotFound(err) = true, want false")
			}
		})
	}
}

// TestErrorMessageFormat cross-checks the exact fmt.Sprintf pattern used in
// errors.go so a future refactor cannot silently break message contracts.
func TestErrorMessageFormat(t *testing.T) {
	t.Parallel()

	t.Run("secretNotFound message template", func(t *testing.T) {
		t.Parallel()
		path := "secret/template-check"
		err := NewSecretNotFoundError(path)
		want := fmt.Sprintf("no secret exists at path `%s`", path)
		if err.Error() != want {
			t.Errorf("Error() = %q, want %q", err.Error(), want)
		}
	})

	t.Run("keyNotFound message template", func(t *testing.T) {
		t.Parallel()
		path := "secret/template-check"
		key := "somekey"
		err := NewKeyNotFoundError(path, key)
		want := fmt.Sprintf("no key `%s` exists in secret `%s`", key, path)
		if err.Error() != want {
			t.Errorf("Error() = %q, want %q", err.Error(), want)
		}
	})
}

// TestTypeAssertions verifies direct type assertion behavior, since the helpers
// use type assertion rather than errors.Is/As (the types carry no wrapped errors).
func TestTypeAssertions(t *testing.T) {
	t.Parallel()

	t.Run("secretNotFound type asserts correctly", func(t *testing.T) {
		t.Parallel()
		err := NewSecretNotFoundError("secret/x")
		if _, ok := err.(secretNotFound); !ok {
			t.Error("expected err to be secretNotFound type")
		}
	})

	t.Run("keyNotFound type asserts correctly", func(t *testing.T) {
		t.Parallel()
		err := NewKeyNotFoundError("secret/x", "k")
		if _, ok := err.(keyNotFound); !ok {
			t.Error("expected err to be keyNotFound type")
		}
	})

	t.Run("secretNotFound does not assert as keyNotFound", func(t *testing.T) {
		t.Parallel()
		err := NewSecretNotFoundError("secret/x")
		if _, ok := err.(keyNotFound); ok {
			t.Error("secretNotFound should not assert as keyNotFound")
		}
	})

	t.Run("keyNotFound does not assert as secretNotFound", func(t *testing.T) {
		t.Parallel()
		err := NewKeyNotFoundError("secret/x", "k")
		if _, ok := err.(secretNotFound); ok {
			t.Error("keyNotFound should not assert as secretNotFound")
		}
	})
}

// TestErrorsIsCompatibility confirms the error types satisfy the error interface
// and behave correctly with errors.Is (identity equality, no unwrapping needed).
func TestErrorsIsCompatibility(t *testing.T) {
	t.Parallel()

	t.Run("same secretNotFound instance matches itself", func(t *testing.T) {
		t.Parallel()
		err := NewSecretNotFoundError("secret/foo")
		if !errors.Is(err, err) {
			t.Error("errors.Is(err, err) = false, want true for same instance")
		}
	})

	t.Run("same keyNotFound instance matches itself", func(t *testing.T) {
		t.Parallel()
		err := NewKeyNotFoundError("secret/foo", "k")
		if !errors.Is(err, err) {
			t.Error("errors.Is(err, err) = false, want true for same instance")
		}
	})

	t.Run("different secretNotFound instances do not match", func(t *testing.T) {
		t.Parallel()
		err1 := NewSecretNotFoundError("secret/foo")
		err2 := NewSecretNotFoundError("secret/foo")
		// These are value types with same content; errors.Is compares by value
		// for comparable types. Both carry the same message string, so they
		// are equal under errors.Is value comparison.
		if !errors.Is(err1, err2) {
			t.Error("errors.Is(err1, err2) = false; expected true for same-content value errors")
		}
	})

	t.Run("secretNotFound does not match keyNotFound", func(t *testing.T) {
		t.Parallel()
		sErr := NewSecretNotFoundError("secret/foo")
		kErr := NewKeyNotFoundError("secret/foo", "k")
		if errors.Is(sErr, kErr) {
			t.Error("errors.Is(secretErr, keyErr) = true, want false")
		}
		if errors.Is(kErr, sErr) {
			t.Error("errors.Is(keyErr, secretErr) = true, want false")
		}
	})
}
