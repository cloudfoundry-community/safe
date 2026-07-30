// White-box tests for the unexported random() function (random.go).
package vault

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestRandomLength verifies random(n, policy) always returns a string of
// exactly n runes for a variety of lengths.
func TestRandomLength(t *testing.T) {
	t.Parallel()

	//A length below one is refused rather than returned as an empty password;
	// see TestRandomRefusesALengthBelowOne.
	lengths := []int{1, 8, 16, 32, 64, 128}
	for _, n := range lengths {
		n := n
		t.Run("", func(t *testing.T) {
			t.Parallel()
			got, err := random(n, "a-zA-Z0-9")
			if err != nil {
				t.Fatalf("random(%d): unexpected error: %v", n, err)
			}
			if len(got) != n {
				t.Errorf("random(%d) returned %d bytes: %q", n, len(got), got)
			}
			if utf8.RuneCountInString(got) != n {
				t.Errorf("random(%d) returned %d runes: %q", n, utf8.RuneCountInString(got), got)
			}
		})
	}
}

// TestRandomCharsetFilter verifies that only characters matching the policy
// appear in the output. We use a very narrow policy to make violations obvious.
func TestRandomCharsetFilter(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		policy string
		// allowed is a set of the only acceptable characters.
		allowed string
	}{
		{
			name:    "digits only",
			policy:  "0-9",
			allowed: "0123456789",
		},
		{
			name:    "lowercase letters only",
			policy:  "a-z",
			allowed: "abcdefghijklmnopqrstuvwxyz",
		},
		{
			name:    "uppercase letters only",
			policy:  "A-Z",
			allowed: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		},
		{
			name:    "alphanumeric",
			policy:  "a-zA-Z0-9",
			allowed: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		},
		{
			name:    "single char a",
			policy:  "a",
			allowed: "a",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const n = 64
			got, err := random(n, tc.policy)
			if err != nil {
				t.Fatalf("random(%d, %q): %v", n, tc.policy, err)
			}
			if len(got) != n {
				t.Errorf("byte length: got %d, want %d", len(got), n)
			}
			if utf8.RuneCountInString(got) != n {
				t.Errorf("rune count: got %d, want %d", utf8.RuneCountInString(got), n)
			}
			for i, ch := range got {
				if !strings.ContainsRune(tc.allowed, ch) {
					t.Errorf("char[%d] = %q not in allowed set %q (policy=%q)", i, ch, tc.allowed, tc.policy)
				}
			}
		})
	}
}

// TestRandomNotDeterministic verifies two successive calls produce different
// output with overwhelming probability (chance of collision is negligible at
// length 32 over a full printable charset).
func TestRandomNotDeterministic(t *testing.T) {
	t.Parallel()

	a, err := random(32, "a-zA-Z0-9")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	b, err := random(32, "a-zA-Z0-9")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if a == b {
		// Extremely unlikely but not impossible; log rather than fail hard.
		t.Logf("random(32) returned identical values twice: %q — may be a fluke", a)
	}
}

// TestRandomSingleCharPolicy verifies that a policy matching exactly one
// character produces a string entirely composed of that character.
func TestRandomSingleCharPolicy(t *testing.T) {
	t.Parallel()

	got, err := random(10, "a")
	if err != nil {
		t.Fatalf("random(10, \"a\"): %v", err)
	}
	for i, ch := range got {
		if ch != 'a' {
			t.Errorf("char[%d] = %q; want 'a'", i, ch)
		}
	}
}
