// White-box tests for what random() does with a policy it cannot generate a
// password from. The policy arrives from `safe gen --policy', so it can be
// anything the user typed, and every one of these used to be a panic.
package vault

import (
	"strings"
	"testing"
)

// A policy goes inside a character class, and not every string is one. These
// reached regexp.MustCompile, which panics rather than returning the error.
func TestRandomRefusesAPolicyThatIsNotACharacterClass(t *testing.T) {
	t.Parallel()

	for _, policy := range []string{`a-\`, `\`, `z-a`} {
		got, err := random(16, policy)
		if err == nil {
			t.Errorf("random(16, %q) = %q, want a refusal", policy, got)
			continue
		}
		//Named so that it is clear which of several policies was the bad one,
		// and that the complaint is about the policy rather than the length.
		if !strings.Contains(err.Error(), policy) {
			t.Errorf("error %q should quote the policy %q", err, policy)
		}
	}
}

// An empty policy is what an unset variable expands to, as in
// `safe gen --policy "$POLICY"'.
func TestRandomRefusesAnEmptyPolicy(t *testing.T) {
	t.Parallel()

	if got, err := random(16, ""); err == nil {
		t.Fatalf("random(16, \"\") = %q, want a refusal", got)
	}
}

// A policy can be a character class and still leave nothing to pick from: a
// space is not one of the characters a password is made of, so keeping only
// spaces keeps nothing. This one used to reach crypto/rand with an empty set
// and panic there instead.
func TestRandomRefusesAPolicyThatKeepsNoCharacters(t *testing.T) {
	t.Parallel()

	for _, policy := range []string{" ", "\t", "é"} {
		got, err := random(16, policy)
		if err == nil {
			t.Errorf("random(16, %q) = %q, want a refusal", policy, got)
			continue
		}
		if !strings.Contains(err.Error(), policy) {
			t.Errorf("error %q should quote the policy %q", err, policy)
		}
	}
}

// The policies people actually pass go on working, including the one the CLI
// sets when --policy is not given.
func TestRandomKeepsGeneratingForUsablePolicies(t *testing.T) {
	t.Parallel()

	for _, policy := range []string{"a-zA-Z0-9", "0-9", "a", "!-~", "^", "-"} {
		got, err := random(16, policy)
		if err != nil {
			t.Errorf("random(16, %q): %v", policy, err)
			continue
		}
		if len(got) != 16 {
			t.Errorf("random(16, %q) returned %d characters: %q", policy, len(got), got)
		}
	}
}
