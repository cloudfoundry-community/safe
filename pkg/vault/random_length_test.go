// White-box tests for what random() does with a length no password can have,
// and for the Password method that hands one to it. `safe gen 0 secret/db pw'
// used to store an empty string and report success.
package vault

import (
	"strings"
	"testing"
)

func TestRandomRefusesALengthBelowOne(t *testing.T) {
	t.Parallel()

	for _, n := range []int{0, -1, -64} {
		got, err := random(n, "a-zA-Z0-9")
		if err == nil {
			t.Errorf("random(%d) = %q, want a refusal", n, got)
			continue
		}
		//The length is said back because it is the argument that has to
		// change, and because a caller passing 0 usually did not mean to.
		if !strings.Contains(err.Error(), "0") && !strings.Contains(err.Error(), "-") {
			t.Errorf("error %q should name the length %d", err, n)
		}
	}
}

// Password is where the length arrives from the command line, and a refused
// one has to leave the key alone rather than store the empty string it would
// otherwise have generated.
func TestPasswordRefusesALengthBelowOneWithoutSettingTheKey(t *testing.T) {
	t.Parallel()

	s := NewSecret()
	if err := s.Password("pw", 0, "a-zA-Z0-9", false); err == nil {
		t.Fatal("Password with a length of 0 returned nil, want a refusal")
	}
	if s.Has("pw") {
		t.Errorf("pw = %q, want the key left unset", s.Get("pw"))
	}
}

// A password of one character is a poor password but a real one, so the line
// is at zero rather than at some judgement about strength.
func TestPasswordAcceptsALengthOfOne(t *testing.T) {
	t.Parallel()

	s := NewSecret()
	if err := s.Password("pw", 1, "a-zA-Z0-9", false); err != nil {
		t.Fatalf("Password: %v", err)
	}
	if got := s.Get("pw"); len(got) != 1 {
		t.Errorf("pw = %q, want one character", got)
	}
}
