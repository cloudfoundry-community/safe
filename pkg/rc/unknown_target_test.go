package rc

import (
	"strings"
	"testing"
)

// The error has to name where the unknown target came from, so a stale
// $SAFE_TARGET or a typo after -T does not read as a problem with the
// saved current target.
func TestVaultUnknownTargetNamesItsSource(t *testing.T) {
	for _, tc := range []struct {
		name    string
		which   string
		env     string
		current string
		want    string
	}{
		{"saved current target", "", "", "ghost", "Current target 'ghost' not found in ~/.saferc"},
		{"-T flag", "ghost", "", "prod", "Target 'ghost' (from -T) not found in ~/.saferc"},
		{"-T flag overriding the environment", "ghost", "other", "prod", "Target 'ghost' (from -T) not found in ~/.saferc"},
		{"$SAFE_TARGET", "ghost", "ghost", "prod", "Target 'ghost' (from $SAFE_TARGET) not found in ~/.saferc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SAFE_TARGET", tc.env)
			c := twoTargets()
			c.Current = tc.current
			_, err := c.Vault(tc.which)
			if err == nil {
				t.Fatal("Vault returned nil, want an unknown-target error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}
