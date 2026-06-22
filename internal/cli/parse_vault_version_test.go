package cli

// Tests for parseVaultVersion (server.go). Pure regex/strconv function;
// no network, no Vault, no filesystem access.
//
// Covered branches:
//   - happy path: standard "Vault v1.15.2" output
//   - no match:   arbitrary garbage bytes
//   - incomplete: "v1." — minor group missing
//   - major parse error: cannot arise via the regex (only matches [0-9]+),
//     so overflow is the only triggerable parse failure.
//   - minor overflow: integer exceeding uint64 max
//   - embedded version in longer output (e.g. real vault version command output)

import "testing"

func TestParseVaultVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantMajor uint64
		wantMinor uint64
		wantOK    bool
	}{
		{
			name:      "standard vault version output",
			input:     "Vault v1.15.2",
			wantMajor: 1,
			wantMinor: 15,
			wantOK:    true,
		},
		{
			name:      "version embedded in multi-line output",
			input:     "Vault v0.7.3\nCaveats: none\n",
			wantMajor: 0,
			wantMinor: 7,
			wantOK:    true,
		},
		{
			name:      "old vault triggers backend key (major=0, minor<8)",
			input:     "Vault v0.7.0",
			wantMajor: 0,
			wantMinor: 7,
			wantOK:    true,
		},
		{
			name:      "modern vault major=1",
			input:     "Vault v1.0.0",
			wantMajor: 1,
			wantMinor: 0,
			wantOK:    true,
		},
		{
			name:   "garbage input — no match",
			input:  "not a version string",
			wantOK: false,
		},
		{
			name:   "empty input",
			input:  "",
			wantOK: false,
		},
		{
			name:   "partial version missing minor — v1. only",
			input:  "v1.",
			wantOK: false,
		},
		{
			name:   "letter in version digits",
			input:  "vA.B.C",
			wantOK: false,
		},
		// Minor overflow: 18446744073709551616 exceeds uint64 max; strconv.ParseUint fails.
		{
			name:   "minor version overflows uint64",
			input:  "Vault v1.18446744073709551616",
			wantOK: false,
		},
		// Major overflow: same overflow applied to major.
		{
			name:   "major version overflows uint64",
			input:  "Vault v18446744073709551616.0",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			maj, min, ok := parseVaultVersion([]byte(tc.input))
			if ok != tc.wantOK {
				t.Fatalf("ok: got %v, want %v (input=%q)", ok, tc.wantOK, tc.input)
			}
			if !ok {
				return // zero values on failure are defined; no further assertion needed
			}
			if maj != tc.wantMajor {
				t.Errorf("major: got %d, want %d", maj, tc.wantMajor)
			}
			if min != tc.wantMinor {
				t.Errorf("minor: got %d, want %d", min, tc.wantMinor)
			}
		})
	}
}
