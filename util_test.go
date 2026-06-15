package main

import (
	"testing"
	"time"
)

// TestDuration covers the duration() parser. It accepts a non-negative integer
// followed by a unit suffix: H/h (hours), D/d (days = 24h), M/m (months = 30d),
// or Y/y (years = 365d). Any other input is an error.
func TestDuration(t *testing.T) {
	cases := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		// Zero values.
		{"0H", 0, false},
		{"0h", 0, false},
		{"0D", 0, false},
		{"0d", 0, false},
		{"0M", 0, false},
		{"0m", 0, false},
		{"0Y", 0, false},
		{"0y", 0, false},

		// Non-zero values resolve to the correct duration.
		{"1H", time.Hour, false},
		{"2h", 2 * time.Hour, false},
		{"24H", 24 * time.Hour, false},
		{"1D", 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"7D", 7 * 24 * time.Hour, false},
		{"1M", 30 * 24 * time.Hour, false},
		{"1m", 30 * 24 * time.Hour, false},
		{"12M", 12 * 30 * 24 * time.Hour, false},
		{"1Y", 365 * 24 * time.Hour, false},
		{"1y", 365 * 24 * time.Hour, false},
		{"2Y", 2 * 365 * 24 * time.Hour, false},
		{"100H", 100 * time.Hour, false},

		// Invalid: unrecognized suffix — no S (seconds) or W (weeks) support.
		{"1s", 0, true},
		{"1S", 0, true},
		{"1w", 0, true},
		{"1W", 0, true},

		// Invalid: no suffix
		{"60", 0, true},

		// Invalid: empty string
		{"", 0, true},

		// Invalid: non-numeric prefix
		{"xH", 0, true},
		{"H", 0, true},

		// Invalid: floating point not accepted by regex
		{"1.5H", 0, true},

		// Invalid: negative sign not accepted by regex (^\d+)
		{"-1H", 0, true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			got, err := duration(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("duration(%q): expected error, got %v", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("duration(%q): unexpected error: %v", tc.input, err)
				return
			}
			if got != tc.want {
				t.Errorf("duration(%q): got %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestUniq(t *testing.T) {
	cases := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "nil input returns empty slice",
			input: nil,
			want:  []string{},
		},
		{
			name:  "empty input",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "no duplicates preserved in order",
			input: []string{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "adjacent duplicates deduplicated",
			input: []string{"a", "a", "b"},
			want:  []string{"a", "b"},
		},
		{
			name:  "non-adjacent duplicates deduplicated",
			input: []string{"a", "b", "a"},
			want:  []string{"a", "b"},
		},
		{
			name:  "all same deduplicated to one",
			input: []string{"x", "x", "x"},
			want:  []string{"x"},
		},
		{
			name:  "first occurrence kept for ordering",
			input: []string{"c", "b", "a", "b", "c"},
			want:  []string{"c", "b", "a"},
		},
		{
			name:  "single element",
			input: []string{"z"},
			want:  []string{"z"},
		},
		{
			name:  "empty strings deduplicated",
			input: []string{"", "a", ""},
			want:  []string{"", "a"},
		},
		{
			name:  "mixed paths",
			input: []string{"secret/foo", "secret/bar", "secret/foo"},
			want:  []string{"secret/foo", "secret/bar"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := uniq(tc.input)
			if len(got) != len(tc.want) {
				t.Errorf("uniq(%v): got len %d (%v), want len %d (%v)",
					tc.input, len(got), got, len(tc.want), tc.want)
				return
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("uniq(%v): index %d got %q, want %q", tc.input, i, got[i], tc.want[i])
				}
			}
		})
	}
}
