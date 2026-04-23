package main

import (
	"testing"
	"time"
)

func TestDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"1h", time.Hour},
		{"24h", 24 * time.Hour},
		{"1d", 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
		{"1m", 30 * 24 * time.Hour},
		{"2y", 2 * 365 * 24 * time.Hour},
		{"10y", 10 * 365 * 24 * time.Hour},
		{"100y", 100 * 365 * 24 * time.Hour},
	}
	for _, c := range cases {
		got, err := duration(c.in)
		if err != nil {
			t.Errorf("duration(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("duration(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestDurationOverflow(t *testing.T) {
	// max int64 nanoseconds ≈ 292 years of hours. Values larger than the
	// units-appropriate bound must return an overflow error rather than
	// silently wrapping.
	overflows := []string{
		"9999999999999h",
		"9999999999999d",
		"9999999999999m",
		"1000y",
	}
	for _, s := range overflows {
		if _, err := duration(s); err == nil {
			t.Errorf("duration(%q) expected overflow error, got nil", s)
		}
	}
}

func TestDurationUnrecognized(t *testing.T) {
	for _, s := range []string{"", "10", "10x", "abc", "10 years"} {
		if _, err := duration(s); err == nil {
			t.Errorf("duration(%q) expected error, got nil", s)
		}
	}
}
