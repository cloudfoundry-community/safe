package parallel_test

import (
	"runtime"
	"testing"

	"github.com/cloudfoundry-community/safe/internal/parallel"
)

func TestIOLimit(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want int
	}{
		{"unset", "", 16},
		{"override", "8", 8},
		{"minimum", "1", 1},
		{"maximum", "64", 64},
		{"clamped low", "0", 1},
		{"clamped negative", "-3", 1},
		{"clamped high", "100", 64},
		{"garbage", "lots", 16},
		{"float", "16.5", 16},
		{"trailing junk", "8x", 16},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.env == "" {
				// t.Setenv("", ...) is invalid; unset the variable
				// explicitly so a developer shell's value cannot leak in.
				t.Setenv("SAFE_CONCURRENCY", "")
			} else {
				t.Setenv("SAFE_CONCURRENCY", c.env)
			}
			if got := parallel.IOLimit(); got != c.want {
				t.Errorf("IOLimit() with SAFE_CONCURRENCY=%q = %d, want %d", c.env, got, c.want)
			}
		})
	}
}

func TestCPULimit(t *testing.T) {
	want := max(runtime.NumCPU(), 4)
	if got := parallel.CPULimit(); got != want {
		t.Errorf("CPULimit() = %d, want %d", got, want)
	}
}
