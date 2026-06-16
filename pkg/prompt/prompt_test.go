package prompt

import (
	"bufio"
	"strings"
	"testing"
)

// readline reads from the package-level *bufio.Reader `in`. These tests inject
// a reader over a fixed string to exercise the EOF-handling behavior without a
// real stdin. The exit-on-empty-EOF path is intentionally not covered here
// because it calls os.Exit.
func TestReadline(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"line with trailing newline", "hello\nrest\n", "hello"},
		{"crlf line ending", "hello\r\n", "hello"},
		{"final line without newline arrives with EOF", "secret", "secret"},
		{"value with surrounding content preserved", "  spaced  \n", "  spaced  "},
		{"empty line followed by more input", "\nnext\n", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in = bufio.NewReader(strings.NewReader(tt.input))
			defer func() { in = nil }()

			if got := readline(); got != tt.want {
				t.Errorf("readline() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestReadlineConsumesSequentially verifies multiple reads advance through the
// buffer, including a final unterminated value returned alongside io.EOF.
func TestReadlineConsumesSequentially(t *testing.T) {
	in = bufio.NewReader(strings.NewReader("first\nsecond\nthird"))
	defer func() { in = nil }()

	for _, want := range []string{"first", "second", "third"} {
		if got := readline(); got != want {
			t.Errorf("readline() = %q, want %q", got, want)
		}
	}
}
