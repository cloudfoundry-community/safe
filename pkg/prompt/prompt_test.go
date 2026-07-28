package prompt

import (
	"bufio"
	"errors"
	"io"
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

// TestReadLine covers the error-returning reader used by callers that must run
// cleanup when the input ends. It reads the same values as readline, and hands
// back io.EOF where readline exits the process.
func TestReadLine(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantEOF bool
	}{
		{"line with trailing newline", "hello\nrest\n", "hello", false},
		{"crlf line ending", "hello\r\n", "hello", false},
		{"final line without newline", "secret", "secret", false},
		{"empty line followed by more input", "\nnext\n", "", false},
		{"exhausted input reports EOF", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in = bufio.NewReader(strings.NewReader(tt.input))
			defer func() { in = nil }()

			got, err := readLine()
			if tt.wantEOF {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("readLine() error = %v, want io.EOF", err)
				}
			} else if err != nil {
				t.Fatalf("readLine() error = %v, want nil", err)
			}
			if got != tt.want {
				t.Errorf("readLine() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestReadLineEOFAfterLastValue verifies the final unterminated value arrives
// with no error and the read that follows it reports io.EOF. Losing that value
// would reintroduce the dropped-input bug the trailing-newline handling fixes.
func TestReadLineEOFAfterLastValue(t *testing.T) {
	in = bufio.NewReader(strings.NewReader("first\nlast"))
	defer func() { in = nil }()

	for _, want := range []string{"first", "last"} {
		got, err := readLine()
		if err != nil {
			t.Fatalf("readLine() error = %v, want nil", err)
		}
		if got != want {
			t.Fatalf("readLine() = %q, want %q", got, want)
		}
	}

	got, err := readLine()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("readLine() error = %v, want io.EOF", err)
	}
	if got != "" {
		t.Errorf("readLine() = %q, want empty string at EOF", got)
	}
}
