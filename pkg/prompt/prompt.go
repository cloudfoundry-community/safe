package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jhunt/go-ansi"
	"github.com/mattn/go-isatty"
	"golang.org/x/term"
)

var in *bufio.Reader

// SetReader replaces the reader used by Normal and readline. Passing nil resets
// to the default (os.Stdin). Call this in tests to inject deterministic input.
func SetReader(r io.Reader) {
	if r == nil {
		in = nil
		return
	}
	in = bufio.NewReader(r)
}

func readline() string {
	if in == nil {
		in = bufio.NewReader(os.Stdin)
	}

	s, err := in.ReadString('\n')
	// ReadString returns any data read before the error, so a final line
	// without a trailing newline arrives together with io.EOF. Trim and
	// return that value; only treat EOF as end-of-input when no data remains.
	line := strings.TrimSuffix(strings.TrimSuffix(s, "\r\n"), "\n")
	if err != nil {
		if errors.Is(err, io.EOF) {
			if line != "" {
				return line
			}
			// stdin closed or pipe ended with no further input; print a
			// newline so the terminal is left on a clean line, then exit.
			// Without this the caller loops forever prompting for input
			// that will never arrive.
			fmt.Fprintln(os.Stderr, "")
			os.Exit(1)
		}
		// Non-EOF read error: surface it and exit rather than silently
		// returning empty input that could be mistaken for a valid value.
		fmt.Fprintf(os.Stderr, "error reading input: %s\n", err)
		os.Exit(1)
	}
	return line
}

func Normal(label string, args ...any) string {
	_, _ = ansi.Fprintf(os.Stderr, label, args...)
	return readline()
}

func Secure(label string, args ...any) string {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return readline()
	}

	_, _ = ansi.Fprintf(os.Stderr, label, args...)
	b, _ := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = ansi.Fprintf(os.Stderr, "\n")
	return string(b)
}
