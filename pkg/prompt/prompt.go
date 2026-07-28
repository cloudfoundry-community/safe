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

// readLine reads a single line from the input reader without terminating the
// process. It returns io.EOF only when the input is exhausted and no data
// remains; a final line without a trailing newline is returned with a nil
// error, because ReadString hands back the data it read alongside io.EOF.
func readLine() (string, error) {
	if in == nil {
		in = bufio.NewReader(os.Stdin)
	}

	s, err := in.ReadString('\n')
	line := strings.TrimSuffix(strings.TrimSuffix(s, "\r\n"), "\n")
	if err != nil {
		if errors.Is(err, io.EOF) && line != "" {
			return line, nil
		}
		// Discard any partial data on a real read error so it cannot be
		// mistaken for a complete value.
		return "", err
	}
	return line, nil
}

func readline() string {
	line, err := readLine()
	if err != nil {
		if errors.Is(err, io.EOF) {
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

// readPassword prompts on stderr and reads a line with terminal echo disabled.
// The caller must have established that stdin is a terminal.
func readPassword(label string, args ...any) (string, error) {
	_, _ = ansi.Fprintf(os.Stderr, label, args...)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	_, _ = ansi.Fprintf(os.Stderr, "\n")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ReadLine reads a line of input, returning io.EOF when the input is exhausted
// instead of exiting the process. Use it when the caller has cleanup to run
// before it gives up on the input.
func ReadLine() (string, error) {
	return readLine()
}

func Normal(label string, args ...any) string {
	_, _ = ansi.Fprintf(os.Stderr, label, args...)
	return readline()
}

// NormalE is Normal, except that it returns io.EOF when the input is exhausted
// rather than exiting the process.
func NormalE(label string, args ...any) (string, error) {
	_, _ = ansi.Fprintf(os.Stderr, label, args...)
	return readLine()
}

func Secure(label string, args ...any) string {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return readline()
	}

	b, _ := readPassword(label, args...)
	return b
}

// SecureE is Secure, except that it returns io.EOF when the input is exhausted
// rather than exiting the process. It also surfaces terminal read errors that
// Secure discards.
func SecureE(label string, args ...any) (string, error) {
	if !isatty.IsTerminal(os.Stdin.Fd()) {
		return readLine()
	}

	return readPassword(label, args...)
}
