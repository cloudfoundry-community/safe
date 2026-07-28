package prompt

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestSetReader verifies the injection seam: a non-nil reader wraps the
// supplied io.Reader, and nil resets the global to nil (lazy-init on next read).
func TestSetReader(t *testing.T) {
	// Non-nil: wraps supplied reader.
	SetReader(strings.NewReader("data\n"))
	if in == nil {
		t.Fatal("SetReader(non-nil): in is nil, expected bufio.Reader")
	}

	// Nil: resets to nil so the next readline rebuilds from os.Stdin.
	SetReader(nil)
	if in != nil {
		t.Fatal("SetReader(nil): in is not nil, expected reset")
	}
}

// TestNormal verifies that Normal returns the line read from the injected
// reader. The label is written to stderr (not asserted here — capturing
// os.Stderr requires a process-global swap that must not run in parallel).
// Global reader is reset after each sub-test so tests are isolated.
//
// No t.Parallel — test mutates the package-level `in` reader.
func TestNormal(t *testing.T) {
	tests := []struct {
		name  string
		label string
		input string
		want  string
	}{
		{
			name:  "returns typed line",
			label: "Password: ",
			input: "hunter2\n",
			want:  "hunter2",
		},
		{
			name:  "returns line without trailing newline",
			label: "Enter value: ",
			input: "value",
			want:  "value",
		},
		{
			name:  "returns empty line",
			label: "Name: ",
			input: "\n",
			want:  "",
		},
		{
			name:  "format substitution in label, return value is independent",
			label: "Q%d: ",
			input: "answer\n",
			want:  "answer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetReader(strings.NewReader(tt.input))
			defer SetReader(nil)

			// Use 42 as the format arg; the label may or may not have a %d verb.
			// The returned value is what matters — label formatting is ansi delegation.
			var got string
			if strings.Contains(tt.label, "%") {
				got = Normal(tt.label, 42)
			} else {
				got = Normal(tt.label)
			}
			if got != tt.want {
				t.Errorf("Normal() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSecure_NonTTY verifies the non-TTY branch of Secure via subprocess
// re-exec. When os.Stdin is not a terminal, Secure falls through to readline.
//
// Using a subprocess ensures isatty.IsTerminal returns false regardless of
// whether the parent test process runs with a real TTY, because the child's
// stdin is a pipe (via cmd.Stdin = strings.NewReader(...)).
//
// SKIPPED (TTY branch): term.ReadPassword requires a real /dev/tty fd.
// Testing it would require opening /dev/tty, which is unavailable in most CI
// environments. The branch is marked as intentionally untested.
func TestSecure_NonTTY(t *testing.T) {
	// Guard: the child process runs the actual Secure call.
	if os.Getenv("SAFE_TEST_SECURE_NONTTY") == "1" {
		// The child's stdin is a pipe (set by the parent below), so
		// isatty.IsTerminal returns false and Secure calls readline.
		// Inject a reader so readline doesn't block on the pipe.
		SetReader(strings.NewReader("s3cr3t\n"))
		result := Secure("Password: ")
		// Write result to stdout so the parent can read it.
		os.Stdout.WriteString(result + "\n")
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestSecure_NonTTY")
	cmd.Env = append(os.Environ(), "SAFE_TEST_SECURE_NONTTY=1")
	// Attach a pipe as stdin so isatty reports false in the child.
	cmd.Stdin = strings.NewReader("")

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child process failed: %v", err)
	}

	got := strings.TrimRight(string(out), "\n")
	want := "s3cr3t"
	if got != want {
		t.Errorf("Secure() non-TTY = %q, want %q", got, want)
	}
}

// TestNormalE verifies that NormalE returns the line read from the injected
// reader, and reports io.EOF instead of exiting once the reader is exhausted.
//
// No t.Parallel — test mutates the package-level `in` reader.
func TestNormalE(t *testing.T) {
	SetReader(strings.NewReader("hunter2\n"))
	defer SetReader(nil)

	got, err := NormalE("Password: ")
	if err != nil {
		t.Fatalf("NormalE() error = %v, want nil", err)
	}
	if got != "hunter2" {
		t.Errorf("NormalE() = %q, want %q", got, "hunter2")
	}

	got, err = NormalE("Password: ")
	if !errors.Is(err, io.EOF) {
		t.Fatalf("NormalE() at EOF: error = %v, want io.EOF", err)
	}
	if got != "" {
		t.Errorf("NormalE() at EOF = %q, want empty string", got)
	}
}

// TestReadLine_Exported verifies the exported wrapper reads through the
// injection seam and surfaces io.EOF rather than exiting.
func TestReadLine_Exported(t *testing.T) {
	SetReader(strings.NewReader("value\n"))
	defer SetReader(nil)

	got, err := ReadLine()
	if err != nil {
		t.Fatalf("ReadLine() error = %v, want nil", err)
	}
	if got != "value" {
		t.Errorf("ReadLine() = %q, want %q", got, "value")
	}

	if _, err = ReadLine(); !errors.Is(err, io.EOF) {
		t.Fatalf("ReadLine() at EOF: error = %v, want io.EOF", err)
	}
}

// TestSecureE_NonTTY verifies the non-TTY branch of SecureE via subprocess
// re-exec, for the same reason as TestSecure_NonTTY: the child's stdin is a
// pipe, so isatty.IsTerminal reports false deterministically.
//
// The exhausted-reader case is the point of SecureE. The child exiting 0 after
// reporting io.EOF is what proves SecureE returned to its caller instead of
// calling os.Exit and skipping every pending defer.
func TestSecureE_NonTTY(t *testing.T) {
	// Guard: the child process runs the actual SecureE call.
	if mode := os.Getenv("SAFE_TEST_SECUREE_NONTTY"); mode != "" {
		input := "s3cr3t\n"
		if mode == "eof" {
			input = ""
		}
		SetReader(strings.NewReader(input))

		value, err := SecureE("Password: ")
		switch {
		case errors.Is(err, io.EOF):
			os.Stdout.WriteString("EOF\n")
		case err != nil:
			os.Stdout.WriteString("ERR " + err.Error() + "\n")
		default:
			os.Stdout.WriteString(value + "\n")
		}
		os.Exit(0)
	}

	tests := []struct {
		name string
		mode string
		want string
	}{
		{"returns typed value", "value", "s3cr3t"},
		{"returns EOF on exhausted input", "eof", "EOF"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestSecureE_NonTTY")
			cmd.Env = append(os.Environ(), "SAFE_TEST_SECUREE_NONTTY="+tt.mode)
			// Attach a pipe as stdin so isatty reports false in the child.
			cmd.Stdin = strings.NewReader("")

			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("child process failed: %v", err)
			}

			if got := strings.TrimRight(string(out), "\n"); got != tt.want {
				t.Errorf("SecureE() non-TTY = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestReadline_EmptyEOFExits is a subprocess test for the os.Exit(1) path in
// readline. When stdin reaches EOF with no data (empty pipe), readline prints
// a newline to stderr and exits with code 1.
//
// The child process injects an empty reader and calls Normal(), which hits
// readline's empty-EOF branch and os.Exit(1). The parent asserts exit code 1.
func TestReadline_EmptyEOFExits(t *testing.T) {
	// Guard: the child process runs this branch.
	if os.Getenv("SAFE_TEST_READLINE_EOF_EXIT") == "1" {
		// Empty reader: ReadString hits io.EOF immediately with s == "".
		SetReader(strings.NewReader(""))
		Normal("prompt: ") // reaches os.Exit(1)
		// Unreachable.
		os.Exit(0)
	}

	// Parent process: re-exec as child with the guard env set.
	cmd := exec.Command(os.Args[0], "-test.run=TestReadline_EmptyEOFExits")
	cmd.Env = append(os.Environ(), "SAFE_TEST_READLINE_EOF_EXIT=1")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected child process to exit non-zero, but it exited 0")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError, got %T: %v", err, err)
	}

	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}
}
