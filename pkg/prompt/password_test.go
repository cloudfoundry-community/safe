package prompt

// readPassword turns off terminal echo, which is only possible on a
// terminal. Its callers guard the call with an isatty check, so the contract
// worth pinning here is what happens when that guard is bypassed: a stdin
// that is not a terminal is an error handed back to the caller, never a
// silent empty string that could be mistaken for a password someone typed.
// The echo-off success path needs a real TTY and is exercised by hand, not
// here.
//
// These tests swap the process-global os.Stdin and os.Stderr -- do NOT add
// t.Parallel.

import (
	"os"
	"strings"
	"testing"
)

// swapStdinWithPipe points os.Stdin at the read end of a fresh pipe and
// restores it via t.Cleanup.
func swapStdinWithPipe(t *testing.T) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = orig
		_ = r.Close()
		_ = w.Close()
	})
}

func TestReadPasswordRefusesAStdinThatIsNotATerminal(t *testing.T) {
	swapStdinWithPipe(t)

	er, ew, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origErr := os.Stderr
	os.Stderr = ew
	t.Cleanup(func() { os.Stderr = origErr })

	got, readErr := readPassword("Passphrase @Y{(hidden)}: ")

	_ = ew.Close()
	os.Stderr = origErr
	buf := make([]byte, 4096)
	n, _ := er.Read(buf)
	_ = er.Close()
	stderr := string(buf[:n])

	if readErr == nil {
		t.Fatal("reading a password from a pipe should be an error")
	}
	if got != "" {
		t.Errorf("a failed read handed back %q, want nothing at all", got)
	}
	//The label was already on the screen when the read failed, and the
	// newline after it keeps whatever is printed next off the prompt's line.
	if !strings.Contains(stderr, "Passphrase") {
		t.Errorf("the prompt label never printed; stderr was %q", stderr)
	}
	if !strings.HasSuffix(stderr, "\n") {
		t.Errorf("stderr should end with a newline, got %q", stderr)
	}
}
