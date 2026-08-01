package cli

// Smoke tests for pure-output helpers: cmdEnvvars and cmdPrompt.
//
// Both write to os.Stdout (cmdEnvvars) or os.Stderr (cmdPrompt) and return
// nil unconditionally. We capture stdout via the existing captureStdout helper
// and use a stderr pipe for cmdPrompt.
//
// captureStdout mutates the process-global os.Stdout — do NOT add t.Parallel
// to any test in this file.

import (
	"os"
	"strings"
	"testing"
)

// captureStderr runs fn while capturing everything written to os.Stderr.
// Restores original os.Stderr on return.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = orig })

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("pipe close: %v", err)
	}
	os.Stderr = orig

	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 512)
	for {
		n, readErr := r.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if readErr != nil {
			break
		}
	}
	_ = r.Close()
	return string(buf)
}

// ---------------------------------------------------------------------------
// cmdEnvvars
// ---------------------------------------------------------------------------

func TestCmdEnvvars_OutputContainsSafeTarget(t *testing.T) {
	// No t.Parallel — captureStdout mutates os.Stdout.
	c := &CLI{opt: &Options{}, r: NewRunner()}
	out := captureStdout(t, func() {
		if err := c.cmdEnvvars("envvars"); err != nil {
			t.Fatalf("cmdEnvvars returned unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "SAFE_TARGET") {
		t.Errorf("expected SAFE_TARGET in output, got:\n%s", out)
	}
}

func TestCmdEnvvars_OutputContainsHttpProxy(t *testing.T) {
	// No t.Parallel — captureStdout mutates os.Stdout.
	c := &CLI{opt: &Options{}, r: NewRunner()}
	out := captureStdout(t, func() {
		_ = c.cmdEnvvars("envvars")
	})
	if !strings.Contains(out, "HTTP_PROXY") {
		t.Errorf("expected HTTP_PROXY in output, got:\n%s", out)
	}
}

func TestCmdEnvvars_OutputContainsSafeAllProxy(t *testing.T) {
	// No t.Parallel — captureStdout mutates os.Stdout.
	c := &CLI{opt: &Options{}, r: NewRunner()}
	out := captureStdout(t, func() {
		_ = c.cmdEnvvars("envvars")
	})
	if !strings.Contains(out, "SAFE_ALL_PROXY") {
		t.Errorf("expected SAFE_ALL_PROXY in output, got:\n%s", out)
	}
}

// safe help envvars renders its Description through escapePercent
// specifically because the body is handed to go-ansi's Printf as a format
// string, and a bare '%' in it is read as the start of a verb. safe envvars
// prints the same constant through a different path that skipped that step,
// so the percent-encoding example the help text gives ('%40') mangled into
// go-ansi's missing-verb marker instead of appearing literally.
func TestCmdEnvvars_RendersAPercentSignLiterally(t *testing.T) {
	// No t.Parallel — captureStdout mutates os.Stdout.
	c := &CLI{opt: &Options{}, r: NewRunner()}
	out := captureStdout(t, func() {
		if err := c.cmdEnvvars("envvars"); err != nil {
			t.Fatalf("cmdEnvvars returned unexpected error: %v", err)
		}
	})
	if strings.Contains(out, "MISSING") {
		t.Errorf("cmdEnvvars mangled a '%%' in its own help text:\n%s", out)
	}
	if !strings.Contains(out, "%40") {
		t.Errorf("expected the literal percent-encoding example '%%40' in the output, got:\n%s", out)
	}
}

func TestCmdEnvvars_ReturnsNil(t *testing.T) {
	// No t.Parallel — captureStdout mutates os.Stdout.
	c := &CLI{opt: &Options{}, r: NewRunner()}
	var got error
	captureStdout(t, func() {
		got = c.cmdEnvvars("envvars")
	})
	if got != nil {
		t.Errorf("expected nil error, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// cmdPrompt
// ---------------------------------------------------------------------------

func TestCmdPrompt_WritesArgsToStderr(t *testing.T) {
	// No t.Parallel — captureStderr mutates os.Stderr.
	c := &CLI{opt: &Options{}, r: NewRunner()}
	out := captureStderr(t, func() {
		if err := c.cmdPrompt("prompt", "hello", "world"); err != nil {
			t.Fatalf("cmdPrompt returned unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "hello world") {
		t.Errorf("expected 'hello world' in stderr, got: %q", out)
	}
}

func TestCmdPrompt_NoArgs_WritesEmptyLine(t *testing.T) {
	// No t.Parallel — captureStderr mutates os.Stderr.
	c := &CLI{opt: &Options{}, r: NewRunner()}
	out := captureStderr(t, func() {
		_ = c.cmdPrompt("prompt")
	})
	// strings.Join(nil, " ") == "" — expect a bare newline.
	if out != "\n" {
		t.Errorf("expected bare newline, got: %q", out)
	}
}

func TestCmdPrompt_ReturnsNil(t *testing.T) {
	// No t.Parallel — captureStderr mutates os.Stderr.
	c := &CLI{opt: &Options{}, r: NewRunner()}
	var got error
	captureStderr(t, func() {
		got = c.cmdPrompt("prompt", "message")
	})
	if got != nil {
		t.Errorf("expected nil error, got %v", got)
	}
}
