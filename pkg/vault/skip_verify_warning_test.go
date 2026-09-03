// The insecure-TLS warning is opt-in. Callers that target a Vault with a
// self-signed certificate are the common case for skip-verify, and a line
// written to stderr without being asked for breaks the scripts and tools that
// wrap safe.
package vault

import (
	"os"
	"strings"
	"testing"
)

// captureStderr runs fn with os.Stderr pointed at a pipe and returns what was
// written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	realStderr := os.Stderr
	os.Stderr = w

	fn()

	os.Stderr = realStderr
	if err := w.Close(); err != nil {
		t.Fatalf("close write end: %v", err)
	}

	var out strings.Builder
	buf := make([]byte, 512)
	for {
		n, err := r.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			break
		}
	}
	_ = r.Close()
	return out.String()
}

func TestSkipVerifyWarningIsOptIn(t *testing.T) {
	for _, tc := range []struct {
		name       string
		skipVerify bool
		env        string
		warns      bool
	}{
		{name: "skip verify with no opt-in stays quiet", skipVerify: true, env: "", warns: false},
		{name: "skip verify with the opt-in warns", skipVerify: true, env: "1", warns: true},
		{name: "an opt-in value other than 1 stays quiet", skipVerify: true, env: "true", warns: false},
		{name: "verification on never warns", skipVerify: false, env: "1", warns: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SAFE_SKIP_VERIFY_WARNING", tc.env)

			out := captureStderr(t, func() { warnSkipVerify(tc.skipVerify) })

			warned := strings.Contains(out, "TLS certificate verification disabled")
			if warned != tc.warns {
				t.Errorf("warned = %v, want %v (stderr %q)", warned, tc.warns, out)
			}
		})
	}
}
