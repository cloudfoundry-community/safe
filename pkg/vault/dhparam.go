package vault

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// dhparamGen is genDHParam behind a package-level variable, so cmdDhparam in
// internal/cli can generate several secrets' parameters concurrently while
// tests substitute a fast stub for the real openssl invocation -- see the
// SetDhparamGenForTest hook in export_test.go, which internal/cli cannot use
// directly since neither this var nor genDHParam is exported.
var dhparamGen = genDHParam

func genDHParam(bits int) (string, error) {
	// Validate bits parameter
	if bits != 1024 && bits != 2048 && bits != 4096 {
		return "", fmt.Errorf("invalid DH parameter bits: %d (must be 1024, 2048, or 4096)", bits)
	}
	cmd := exec.Command("openssl", "dhparam", fmt.Sprintf("%d", bits)) // #nosec G204 - bits parameter is validated
	// Several of these may now run at once under cmdDhparam's parallel
	// grouping; openssl writes its progress dots straight to stderr, and
	// several of those streams interleaved on safe's own stderr would be
	// unreadable. So stderr is captured instead of connected live, and
	// surfaced only in the returned error on failure.
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// output runs command and returns output
	output, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", fmt.Errorf("%w: %s", err, msg)
		}
		return "", err
	}
	return string(output), nil
}
