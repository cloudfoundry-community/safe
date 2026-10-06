package cli

import (
	"io"
	"os"
	"runtime"
	"strings"

	fmt "github.com/jhunt/go-ansi"
)

// resolveRootToken picks the root token for a local Vault. A fresh
// initialization already yields a root token; only a pre-existing vault
// (unsealed with a supplied key) needs one generated via sys/generate-root.
// OpenBao removed that API, so generation is a last resort rather than the
// default path.
func resolveRootToken(initToken string, generate func() (string, error)) (string, error) {
	if initToken != "" {
		return initToken, nil
	}
	return generate()
}

// readRootTokenFile reads the root token of an existing vault from the file
// named by --root-token-file. Surrounding whitespace is trimmed, and a file
// that holds nothing, or more than one word, is refused. A file that group
// or others can read draws a warning on warn but is still used. No error or
// warning ever repeats what the file holds.
func readRootTokenFile(path string, warn io.Writer) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("Unable to read the root token file: %w", err)
	}
	b, err := os.ReadFile(path) // #nosec G304 -- the operator names this file
	if err != nil {
		return "", fmt.Errorf("Unable to read the root token file: %w", err)
	}
	token := strings.TrimSpace(string(b))
	if token == "" {
		return "", fmt.Errorf("The root token file %s is empty", path)
	}
	if strings.ContainsAny(token, " \t\r\n") {
		return "", fmt.Errorf("The root token file %s must hold a single token and nothing else", path)
	}
	// Windows reports synthetic permission bits, so the check would only
	// ever cry wolf there.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		_, _ = fmt.Fprintf(warn, "@Y{WARNING: the root token file %s is readable by group or others (mode %04o)}\n", path, info.Mode().Perm())
	}
	return token, nil
}
