package vault

import (
	"fmt"
	"os"
	"os/exec"
)

func genDHParam(bits int) (string, error) {
	// Validate bits parameter
	if bits != 1024 && bits != 2048 && bits != 4096 {
		return "", fmt.Errorf("invalid DH parameter bits: %d (must be 1024, 2048, or 4096)", bits)
	}
	cmd := exec.Command("openssl", "dhparam", fmt.Sprintf("%d", bits)) // #nosec G204 - bits parameter is validated
	cmd.Stderr = os.Stderr

	// output runs command and returns output
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}
