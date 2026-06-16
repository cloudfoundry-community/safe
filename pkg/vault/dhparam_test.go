// White-box tests for the unexported genDHParam() function (dhparam.go).
// Only the bits-validation error path is tested; actual openssl invocation
// is not performed.
package vault

import (
	"strings"
	"testing"
)

// TestGenDHParamInvalidBitsReturnsError verifies that bit counts other than
// 1024, 2048, and 4096 are rejected before openssl is invoked.
func TestGenDHParamInvalidBitsReturnsError(t *testing.T) {
	t.Parallel()

	invalid := []int{0, 1, 512, 1023, 1025, 2047, 2049, 3000, 4095, 4097, 8192, -1}

	for _, bits := range invalid {
		bits := bits
		t.Run("", func(t *testing.T) {
			t.Parallel()
			_, err := genDHParam(bits)
			if err == nil {
				t.Errorf("genDHParam(%d): expected error, got nil", bits)
			}
		})
	}
}

// TestGenDHParamErrorMessageContainsBits verifies the error message includes
// the invalid bit count so operators can diagnose the rejection.
func TestGenDHParamErrorMessageContainsBits(t *testing.T) {
	t.Parallel()

	_, err := genDHParam(512)
	if err == nil {
		t.Fatal("expected error for bits=512, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "512") {
		t.Errorf("error message %q does not mention the invalid bits value 512", msg)
	}
}
