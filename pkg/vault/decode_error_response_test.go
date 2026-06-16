// Black-box tests for DecodeErrorResponse (vault.go).
package vault_test

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// TestDecodeErrorResponse_ErrorsArray verifies that a well-formed Vault error
// payload with an "errors" array is decoded into a combined error message.
func TestDecodeErrorResponse_ErrorsArray(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		body     []byte
		wantMsgs []string
	}{
		{
			name:     "single error",
			body:     []byte(`{"errors":["permission denied"]}`),
			wantMsgs: []string{"permission denied"},
		},
		{
			name:     "multiple errors joined",
			body:     []byte(`{"errors":["bad token","permission denied"]}`),
			wantMsgs: []string{"bad token", "permission denied"},
		},
		{
			name:     "empty errors array",
			body:     []byte(`{"errors":[]}`),
			wantMsgs: []string{},
		},
		{
			name:     "errors with extra fields",
			body:     []byte(`{"request_id":"abc","errors":["not found"]}`),
			wantMsgs: []string{"not found"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := vault.DecodeErrorResponse(tc.body)
			if err == nil {
				t.Fatal("DecodeErrorResponse returned nil error; want non-nil")
			}
			msg := err.Error()
			for _, want := range tc.wantMsgs {
				if !strings.Contains(msg, want) {
					t.Errorf("error message %q does not contain %q", msg, want)
				}
			}
		})
	}
}

// TestDecodeErrorResponse_NonJSONBody verifies that a non-JSON body returns an
// error indicating the non-JSON payload.
func TestDecodeErrorResponse_NonJSONBody(t *testing.T) {
	t.Parallel()

	bodies := [][]byte{
		[]byte("not json at all"),
		[]byte("<html>403 Forbidden</html>"),
		[]byte(""),
		[]byte("{bad json"),
	}

	for _, body := range bodies {
		body := body
		t.Run(string(body), func(t *testing.T) {
			t.Parallel()
			err := vault.DecodeErrorResponse(body)
			if err == nil {
				t.Errorf("DecodeErrorResponse(%q): expected error, got nil", body)
			}
		})
	}
}

// TestDecodeErrorResponse_NoErrorsKey verifies that valid JSON without an
// "errors" key returns an error (not nil).
func TestDecodeErrorResponse_NoErrorsKey(t *testing.T) {
	t.Parallel()

	cases := [][]byte{
		[]byte(`{"message":"something happened"}`),
		[]byte(`{"status":"ok"}`),
		[]byte(`{}`),
	}

	for _, body := range cases {
		body := body
		t.Run(string(body), func(t *testing.T) {
			t.Parallel()
			err := vault.DecodeErrorResponse(body)
			if err == nil {
				t.Errorf("DecodeErrorResponse(%q): expected error for missing errors key, got nil", body)
			}
		})
	}
}

// TestDecodeErrorResponse_ErrorsNotArray verifies that JSON with an "errors"
// field that is not a JSON array returns an error rather than panicking.
func TestDecodeErrorResponse_ErrorsNotArray(t *testing.T) {
	t.Parallel()

	cases := [][]byte{
		[]byte(`{"errors":"a string, not an array"}`),
		[]byte(`{"errors":42}`),
		[]byte(`{"errors":{"nested":"object"}}`),
		[]byte(`{"errors":null}`),
	}

	for _, body := range cases {
		body := body
		t.Run(string(body), func(t *testing.T) {
			t.Parallel()
			err := vault.DecodeErrorResponse(body)
			if err == nil {
				t.Errorf("DecodeErrorResponse(%q): expected error for non-array errors, got nil", body)
			}
		})
	}
}

// TestDecodeErrorResponse_NeverPanics verifies pathological inputs do not
// cause a panic.
func TestDecodeErrorResponse_NeverPanics(t *testing.T) {
	t.Parallel()

	inputs := [][]byte{
		nil,
		{},
		[]byte("null"),
		[]byte(`{"errors":[]}`),
		[]byte(`{"errors":["a","b","c"]}`),
	}

	for _, input := range inputs {
		input := input
		t.Run("", func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("DecodeErrorResponse panicked: %v (input=%q)", r, input)
				}
			}()
			_ = vault.DecodeErrorResponse(input)
		})
	}
}
