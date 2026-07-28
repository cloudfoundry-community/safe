package vault_test

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

// TestReKeyCancelsOnClosedStdin covers the abort path: stdin ends before the
// required unseal keys have been entered. ReKey must return an error to its
// caller so the deferred cancel runs, leaving no rekey in progress on the
// server. A prompt that terminates the process instead would skip that defer
// and strand the Vault mid-rekey.
//
// Both cases assert on the fake's rekey state rather than on the cancel call
// itself: the fake only clears rekeyActive when the DELETE arrives, and only
// the deferred cancel sends one here.
func TestReKeyCancelsOnClosedStdin(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"no keys entered at all", ""},
		{"stdin closes partway through the keys", "old-key-1\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, fv := newTestVault(t)
			fv.threshold = 2
			fv.rekeyRequired = 2

			prompt.SetReader(strings.NewReader(tt.input))
			t.Cleanup(func() { prompt.SetReader(nil) })

			keys, err := v.ReKey(5, 3, nil)
			if err == nil {
				t.Fatalf("ReKey: expected an error, got keys %v", keys)
			}
			if keys != nil {
				t.Errorf("ReKey: expected no keys on failure, got %v", keys)
			}

			// The message comes from the client rejecting an empty key, and
			// is what the caller prints. Asserting on it keeps safe out of
			// the business of inventing its own wording for this failure.
			want := "key submission failed: no key provided"
			if !strings.Contains(err.Error(), want) {
				t.Errorf("ReKey error = %q, want it to contain %q", err, want)
			}

			if fv.rekeyNonce == "" {
				t.Fatal("expected the rekey to have been started before it failed")
			}
			if fv.rekeyActive {
				t.Error("rekey still in progress: the deferred cancel did not run")
			}
		})
	}
}
