package vault_test

import (
	"errors"
	"io"
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
// It must also abort without submitting the keys already typed: Submit posts
// each key to the server in turn, so padding the short slice with an empty
// string and submitting it anyway would transmit real key material for a
// rekey already known to be unsatisfiable, before the empty entry is even
// reached. rekeyUpdateCalls never resets, unlike rekeyProgress, so it is what
// proves no key reached the server.
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

			// The prompt hit EOF before every key arrived; the error must
			// still say so, whatever wording wraps it.
			if !errors.Is(err, io.EOF) {
				t.Errorf("ReKey error = %v, want it to wrap io.EOF", err)
			}

			if fv.rekeyNonce == "" {
				t.Fatal("expected the rekey to have been started before it failed")
			}
			if fv.rekeyActive {
				t.Error("rekey still in progress: the deferred cancel did not run")
			}
			if fv.rekeyUpdateCalls != 0 {
				t.Errorf("rekeyUpdateCalls = %d, want 0: a key was submitted although the set could not be completed", fv.rekeyUpdateCalls)
			}
		})
	}
}
