package vault_test

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

// TestInit exercises Vault.Init against the fake sys/init endpoint and asserts
// the unseal keys and root token are returned.
func TestInit(t *testing.T) {
	v, fv := newTestVault(t)

	keys, root, err := v.Init(5, 3)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(keys) != 5 {
		t.Fatalf("expected 5 unseal keys, got %d: %v", len(keys), keys)
	}
	if root == "" {
		t.Fatal("expected a non-empty root token")
	}
	if !fv.initialized {
		t.Fatal("fake vault should be marked initialized after Init")
	}
	if fv.threshold != 3 || fv.shares != 5 {
		t.Fatalf("fake threshold/shares = %d/%d, want 3/5", fv.threshold, fv.shares)
	}
}

// TestSealKeys reads the unseal threshold from sys/seal-status.
func TestSealKeys(t *testing.T) {
	v, fv := newTestVault(t)
	fv.threshold = 3

	n, err := v.SealKeys()
	if err != nil {
		t.Fatalf("SealKeys: %v", err)
	}
	if n != 3 {
		t.Fatalf("SealKeys = %d, want 3", n)
	}
}

// TestSeal seals an unsealed vault and reports success.
func TestSeal(t *testing.T) {
	v, fv := newTestVault(t)
	fv.sealed = false

	sealed, err := v.Seal()
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !sealed {
		t.Fatal("Seal reported the vault was already sealed")
	}
	if !fv.sealed {
		t.Fatal("fake vault should be sealed after Seal")
	}
}

// TestUnseal submits the threshold number of keys and confirms the vault
// unseals. It also confirms ResetUnseal runs first by progressing from zero.
func TestUnseal(t *testing.T) {
	v, fv := newTestVault(t)
	fv.sealed = true
	fv.threshold = 3
	fv.shares = 5
	fv.progress = 1 // a stale partial attempt that ResetUnseal must clear

	if err := v.Unseal([]string{"k1", "k2", "k3"}); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if fv.sealed {
		t.Fatal("vault should be unsealed after submitting the threshold keys")
	}
}

// TestSealed reports the seal state via sys/health.
func TestSealed(t *testing.T) {
	t.Run("sealed", func(t *testing.T) {
		v, fv := newTestVault(t)
		fv.sealed = true

		sealed, err := v.Sealed()
		if err != nil {
			t.Fatalf("Sealed: %v", err)
		}
		if !sealed {
			t.Fatal("expected Sealed to report true")
		}
	})

	t.Run("unsealed", func(t *testing.T) {
		v, fv := newTestVault(t)
		fv.sealed = false

		sealed, err := v.Sealed()
		if err != nil {
			t.Fatalf("Sealed: %v", err)
		}
		if sealed {
			t.Fatal("expected Sealed to report false")
		}
	})
}

// TestReKey drives the full rekey state machine: cancel any prior rekey, start
// a new one, prompt for the required existing keys (fed through the injected
// reader), and collect the freshly minted keys.
func TestReKey(t *testing.T) {
	v, fv := newTestVault(t)
	fv.threshold = 2     // existing keys required to authorize the rekey
	fv.rekeyRequired = 2 // prompts to expect

	// Feed the two unseal keys the rekey prompt will read.
	prompt.SetReader(strings.NewReader("old-key-1\nold-key-2\n"))
	t.Cleanup(func() { prompt.SetReader(nil) })

	keys, err := v.ReKey(5, 3, nil)
	if err != nil {
		t.Fatalf("ReKey: %v", err)
	}
	if len(keys) != 5 {
		t.Fatalf("expected 5 new keys, got %d: %v", len(keys), keys)
	}
	if fv.rekeyActive {
		t.Fatal("rekey should be inactive after completion")
	}
}
