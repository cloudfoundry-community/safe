// RenewLease, NewRootToken, and SaveSealKeys are the three token-and-seal
// operations safe runs against a live Vault: `safe renew` keeps the current
// token alive, `safe rekey` can mint a new root token from unseal keys, and
// init stores the unseal keys under secret/vault/seal/keys. Each is tested
// against the fake's auth and sys endpoints.

package vault_test

import (
	"strings"
	"testing"
)

func TestRenewLease(t *testing.T) {
	t.Parallel()
	v, _ := newTestVault(t)

	if err := v.RenewLease(); err != nil {
		t.Fatalf("RenewLease: %v", err)
	}
}

func TestRenewLeaseReportsARefusal(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.renewFails = true

	if err := v.RenewLease(); err == nil {
		t.Fatal("RenewLease returned nil for a token that cannot renew itself")
	}
}

// Submitting the unseal threshold's worth of keys mints the token. The fake
// encodes fakeRootToken against the client's one-time pad, and vaultkv
// formats the decoded 16 bytes as a UUID, so the expectation is the hex of
// "0123456789abcdef" in UUID grouping.
func TestNewRootToken(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.threshold = 3

	token, err := v.NewRootToken([]string{"key-a", "key-b", "key-c"})
	if err != nil {
		t.Fatalf("NewRootToken: %v", err)
	}

	want := "30313233-3435-3637-3839-616263646566"
	if token != want {
		t.Errorf("token = %q, want %q", token, want)
	}
}

func TestNewRootTokenWithTooFewKeys(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.threshold = 3

	_, err := v.NewRootToken([]string{"key-a", "key-b"})
	if err == nil {
		t.Fatal("NewRootToken returned nil below the threshold")
	}
	if !strings.Contains(err.Error(), "not enough keys") {
		t.Errorf("error %q should say there were not enough keys", err)
	}
}

func TestSaveSealKeys(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)

	if err := v.SaveSealKeys([]string{"first", "second"}); err != nil {
		t.Fatalf("SaveSealKeys: %v", err)
	}

	kv := mustGetSecret(t, fv, "secret/vault/seal/keys")
	if len(kv) != 2 || kv["key1"] != "first" || kv["key2"] != "second" {
		t.Errorf("stored keys = %v, want key1=first key2=second", kv)
	}
}

// Saving again replaces the whole secret, so keys from a larger earlier set
// do not linger past a rekey to fewer shares.
func TestSaveSealKeysReplacesTheOldSet(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/vault/seal/keys", map[string]string{
		"key1": "stale",
		"key2": "stale",
		"key3": "stale",
	})

	if err := v.SaveSealKeys([]string{"fresh"}); err != nil {
		t.Fatalf("SaveSealKeys: %v", err)
	}

	kv := mustGetSecret(t, fv, "secret/vault/seal/keys")
	if len(kv) != 1 || kv["key1"] != "fresh" {
		t.Errorf("stored keys = %v, want only key1=fresh", kv)
	}
}
