package rc

// Applying a target sets the environment the Vault client is built from, and
// applying a second one on top of the first leaves standing whatever the first
// carried and the second does not. A caller that walks the targets records the
// environment first and puts it back between them.

import (
	"os"
	"testing"
)

func TestSnapshotEnvRestoresWhatWasThere(t *testing.T) {
	setHome(t)
	clearVaultEnv(t)
	t.Setenv("VAULT_ADDR", "https://before.example.com")
	if err := os.Unsetenv("VAULT_NAMESPACE"); err != nil {
		t.Fatalf("unset VAULT_NAMESPACE: %s", err)
	}

	env := SnapshotEnv()

	c := Config{
		Current: "one",
		Vaults: map[string]*Vault{
			"one": {
				URL:        "https://one.example.com",
				Token:      "token-one",
				SkipVerify: true,
				Namespace:  "ns-one",
			},
		},
	}
	if err := c.Apply(""); err != nil {
		t.Fatalf("apply: %s", err)
	}

	env.Restore()

	assertEnv(t, "VAULT_ADDR", "https://before.example.com")
	assertEnv(t, "VAULT_SKIP_VERIFY", "")
	//A variable that was not set is not restored as an empty one: an empty
	// VAULT_NAMESPACE is a namespace as far as the client is concerned.
	if _, set := os.LookupEnv("VAULT_NAMESPACE"); set {
		t.Errorf("VAULT_NAMESPACE was not set before, and is now %q", os.Getenv("VAULT_NAMESPACE"))
	}
}

// A second target applied over a restored environment is talked to on its own
// terms, not on those of the first.
func TestSnapshotEnvSeparatesOneTargetFromTheNext(t *testing.T) {
	setHome(t)
	clearVaultEnv(t)

	c := Config{
		Vaults: map[string]*Vault{
			"one": {URL: "https://one.example.com", Token: "token-one",
				SkipVerify: true, Namespace: "ns-one"},
			"two": {URL: "https://two.example.com", Token: "token-two"},
		},
	}

	env := SnapshotEnv()
	if err := c.Apply("one"); err != nil {
		t.Fatalf("apply one: %s", err)
	}
	env.Restore()
	if err := c.Apply("two"); err != nil {
		t.Fatalf("apply two: %s", err)
	}

	assertEnv(t, "VAULT_ADDR", "https://two.example.com")
	assertEnv(t, "VAULT_TOKEN", "token-two")
	assertEnv(t, "VAULT_SKIP_VERIFY", "")
	assertEnv(t, "VAULT_NAMESPACE", "")
}
