package rc

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdatePersistsMutation(t *testing.T) {
	setHome(t)

	err := Update(func(c *Config) error {
		return c.SetTarget("unit", Vault{URL: "http://127.0.0.1:8201"})
	})
	if err != nil {
		t.Fatalf("Update: %s", err)
	}

	c, err := Read()
	if err != nil {
		t.Fatalf("Read: %s", err)
	}
	if v, ok, _ := c.Find("unit"); !ok || v.URL != "http://127.0.0.1:8201" {
		t.Errorf("target not persisted: found=%v", ok)
	}
	if c.Current != "unit" {
		t.Errorf("current = %q, want %q", c.Current, "unit")
	}
}

// The lost-update defect: a writer applying its delta to state it read
// earlier erases whatever landed in between. Update must read at mutation
// time, under the lock, so a delta lands on top of the latest file.
func TestUpdateAppliesDeltaToLatestState(t *testing.T) {
	setHome(t)

	if err := Update(func(c *Config) error {
		return c.SetTarget("first", Vault{URL: "http://first"})
	}); err != nil {
		t.Fatalf("seed: %s", err)
	}

	// Another process's write, after this process last read the file.
	writeFile(t, saferc(), strings.Join([]string{
		"version: 1",
		"current: second",
		"vaults:",
		"  first:",
		"    url: http://first",
		"  second:",
		"    url: http://second",
	}, "\n")+"\n")

	if err := Update(func(c *Config) error {
		return c.SetTarget("third", Vault{URL: "http://third"})
	}); err != nil {
		t.Fatalf("Update: %s", err)
	}

	c, err := Read()
	if err != nil {
		t.Fatalf("Read: %s", err)
	}
	for _, name := range []string{"first", "second", "third"} {
		if _, ok, _ := c.Find(name); !ok {
			t.Errorf("target %q lost", name)
		}
	}
}

func TestUpdateMutationErrorAbortsWrite(t *testing.T) {
	setHome(t)

	writeFile(t, saferc(), "version: 1\ncurrent: keep\nvaults:\n  keep:\n    url: http://keep\n")
	before := readFile(t, saferc())

	sentinel := errors.New("no thanks")
	err := Update(func(c *Config) error {
		c.Current = "clobbered"
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Update error = %v, want %v", err, sentinel)
	}

	if after := readFile(t, saferc()); after != before {
		t.Errorf(".saferc changed after failed mutation:\n%s", after)
	}
}

// A legacy (version 0) file read by Update must round-trip into a valid
// version 1 file with its targets intact.
func TestUpdateUpgradesLegacyConfig(t *testing.T) {
	setHome(t)

	writeFile(t, saferc(), strings.Join([]string{
		"Current: http://legacy",
		"Targets:",
		"  http://legacy: sekrit-token",
		"Aliases:",
		"  legacy: http://legacy",
		"SkipVerify:",
		"  http://legacy: true",
	}, "\n")+"\n")

	if err := Update(func(c *Config) error { return nil }); err != nil {
		t.Fatalf("Update: %s", err)
	}

	c, err := Read()
	if err != nil {
		t.Fatalf("Read after upgrade: %s", err)
	}
	if c.Version != 1 {
		t.Errorf("version = %d, want 1", c.Version)
	}
	v, ok, _ := c.Find("legacy")
	if !ok {
		t.Fatalf("legacy target lost in upgrade")
	}
	if v.Token != "sekrit-token" || !v.SkipVerify {
		t.Errorf("legacy target = %+v", v)
	}
}

// manage_vault_token failures must surface (the operator opted in; failing
// silently leaves the Vault CLI authenticated as someone else), and a failure
// there must not stop the .svtoken write behind it.
func TestWriteSurfacesVaultTokenError(t *testing.T) {
	dir := setHome(t)

	// A directory where the file should be makes the atomic rename fail.
	if err := os.Mkdir(filepath.Join(dir, ".vault-token"), 0700); err != nil {
		t.Fatalf("mkdir: %s", err)
	}

	err := Update(func(c *Config) error {
		c.Options.ManageVaultToken = true
		return c.SetTarget("t", Vault{URL: "http://t", Token: "tok"})
	})
	if err == nil {
		t.Fatalf("Update succeeded with an unwritable .vault-token")
	}
	if !strings.Contains(err.Error(), ".vault-token") {
		t.Errorf("error %q does not name .vault-token", err)
	}

	// The trailing .svtoken write still happened.
	if _, statErr := os.Stat(svtoken()); statErr != nil {
		t.Errorf(".svtoken missing after .vault-token failure: %s", statErr)
	}
	// And .saferc itself was written before the failure.
	c, readErr := Read()
	if readErr != nil {
		t.Fatalf("Read: %s", readErr)
	}
	if _, ok, _ := c.Find("t"); !ok {
		t.Errorf(".saferc write did not happen")
	}
}
