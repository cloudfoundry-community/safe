package cli

// Concurrent `safe target` invocations used to lose each other's entries:
// each read ~/.saferc at startup, applied its own change to that snapshot,
// and rewrote the whole file. Whoever wrote last won; everyone else's target
// vanished. These run the real command handlers concurrently and require
// every writer's entry to survive.

import (
	"fmt"
	"sync"
	"testing"
)

func TestConcurrentTargetAddsAllSurvive(t *testing.T) {
	isolateHome(t)

	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := newTestCLI(t)
			alias := fmt.Sprintf("target-%02d", i)
			errs[i] = c.cmdTarget("target", fmt.Sprintf("https://%s.example.com", alias), alias)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("cmdTarget %d: %v", i, err)
		}
	}

	cfg := readConfig(t)
	for i := range n {
		alias := fmt.Sprintf("target-%02d", i)
		if _, ok := cfg.Vaults[alias]; !ok {
			t.Errorf("target %q lost to a concurrent writer", alias)
		}
	}
	if len(cfg.Vaults) != n {
		t.Errorf("%d targets in config, want %d", len(cfg.Vaults), n)
	}
}

// Deleting one target while another is being added must end with the added
// target present and the deleted one gone -- not with either operation's
// whole-file view of the world.
func TestConcurrentTargetAddAndDelete(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, `version: 1
current: keep
vaults:
  keep:
    url: https://keep.example.com
  doomed:
    url: https://doomed.example.com
`)

	var wg sync.WaitGroup
	var addErr, delErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		addErr = newTestCLI(t).cmdTarget("target", "https://fresh.example.com", "fresh")
	}()
	go func() {
		defer wg.Done()
		delErr = newTestCLI(t).cmdTargetDelete("target delete", "doomed")
	}()
	wg.Wait()

	if addErr != nil {
		t.Fatalf("cmdTarget: %v", addErr)
	}
	if delErr != nil {
		t.Fatalf("cmdTargetDelete: %v", delErr)
	}

	cfg := readConfig(t)
	if _, ok := cfg.Vaults["fresh"]; !ok {
		t.Error("added target lost to the concurrent delete")
	}
	if _, ok := cfg.Vaults["doomed"]; ok {
		t.Error("deleted target still present")
	}
	if _, ok := cfg.Vaults["keep"]; !ok {
		t.Error("bystander target lost")
	}
}

// `safe option` writes the whole config too; setting an option while a target
// is being added must keep both changes.
func TestConcurrentOptionSetAndTargetAdd(t *testing.T) {
	isolateHome(t)

	var wg sync.WaitGroup
	var optErr, addErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		optErr = newTestCLI(t).cmdOption("option", "manage-vault-token=true")
	}()
	go func() {
		defer wg.Done()
		addErr = newTestCLI(t).cmdTarget("target", "https://fresh.example.com", "fresh")
	}()
	wg.Wait()

	if optErr != nil {
		t.Fatalf("cmdOption: %v", optErr)
	}
	if addErr != nil {
		t.Fatalf("cmdTarget: %v", addErr)
	}

	cfg := readConfig(t)
	if !cfg.Options.ManageVaultToken {
		t.Error("option lost to the concurrent target add")
	}
	if _, ok := cfg.Vaults["fresh"]; !ok {
		t.Error("target lost to the concurrent option set")
	}
}
