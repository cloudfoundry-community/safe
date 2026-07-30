package cli

// `safe target' names a Vault by its alias or by its URL, and both used to be
// written back into ~/.saferc as the current target. A URL there is a name for
// a target only for as long as one target carries it, so the listing lost the
// (*) marker and a later `safe target delete' left the selection pointing at
// something that no longer existed.

import (
	"strings"
	"testing"
)

// twoAliasedTargets writes a config holding alpha and beta with none current.
func twoAliasedTargets(t *testing.T) {
	t.Helper()
	writeSaferc(t, `version: 1
current: ""
vaults:
  alpha:
    url: https://alpha.example.com
    token: token-alpha
  beta:
    url: https://beta.example.com
    token: token-beta
`)
}

func TestTargetingByURLRecordsTheAlias(t *testing.T) {
	for _, name := range []string{"alpha", "https://alpha.example.com", "https://alpha.example.com/"} {
		t.Run(name, func(t *testing.T) {
			isolateHome(t)
			twoAliasedTargets(t)
			c := newTestCLI(t)
			c.opt.Quiet = true

			if err := c.cmdTarget("target", name); err != nil {
				t.Fatalf("cmdTarget(%q): %v", name, err)
			}

			cfg := readConfig(t)
			if cfg.Current != "alpha" {
				t.Errorf("current = %q, want alpha", cfg.Current)
			}
		})
	}
}

// The listing marks the current target with a (*), which it does by comparing
// the name it was given against the aliases it prints.
func TestTargetingByURLIsMarkedInTheListing(t *testing.T) {
	isolateHome(t)
	twoAliasedTargets(t)
	c := newTestCLI(t)
	c.opt.Quiet = true

	if err := c.cmdTarget("target", "https://alpha.example.com"); err != nil {
		t.Fatalf("cmdTarget: %v", err)
	}

	out := captureStderr(t, func() {
		if err := c.cmdTargets("targets"); err != nil {
			t.Fatalf("cmdTargets: %v", err)
		}
	})

	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "alpha") {
			continue
		}
		if !strings.HasPrefix(line, "(*)") {
			t.Errorf("alpha is current but its line reads %q", line)
		}
	}
	if !strings.Contains(out, "current target indicated") {
		t.Error("the listing should say a target is current")
	}
}

// Targeting by URL and then deleting by alias is the pair that used to leave
// ~/.saferc naming a target that is not there, which every later command
// reported as a missing current target.
func TestDeletingTheTargetSelectedByURLClearsTheSelection(t *testing.T) {
	isolateHome(t)
	twoAliasedTargets(t)
	c := newTestCLI(t)
	c.opt.Quiet = true

	if err := c.cmdTarget("target", "https://alpha.example.com"); err != nil {
		t.Fatalf("cmdTarget: %v", err)
	}
	if err := c.cmdTargetDelete("target delete", "alpha"); err != nil {
		t.Fatalf("cmdTargetDelete: %v", err)
	}

	cfg := readConfig(t)
	if cfg.Current != "" {
		t.Errorf("current = %q, want it cleared with the target it named", cfg.Current)
	}
	//A selection that names nothing is what every other command trips over,
	// so check the way they reach it rather than only the stored string.
	if _, err := cfg.Vault(""); err != nil {
		t.Errorf("reading the current target: %v", err)
	}
}
