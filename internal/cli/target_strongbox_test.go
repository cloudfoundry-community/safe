package cli

// safe target records whether a Vault has Strongbox alongside it. Strongbox
// is opt-in: a target made without -s speaks to the Vault alone, so the
// seal-state commands work against any Vault, not only a safe installation.

import (
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/rc"
)

func targetStrongbox(t *testing.T, c *CLI, alias string) bool {
	t.Helper()
	cfg, err := rc.Read()
	if err != nil {
		t.Fatalf("rc.Read: %v", err)
	}
	tgt, ok := cfg.Vaults[alias]
	if !ok {
		t.Fatalf("no %q in the config after targeting it", alias)
	}
	return tgt.Strongbox
}

func TestCmdTargetHasNoStrongboxByDefault(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	c.opt.Quiet = true

	if err := c.cmdTarget("target", "one", "https://vault.one:8200"); err != nil {
		t.Fatalf("cmdTarget: %v", err)
	}
	if targetStrongbox(t, c, "one") {
		t.Error("a target made without -s got Strongbox")
	}
}

func TestCmdTargetDashSOptsIntoStrongbox(t *testing.T) {
	isolateHome(t)
	c := newTestCLI(t)
	c.opt.Quiet = true
	c.opt.Target.Strongbox = true

	if err := c.cmdTarget("target", "one", "https://vault.one:8200"); err != nil {
		t.Fatalf("cmdTarget: %v", err)
	}
	if !targetStrongbox(t, c, "one") {
		t.Error("a target made with -s did not get Strongbox")
	}
}
