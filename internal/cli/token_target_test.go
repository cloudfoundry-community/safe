package cli

// The commands that store a token in ~/.saferc write it against the current
// target, because that is the only target Config.SetToken knows about. -T
// names a different Vault for one command, so those commands put the token on
// the wrong target — and, in the case of logout, clear a token the user did
// not ask them to clear.

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
	"github.com/cloudfoundry-community/safe/pkg/rc"
)

// readConfig parses ~/.saferc under the isolated home.
func readConfig(t *testing.T) rc.Config {
	t.Helper()
	cfg, err := rc.Read()
	if err != nil {
		t.Fatalf("rc.Read: %v", err)
	}
	return cfg
}

func TestCmdLogoutClearsTheTokenOfTheTargetNamedByDashT(t *testing.T) {
	isolateHome(t)
	alpha := newSealFake(t, false)
	beta := newSealFake(t, false)
	writeSaferc(t, twoTargets(alpha, beta))

	c := newTestCLI(t)
	c.opt.UseTarget = "beta"

	if err := c.cmdLogout("logout"); err != nil {
		t.Fatalf("cmdLogout: %v", err)
	}

	cfg := readConfig(t)
	if cfg.Vaults["beta"].Token != "" {
		t.Errorf("beta kept its token %q after being logged out of", cfg.Vaults["beta"].Token)
	}
	if cfg.Vaults["alpha"].Token != "token-alpha" {
		t.Errorf("alpha lost its token: %q", cfg.Vaults["alpha"].Token)
	}
	if cfg.Current != "alpha" {
		t.Errorf("current target: got %q, want alpha", cfg.Current)
	}
}

func TestCmdLogoutWithNothingTargetedReportsAnError(t *testing.T) {
	isolateHome(t)
	f := newSealFake(t, false)
	t.Setenv("VAULT_ADDR", f.url)
	t.Setenv("VAULT_TOKEN", "test-token")

	c := newTestCLI(t)

	if err := c.cmdLogout("logout"); err == nil {
		t.Error("logging out with no target selected reported success")
	}
}

func TestCmdAuthStoresTheTokenOnTheTargetNamedByDashT(t *testing.T) {
	isolateHome(t)
	alpha := newSealFake(t, false)
	beta := newSealFake(t, false)
	writeSaferc(t, twoTargets(alpha, beta))

	prompt.SetReader(strings.NewReader("beta-token\n"))
	t.Cleanup(func() { prompt.SetReader(nil) })

	c := newTestCLI(t)
	c.opt.UseTarget = "beta"

	if err := c.cmdAuth("auth", "token"); err != nil {
		t.Fatalf("cmdAuth: %v", err)
	}

	cfg := readConfig(t)
	if cfg.Vaults["beta"].Token != "beta-token" {
		t.Errorf("beta token: got %q, want beta-token", cfg.Vaults["beta"].Token)
	}
	if cfg.Vaults["alpha"].Token != "token-alpha" {
		t.Errorf("alpha token: got %q, want it untouched", cfg.Vaults["alpha"].Token)
	}
	if cfg.Current != "alpha" {
		t.Errorf("current target: got %q, want alpha", cfg.Current)
	}
}
