package cli

// The commands that store a token in ~/.saferc write it against the current
// target, because that is the only target Config.SetToken knows about. -T
// names a different Vault for one command, so those commands put the token on
// the wrong target — and, in the case of logout, clear a token the user did
// not ask them to clear.

import (
	"encoding/json"
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

// safe init with only VAULT_ADDR set -- no ~/.saferc target at all, the
// documented environment-variable workflow -- must still print the unseal
// keys and root token. Vault hands them out exactly once; a config-store
// failure after Init must never be what decides whether the operator sees
// them, or the vault it just initialized is unrecoverable.
func TestCmdInitPrintsKeysWhenNoTargetIsSelected(t *testing.T) {
	isolateHome(t)
	f := newSealFake(t, true)
	t.Setenv("VAULT_ADDR", f.url)
	c := newTestCLI(t)
	c.opt.Init.Sealed = true

	var err error
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			err = c.cmdInit("init")
		})
	})
	if err != nil {
		t.Fatalf("cmdInit returned an error with no target selected: %v\nstderr:\n%s", err, stderr)
	}
	if !strings.Contains(stdout, "Initial Root Token") || !strings.Contains(stdout, f.rootToken) {
		t.Errorf("expected the root token printed even with no target selected, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Unseal Key") {
		t.Errorf("expected the unseal key printed even with no target selected, got:\n%s", stdout)
	}
	if !strings.Contains(stderr, "Unable to save the root token") {
		t.Errorf("expected a warning that the token could not be stored, got:\n%s", stderr)
	}
}

// The --json form of the same scenario: no target selected, so there is
// nowhere in ~/.saferc to store the token, but the machine-readable output
// must still carry it.
func TestCmdInitPrintsJSONWhenNoTargetIsSelected(t *testing.T) {
	isolateHome(t)
	f := newSealFake(t, true)
	t.Setenv("VAULT_ADDR", f.url)
	c := newTestCLI(t)
	c.opt.Init.Sealed = true
	c.opt.Init.JSON = true

	var err error
	stdout := captureStdout(t, func() {
		captureStderr(t, func() {
			err = c.cmdInit("init")
		})
	})
	if err != nil {
		t.Fatalf("cmdInit returned an error with no target selected: %v", err)
	}
	var out struct {
		Keys  []string `json:"seal_keys"`
		Token string   `json:"root_token"`
	}
	if jsonErr := json.Unmarshal([]byte(stdout), &out); jsonErr != nil {
		t.Fatalf("stdout did not parse as JSON: %v\nstdout:\n%s", jsonErr, stdout)
	}
	if out.Token != f.rootToken {
		t.Errorf("root_token: got %q, want %q", out.Token, f.rootToken)
	}
	if len(out.Keys) == 0 {
		t.Errorf("expected seal_keys to be populated, got none")
	}
}

func TestCmdInitStoresTheRootTokenOnTheTargetNamedByDashT(t *testing.T) {
	isolateHome(t)
	alpha := newSealFake(t, false)
	beta := newSealFake(t, true)
	beta.rootToken = "beta-root"
	writeSaferc(t, twoTargets(alpha, beta))

	c := newTestCLI(t)
	c.opt.UseTarget = "beta"
	//Leaving the Vault sealed keeps the test to the one thing it is about:
	// where the root token that initializing produced ends up.
	c.opt.Init.Sealed = true

	_ = captureStdout(t, func() {
		if err := c.cmdInit("init"); err != nil {
			t.Fatalf("cmdInit: %v", err)
		}
	})

	cfg := readConfig(t)
	if cfg.Vaults["beta"].Token != "beta-root" {
		t.Errorf("beta token: got %q, want beta-root", cfg.Vaults["beta"].Token)
	}
	if cfg.Vaults["alpha"].Token != "token-alpha" {
		t.Errorf("alpha token: got %q, want it untouched", cfg.Vaults["alpha"].Token)
	}
}
