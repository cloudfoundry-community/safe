package cli

// `safe target <name> <url> --keep-current` registers a target without
// selecting it, so a caller that only wants an entry in ~/.saferc can add one
// without moving the operator's current target.

import (
	"strings"
	"testing"
)

func TestTargetKeepCurrentLeavesExistingCurrentUnchanged(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, `version: 1
current: alpha
vaults:
  alpha:
    url: https://alpha.example.com
    token: token-alpha
`)
	c := newTestCLI(t)
	c.opt.Quiet = true
	c.opt.Target.KeepCurrent = true

	if err := c.cmdTarget("target", "beta", "https://beta.example.com"); err != nil {
		t.Fatalf("cmdTarget: %v", err)
	}

	cfg := readConfig(t)
	if cfg.Current != "alpha" {
		t.Errorf("current = %q, want alpha", cfg.Current)
	}
	if v := cfg.Vaults["beta"]; v == nil || v.URL != "https://beta.example.com" {
		t.Errorf("beta was not registered: %+v", v)
	}
}

func TestTargetKeepCurrentLeavesEmptyCurrentEmpty(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, "version: 1\ncurrent: \"\"\nvaults: {}\n")
	c := newTestCLI(t)
	c.opt.Quiet = true
	c.opt.Target.KeepCurrent = true

	if err := c.cmdTarget("target", "beta", "https://beta.example.com"); err != nil {
		t.Fatalf("cmdTarget: %v", err)
	}

	cfg := readConfig(t)
	if cfg.Current != "" {
		t.Errorf("current = %q, want empty", cfg.Current)
	}
	if cfg.Vaults["beta"] == nil {
		t.Error("beta was not registered")
	}
}

func TestTargetKeepCurrentKeepsTokenWhenURLMatches(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, `version: 1
current: alpha
vaults:
  alpha:
    url: https://alpha.example.com
    token: token-alpha
  beta:
    url: https://beta.example.com
    token: token-beta
`)
	c := newTestCLI(t)
	c.opt.Quiet = true
	c.opt.Target.KeepCurrent = true

	if err := c.cmdTarget("target", "beta", "https://beta.example.com"); err != nil {
		t.Fatalf("cmdTarget: %v", err)
	}
	cfg := readConfig(t)
	if got := cfg.Vaults["beta"].Token; got != "token-beta" {
		t.Errorf("token = %q, want token-beta", got)
	}
	if cfg.Current != "alpha" {
		t.Errorf("current = %q, want alpha", cfg.Current)
	}

	if err := c.cmdTarget("target", "beta", "https://moved.example.com"); err != nil {
		t.Fatalf("cmdTarget: %v", err)
	}
	cfg = readConfig(t)
	if got := cfg.Vaults["beta"].Token; got != "" {
		t.Errorf("token = %q, want it dropped when the URL changes", got)
	}
}

func TestTargetKeepCurrentReportsTheAddition(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, "version: 1\ncurrent: \"\"\nvaults: {}\n")
	c := newTestCLI(t)
	c.opt.Target.KeepCurrent = true

	var err error
	out := captureStderr(t, func() {
		err = c.cmdTarget("target", "beta", "https://beta.example.com")
	})
	if err != nil {
		t.Fatalf("cmdTarget: %v", err)
	}
	if !strings.Contains(out, "Added target") || !strings.Contains(out, "beta") || !strings.Contains(out, "https://beta.example.com") {
		t.Errorf("missing the added-target confirmation:\n%s", out)
	}
	if strings.Contains(out, "Currently targeting") {
		t.Errorf("claimed a current target:\n%s", out)
	}
}

func TestTargetKeepCurrentOnlyAppliesToTheTwoArgumentForm(t *testing.T) {
	cases := []struct {
		name        string
		interactive bool
		args        []string
	}{
		{"one argument", false, []string{"alpha"}},
		{"no arguments", false, nil},
		{"interactive", true, nil},
		{"interactive with arguments", true, []string{"beta", "https://beta.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			twoAliasedTargets(t)
			c := newTestCLI(t)
			c.opt.Quiet = true
			c.opt.Target.KeepCurrent = true
			c.opt.Target.Interactive = tc.interactive

			err := c.cmdTarget("target", tc.args...)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), "only applies to `safe target <name> <url>'") {
				t.Errorf("unexpected error: %v", err)
			}
			if cfg := readConfig(t); cfg.Current != "" {
				t.Errorf("current changed to %q", cfg.Current)
			}
		})
	}
}
