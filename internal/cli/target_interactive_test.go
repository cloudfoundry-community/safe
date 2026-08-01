package cli

// `safe target -i' walks the list of known Vaults and asks which one to
// point at. With nothing on the list there is nothing to choose from, so it
// explains how to target a Vault manually and leaves with status 1 -- an
// exit, so that branch is pinned from outside the process. With Vaults on
// the list it keeps asking until it is given a name it knows.
//
// prompt.SetReader and captureStderr both mutate process-global state -- do
// NOT add t.Parallel to any test in this file.

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

// With no Vaults targeted yet there is no menu to offer: interactive
// targeting turns into instructions and a failure, not a prompt that could
// only be answered wrongly.
func TestInteractiveTargetWithNoVaultsExplainsAndFails(t *testing.T) {
	stdout, stderr, status := run(t, "target", "-i")
	if status != 1 {
		t.Errorf("safe target -i with no Vaults exited %d, want 1", status)
	}
	if !strings.Contains(stderr, "No Vaults have been targeted yet.") {
		t.Errorf("stderr does not say there is nothing to choose from:\n%s", stderr)
	}
	if !strings.Contains(stderr, "safe target ops https://address.of.your.vault") {
		t.Errorf("stderr does not show how to target a Vault manually:\n%s", stderr)
	}
	if strings.Contains(stdout+stderr, "Which Vault") {
		t.Errorf("safe asked which Vault to target with none to offer:\n%s", stdout+stderr)
	}
}

func TestInteractiveTargetSelectsAndPersistsTheAnswer(t *testing.T) {
	isolateHome(t)
	twoAliasedTargets(t)
	c := newTestCLI(t)
	c.opt.Target.Interactive = true

	prompt.SetReader(strings.NewReader("alpha\n"))
	t.Cleanup(func() { prompt.SetReader(nil) })

	var err error
	out := captureStderr(t, func() {
		err = c.cmdTarget("target")
	})
	if err != nil {
		t.Fatalf("cmdTarget: %v", err)
	}
	if !strings.Contains(out, "Which Vault") {
		t.Errorf("the prompt never asked which Vault to target:\n%s", out)
	}
	if !strings.Contains(out, "Now targeting") {
		t.Errorf("the answer was never confirmed:\n%s", out)
	}

	if cfg := readConfig(t); cfg.Current != "alpha" {
		t.Errorf("current = %q, want alpha written to ~/.saferc", cfg.Current)
	}
}

// A name safe does not know is not the end of the conversation: the mistake
// is reported and the question asked again.
func TestInteractiveTargetAsksAgainAfterAnUnknownName(t *testing.T) {
	isolateHome(t)
	twoAliasedTargets(t)
	c := newTestCLI(t)
	c.opt.Target.Interactive = true

	prompt.SetReader(strings.NewReader("gamma\nbeta\n"))
	t.Cleanup(func() { prompt.SetReader(nil) })

	var err error
	out := captureStderr(t, func() {
		err = c.cmdTarget("target")
	})
	if err != nil {
		t.Fatalf("cmdTarget: %v", err)
	}
	if !strings.Contains(out, "Unknown target 'gamma'") {
		t.Errorf("the unknown name was not reported:\n%s", out)
	}

	if cfg := readConfig(t); cfg.Current != "beta" {
		t.Errorf("current = %q, want beta -- the answer given after the mistake", cfg.Current)
	}
}
