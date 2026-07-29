package cli

// -T names the Vault a single command should act on. rc.Apply points the
// environment at that Vault but leaves the current target alone, so a command
// that asks the config for an address or a Strongbox flag gets the answer for
// whichever Vault happens to be current. For the seal-state commands that
// means reporting on, unsealing, or sealing the wrong Vault.

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

func TestCmdStatusReportsTheTargetNamedByDashT(t *testing.T) {
	isolateHome(t)
	alpha := newSealFake(t, false)
	beta := newSealFake(t, true)
	writeSaferc(t, twoTargets(alpha, beta))

	c := newTestCLI(t)
	c.opt.UseTarget = "beta"

	out := captureStdout(t, func() {
		if err := c.cmdStatus("status"); err != nil {
			t.Fatalf("cmdStatus: %v", err)
		}
	})

	if !strings.Contains(out, beta.url+" is sealed") {
		t.Errorf("status did not report the sealed target named by -T:\n%s", out)
	}
	if strings.Contains(out, alpha.url) {
		t.Errorf("status reported the current target instead of the one named by -T:\n%s", out)
	}
}

func TestCmdStatusReadsTheStrongboxFlagOfTheDashTTarget(t *testing.T) {
	isolateHome(t)
	alpha := newSealFake(t, false)
	beta := newSealFake(t, true)
	//alpha uses Strongbox, beta does not. Asking alpha's flag sends the
	// command down the Strongbox branch, which beta cannot answer.
	writeSaferc(t, `version: 1
current: alpha
vaults:
  alpha:
    url: `+alpha.url+`
    token: token-alpha
  beta:
    url: `+beta.url+`
    token: token-beta
    no_strongbox: true
`)

	c := newTestCLI(t)
	c.opt.UseTarget = "beta"

	out := captureStdout(t, func() {
		if err := c.cmdStatus("status"); err != nil {
			t.Fatalf("cmdStatus: %v", err)
		}
	})

	if !strings.Contains(out, beta.url+" is sealed") {
		t.Errorf("status did not report the target named by -T:\n%s", out)
	}
}

func TestCmdStatusUsesTheEnvironmentAddressWithNoTarget(t *testing.T) {
	isolateHome(t)
	//No ~/.saferc at all: the address and token come from the environment,
	// which is how safe is driven in a pipeline.
	f := newSealFake(t, false)
	t.Setenv("VAULT_ADDR", f.url)
	t.Setenv("VAULT_TOKEN", "test-token")

	c := newTestCLI(t)

	out := captureStdout(t, func() {
		if err := c.cmdStatus("status"); err != nil {
			t.Fatalf("cmdStatus: %v", err)
		}
	})

	if !strings.Contains(out, f.url+" is unsealed") {
		t.Errorf("status did not report the Vault named by VAULT_ADDR:\n%s", out)
	}
}

func TestCmdSealSealsTheTargetNamedByDashT(t *testing.T) {
	isolateHome(t)
	alpha := newSealFake(t, false)
	beta := newSealFake(t, false)
	writeSaferc(t, twoTargets(alpha, beta))

	c := newTestCLI(t)
	c.opt.UseTarget = "beta"

	_ = captureStdout(t, func() {
		if err := c.cmdSeal("seal"); err != nil {
			t.Fatalf("cmdSeal: %v", err)
		}
	})

	if !beta.isSealed() {
		t.Error("seal left the target named by -T unsealed")
	}
	if alpha.isSealed() {
		t.Error("seal sealed the current target instead of the one named by -T")
	}
}

func TestCmdUnsealUnsealsTheTargetNamedByDashT(t *testing.T) {
	isolateHome(t)
	//The current target is already unsealed, so a command that looks at it
	// concludes there is nothing to do.
	alpha := newSealFake(t, false)
	beta := newSealFake(t, true)
	writeSaferc(t, twoTargets(alpha, beta))

	prompt.SetReader(strings.NewReader("unseal-key\n"))
	t.Cleanup(func() { prompt.SetReader(nil) })

	c := newTestCLI(t)
	c.opt.UseTarget = "beta"

	_ = captureStdout(t, func() {
		if err := c.cmdUnseal("unseal"); err != nil {
			t.Fatalf("cmdUnseal: %v", err)
		}
	})

	if beta.isSealed() {
		t.Error("unseal left the target named by -T sealed")
	}
}
