package cli

// safe seal, safe unseal, and safe status only ever probe the one address
// they are pointed at unless the target carries strongbox: true, in which
// case they fan out across the whole cluster via the Strongbox seal-state
// service. A target without Strongbox gets a one-line stderr hint that only
// the targeted node was checked, and how to turn cluster-wide checking on --
// so an operator reading "unsealed" does not read it as "the cluster is
// unsealed" when only one node was ever asked.

import (
	"strings"
	"testing"
)

// singleTarget writes a ~/.saferc naming one target at f's URL, opting into
// Strongbox when asked.
func singleTarget(t *testing.T, f *fakeSealVault, strongbox bool) {
	t.Helper()
	body := "version: 1\ncurrent: solo\nvaults:\n  solo:\n    url: " + f.url + "\n    token: solo-token\n"
	if strongbox {
		body += "    strongbox: true\n"
	}
	writeSaferc(t, body)
}

func TestCmdStatusHintsStrongboxOffWhenNotEnabled(t *testing.T) {
	isolateHome(t)
	f := newSealFake(t, false)
	singleTarget(t, f, false)
	c := newTestCLI(t)

	stderr := captureStderr(t, func() {
		_ = captureStdout(t, func() {
			if err := c.cmdStatus("status"); err != nil {
				t.Fatalf("cmdStatus: %v", err)
			}
		})
	})
	if !strings.Contains(stderr, "Strongbox") {
		t.Errorf("expected a Strongbox visibility hint on stderr, got:\n%s", stderr)
	}
}

func TestCmdStatusNoHintWhenStrongboxEnabled(t *testing.T) {
	isolateHome(t)
	f := newSealFake(t, false)
	singleTarget(t, f, true)
	c := newTestCLI(t)

	stderr := captureStderr(t, func() {
		_ = captureStdout(t, func() {
			// fakeSealVault does not implement /v1/sys/strongbox, so this
			// errors -- the point here is only that the no-Strongbox hint,
			// which belongs to the other branch, never fires.
			_ = c.cmdStatus("status")
		})
	})
	if strings.Contains(stderr, "Strongbox is off") {
		t.Errorf("did not expect the no-Strongbox hint for a Strongbox-enabled target, got:\n%s", stderr)
	}
}

func TestCmdUnsealHintsStrongboxOffWhenNotEnabled(t *testing.T) {
	isolateHome(t)
	// Already unsealed: cmdUnseal takes its early return before it would
	// ever prompt for a key.
	f := newSealFake(t, false)
	singleTarget(t, f, false)
	c := newTestCLI(t)

	stdout := captureStdout(t, func() {
		stderr := captureStderr(t, func() {
			if err := c.cmdUnseal("unseal"); err != nil {
				t.Fatalf("cmdUnseal: %v", err)
			}
		})
		if !strings.Contains(stderr, "Strongbox") {
			t.Errorf("expected a Strongbox visibility hint on stderr, got:\n%s", stderr)
		}
	})
	if !strings.Contains(stdout, "already unsealed") {
		t.Errorf("expected the already-unsealed message, got:\n%s", stdout)
	}
}

func TestCmdSealHintsStrongboxOffWhenNotEnabled(t *testing.T) {
	isolateHome(t)
	// Already sealed: cmdSeal's retry loop never runs, so this returns
	// without needing an unseal/reseal round trip.
	f := newSealFake(t, true)
	singleTarget(t, f, false)
	c := newTestCLI(t)

	stdout := captureStdout(t, func() {
		stderr := captureStderr(t, func() {
			if err := c.cmdSeal("seal"); err != nil {
				t.Fatalf("cmdSeal: %v", err)
			}
		})
		if !strings.Contains(stderr, "Strongbox") {
			t.Errorf("expected a Strongbox visibility hint on stderr, got:\n%s", stderr)
		}
	})
	if !strings.Contains(stdout, "already sealed") {
		t.Errorf("expected the already-sealed message, got:\n%s", stdout)
	}
}
