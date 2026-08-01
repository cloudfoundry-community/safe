package cli

// cmdOption must not announce "updated <opt>" until the change has actually
// been persisted through rc.Update. Printing during argument parsing tells the
// operator the option changed even when the write later fails, leaving safe's
// reported state and the on-disk config disagreeing.

import (
	"os"
	"strings"
	"testing"
)

// TestCmdOptionDoesNotClaimSuccessWhenPersistFails makes HOME unwritable so the
// atomic config write fails at persist time (rc.Apply still reads the absent
// ~/.saferc as an empty config). The command must report the error and must
// not have printed "updated".
func TestCmdOptionDoesNotClaimSuccessWhenPersistFails(t *testing.T) {
	isolateHome(t)
	home := os.Getenv("HOME")
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatalf("chmod home: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })

	c := newTestCLI(t)
	var err error
	out := captureStdout(t, func() {
		err = c.cmdOption("option", "manage-vault-token=on")
	})

	if err == nil {
		t.Fatal("expected a persist error, got nil")
	}
	if strings.Contains(out, "updated") {
		t.Errorf("must not claim 'updated' when the write failed; stdout was %q", out)
	}
}
