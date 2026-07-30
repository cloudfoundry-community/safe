package cli

// `safe target' printed the target it had just selected and saved it
// afterwards, so a configuration that could not be written -- a read-only home
// directory, a full disk -- was reported as a target that had been changed.
// The next command still used the old one.

import (
	"os"
	"strings"
	"testing"
)

// sealHome makes the isolated home directory unwritable for the rest of the
// test, so writing ~/.saferc fails while reading it still works. Root ignores
// the mode, so there is nothing to test there.
func sealHome(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: the directory mode would not stop a write")
	}
	home := os.Getenv("HOME")
	if err := os.Chmod(home, 0o500); err != nil {
		t.Fatalf("chmod %s: %v", home, err)
	}
	//Put the mode back before the temp directory is removed, or the cleanup
	// that removes it fails and the failure is reported against this test.
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
}

func TestTargetDoesNotReportASelectionItCouldNotSave(t *testing.T) {
	isolateHome(t)
	twoAliasedTargets(t)
	sealHome(t)
	c := newTestCLI(t)

	var err error
	out := captureStderr(t, func() {
		err = c.cmdTarget("target", "alpha")
	})

	if err == nil {
		t.Fatal("cmdTarget returned nil with an unwritable config, want the write error")
	}
	if strings.Contains(out, "Currently targeting") {
		t.Errorf("stderr reported the new target although it was not saved: %q", out)
	}
}

func TestTargetDoesNotReportAVaultItCouldNotSave(t *testing.T) {
	isolateHome(t)
	twoAliasedTargets(t)
	sealHome(t)
	c := newTestCLI(t)

	var err error
	out := captureStderr(t, func() {
		err = c.cmdTarget("target", "https://gamma.example.com", "gamma")
	})

	if err == nil {
		t.Fatal("cmdTarget returned nil with an unwritable config, want the write error")
	}
	if strings.Contains(out, "Currently targeting") {
		t.Errorf("stderr reported the new target although it was not saved: %q", out)
	}
}

// The report is still made when the target is saved, in both forms.
func TestTargetReportsASelectionItSaved(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		args       []string
	}{
		{name: "an existing target", want: "alpha", args: []string{"alpha"}},
		{name: "a new one", want: "gamma", args: []string{"https://gamma.example.com", "gamma"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			twoAliasedTargets(t)
			c := newTestCLI(t)

			var err error
			out := captureStderr(t, func() {
				err = c.cmdTarget("target", tc.args...)
			})
			if err != nil {
				t.Fatalf("cmdTarget %v: %v", tc.args, err)
			}
			if !strings.Contains(out, "Currently targeting") || !strings.Contains(out, tc.want) {
				t.Errorf("stderr = %q, want it to report targeting %s", out, tc.want)
			}
			if cfg := readConfig(t); cfg.Current != tc.want {
				t.Errorf("current = %q, want %s", cfg.Current, tc.want)
			}
		})
	}
}
