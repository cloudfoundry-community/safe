package cli

// `safe values` searches the value in use. A rotated credential is exactly the
// one an operator goes looking for after a leak, and it lives in the history
// rather than in the current version, so --all-versions searches the whole
// readable history and names the version each match came from.

import (
	"strings"
	"testing"
)

// rotated serves a v2 mount holding secret/v/db, whose password was rotated
// once, plus a second secret that never changed.
func rotated(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := newCLIFakeV2(t)
	fv.setV2("secret/v/db",
		map[string]string{"password": "old-pass", "user": "dba"},
		map[string]string{"password": "new-pass", "user": "dba"})
	fv.setV2("secret/v/api",
		map[string]string{"token": "static"})
	return fv
}

// valueLines runs cmdValues and returns the paths it printed.
func valueLines(t *testing.T, c *CLI, values ...string) []string {
	t.Helper()
	out := captureStdout(t, func() {
		if err := c.cmdValues("values", values...); err != nil {
			t.Fatalf("cmdValues(%v): %v", values, err)
		}
	})
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

func TestValuesSearchesOnlyTheCurrentVersionByDefault(t *testing.T) {
	isolateHome(t)
	rotated(t)
	c := newTestCLI(t)

	if got := valueLines(t, c, "old-pass"); got != nil {
		t.Errorf("a rotated-away value = %v, want no match without --all-versions", got)
	}
	if got, want := valueLines(t, c, "new-pass"), []string{"secret/v/db"}; !equalLines(got, want) {
		t.Errorf("current value = %v, want %v", got, want)
	}
}

func TestValuesAllVersionsFindsARotatedValue(t *testing.T) {
	isolateHome(t)
	rotated(t)
	c := newTestCLI(t)
	c.opt.Values.AllVersions = true

	got, want := valueLines(t, c, "old-pass"), []string{"secret/v/db^1"}
	if !equalLines(got, want) {
		t.Errorf("values --all-versions old-pass = %v, want %v", got, want)
	}
}

// The version belongs on the reported path in every output shape, so that
// what is printed reads back as printed.
func TestValuesAllVersionsNamesTheVersionWithKeys(t *testing.T) {
	isolateHome(t)
	rotated(t)
	c := newTestCLI(t)
	c.opt.Values.AllVersions = true
	c.opt.Values.ShowKeys = true

	got, want := valueLines(t, c, "old-pass"), []string{"secret/v/db:password^1"}
	if !equalLines(got, want) {
		t.Errorf("values --all-versions --keys = %v, want %v", got, want)
	}
}

// A value that survived the rotation appears once per version that holds it,
// oldest first.
func TestValuesAllVersionsReportsEveryVersionHolding(t *testing.T) {
	isolateHome(t)
	rotated(t)
	c := newTestCLI(t)
	c.opt.Values.AllVersions = true

	got, want := valueLines(t, c, "dba"), []string{"secret/v/db^1", "secret/v/db^2"}
	if !equalLines(got, want) {
		t.Errorf("values --all-versions dba = %v, want %v", got, want)
	}
}

// Reading a deleted version means undeleting it first, which a search must not
// do, so the history it reports stops at what it can read.
func TestValuesAllVersionsSkipsADeletedVersion(t *testing.T) {
	isolateHome(t)
	fv := rotated(t)
	fv.deleteV2("secret/v/db", 1)
	c := newTestCLI(t)
	c.opt.Values.AllVersions = true

	if got := valueLines(t, c, "old-pass"); got != nil {
		t.Errorf("deleted version = %v, want no match", got)
	}
	if got, want := valueLines(t, c, "new-pass"), []string{"secret/v/db^2"}; !equalLines(got, want) {
		t.Errorf("alive version alongside a deleted one = %v, want %v", got, want)
	}
}

func equalLines(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
