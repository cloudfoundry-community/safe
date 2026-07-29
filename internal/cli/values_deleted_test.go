package cli

// `safe values -d` searches versions that have been deleted, which it can only
// do by undeleting each one, reading it, and deleting it again -- the cycle
// `safe export -d` already uses. What the tests here pin down is that the
// search finds what is in those versions and puts every one of them back.

import "testing"

// deletedHistory serves a v2 mount holding secret/d/db with three versions:
// version 1 deleted, version 2 destroyed, version 3 alive.
func deletedHistory(t *testing.T) *cliFakeVault {
	t.Helper()
	fv := newCLIFakeV2(t)
	fv.setV2("secret/d/db",
		map[string]string{"password": "leaked"},
		map[string]string{"password": "interim"},
		map[string]string{"password": "current"})
	fv.deleteV2("secret/d/db", 1)
	fv.destroyV2("secret/d/db", 2)
	return fv
}

func TestValuesWithoutDeletedCannotSeeADeletedVersion(t *testing.T) {
	isolateHome(t)
	deletedHistory(t)
	c := newTestCLI(t)
	c.opt.Values.AllVersions = true

	if got := valueLines(t, c, "leaked"); got != nil {
		t.Errorf("a deleted version = %v, want no match without -d", got)
	}
}

func TestValuesDeletedFindsAValueInADeletedVersion(t *testing.T) {
	isolateHome(t)
	deletedHistory(t)
	c := newTestCLI(t)
	c.opt.Values.AllVersions = true
	c.opt.Values.Deleted = true

	got, want := valueLines(t, c, "leaked"), []string{"secret/d/db^1"}
	if !equalLines(got, want) {
		t.Errorf("values -a -d leaked = %v, want %v", got, want)
	}
}

// The search must leave the Vault as it found it. An undelete that is not
// followed by a delete turns a search into a restore.
func TestValuesDeletedLeavesTheVersionDeleted(t *testing.T) {
	isolateHome(t)
	fv := deletedHistory(t)
	c := newTestCLI(t)
	c.opt.Values.AllVersions = true
	c.opt.Values.Deleted = true

	before := fv.versionStates("secret/d/db")
	valueLines(t, c, "leaked")
	after := fv.versionStates("secret/d/db")

	if !equalLines(before, after) {
		t.Errorf("version states after the search = %v, want %v as before", after, before)
	}
}

// A destroyed version cannot be read back by anyone, so -d must not claim it
// searched one.
func TestValuesDeletedStillCannotSeeADestroyedVersion(t *testing.T) {
	isolateHome(t)
	deletedHistory(t)
	c := newTestCLI(t)
	c.opt.Values.AllVersions = true
	c.opt.Values.Deleted = true

	if got := valueLines(t, c, "interim"); got != nil {
		t.Errorf("a destroyed version = %v, want no match", got)
	}
}

// Without --all-versions, -d reaches the newest version even when that one is
// the deleted one, which is the state a secret is left in by `safe delete`.
func TestValuesDeletedReachesADeletedLatestVersion(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/d/gone", map[string]string{"password": "buried"})
	fv.deleteV2("secret/d/gone", 1)
	c := newTestCLI(t)
	c.opt.Values.Deleted = true

	got, want := valueLines(t, c, "buried"), []string{"secret/d/gone^1"}
	if !equalLines(got, want) {
		t.Errorf("values -d buried = %v, want %v", got, want)
	}
	if states := fv.versionStates("secret/d/gone"); !equalLines(states, []string{"deleted"}) {
		t.Errorf("version states after the search = %v, want [deleted]", states)
	}
}
