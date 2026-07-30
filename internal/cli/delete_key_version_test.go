package cli

// A key named together with a version — `safe delete secret/app:password^1` —
// only means something when that version holds nothing but the key, because a
// version already written cannot be rewritten. These cover what safe does with
// the request either way.

import (
	"strings"
	"testing"
)

// versionData returns the values held by one version of a path, for tests that
// need to see that a version was left as it was.
func (f *cliFakeVault) versionData(path string, n uint) map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := f.versionLocked(path, n)
	if v == nil {
		return nil
	}
	out := map[string]string{}
	for k, val := range v.data {
		out[k] = val
	}
	return out
}

// assertVersionData fails unless version n of path holds exactly want.
func assertVersionData(t *testing.T, fv *cliFakeVault, path string, n uint, want map[string]string) {
	t.Helper()
	got := fv.versionData(path, n)
	if len(got) != len(want) {
		t.Fatalf("version %d of %s = %v, want %v", n, path, got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("version %d of %s = %v, want %v", n, path, got, want)
		}
	}
}

func TestDeletingAKeyOfAnOlderVersionThatHoldsOthersIsRefused(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one", "username": "admin"},
		map[string]string{"password": "two", "username": "admin"},
	)

	c := newTestCLI(t)
	err := c.cmdDelete("delete", "secret/app:password^1")
	if err == nil {
		t.Fatal("expected a refusal deleting one of two keys of an older version, got nil")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("error %q should name the key", err)
	}

	//Nothing may have moved: not the version that was named, and not the
	// latest, which is what safe used to rewrite instead.
	assertVersionData(t, fv, "secret/app", 1, map[string]string{"password": "one", "username": "admin"})
	assertVersionData(t, fv, "secret/app", 2, map[string]string{"password": "two", "username": "admin"})
	if states := fv.versionStates("secret/app"); len(states) != 2 {
		t.Errorf("version count = %d, want 2 (no version should have been written)", len(states))
	}
}

func TestMovingAKeyOffAnOlderVersionThatHoldsOthersIsRefused(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one", "username": "admin"},
		map[string]string{"password": "two", "username": "admin"},
	)

	c := newTestCLI(t)
	err := c.cmdMove("move", "secret/app:password^1", "secret/other:password")
	if err == nil {
		t.Fatal("expected a refusal moving one of two keys of an older version, got nil")
	}

	assertVersionData(t, fv, "secret/app", 1, map[string]string{"password": "one", "username": "admin"})
	assertVersionData(t, fv, "secret/app", 2, map[string]string{"password": "two", "username": "admin"})
	if states := fv.versionStates("secret/other"); len(states) != 0 {
		t.Errorf("the destination should not have been written, got %v", states)
	}
}

// Copying is the operation that does work here, and the refusal above points
// at it, so it has to.
func TestCopyingAKeyOffAnOlderVersionIsAllowed(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one", "username": "admin"},
		map[string]string{"password": "two", "username": "admin"},
	)

	c := newTestCLI(t)
	if err := c.cmdCopy("copy", "secret/app:password^1", "secret/other:password"); err != nil {
		t.Fatalf("cmdCopy: %v", err)
	}

	assertVersionData(t, fv, "secret/other", 1, map[string]string{"password": "one"})
	assertVersionData(t, fv, "secret/app", 1, map[string]string{"password": "one", "username": "admin"})
}

// A key that is not in the named version is a missing key, and saying so sends
// the reader somewhere different than the refusal above does.
func TestDeletingAKeyMissingFromTheNamedVersionSaysSo(t *testing.T) {
	isolateHome(t)
	newCLIFakeV2(t).setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two", "username": "admin"},
	)

	c := newTestCLI(t)
	err := c.cmdDelete("delete", "secret/app:username^1")
	if err == nil {
		t.Fatal("expected an error for a key the named version does not hold, got nil")
	}
	if !strings.Contains(err.Error(), "username") {
		t.Errorf("error %q should name the key", err)
	}
	if strings.Contains(err.Error(), "holds other keys") {
		t.Errorf("a missing key should not be reported as a crowded version: %q", err)
	}
}

// Same again where the named version does hold several keys, none of them the
// one asked for. Counting the keys before looking for the one named answers a
// question nobody asked.
func TestDeletingAKeyMissingFromACrowdedVersionSaysSo(t *testing.T) {
	isolateHome(t)
	newCLIFakeV2(t).setV2("secret/app",
		map[string]string{"password": "one", "username": "admin"},
		map[string]string{"password": "two", "username": "admin", "token": "t"},
	)

	c := newTestCLI(t)
	err := c.cmdDelete("delete", "secret/app:token^1")
	if err == nil {
		t.Fatal("expected an error for a key the named version does not hold, got nil")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error %q should name the key", err)
	}
	if strings.Contains(err.Error(), "holds other keys") {
		t.Errorf("a missing key should not be reported as a crowded version: %q", err)
	}
}
