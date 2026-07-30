package cli

// --destroy and --all both work on whole versions. What that means for a path
// that names one key depends on whether the key is the whole secret.

import (
	"strings"
	"testing"
)

func TestDestroyingTheOnlyKeyDestroysTheSecret(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app", map[string]string{"password": "one"})

	c := newTestCLI(t)
	c.opt.Delete.Destroy = true
	if err := c.cmdDelete("delete", "secret/app:password"); err != nil {
		t.Fatalf("cmdDelete --destroy: %v", err)
	}

	//A destroy that leaves the version merely deleted is one an undelete
	// brings straight back, which is the opposite of what was asked.
	if states := fv.versionStates("secret/app"); len(states) != 0 {
		t.Errorf("version states = %v, want the secret gone", states)
	}
}

func TestDestroyingTheOnlyKeyOfSeveralVersions(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)

	c := newTestCLI(t)
	c.opt.Delete.Destroy = true
	if err := c.cmdDelete("delete", "secret/app:password"); err != nil {
		t.Fatalf("cmdDelete --destroy: %v", err)
	}

	got := fv.versionStates("secret/app")
	want := []string{"alive", "destroyed"}
	if !equalStrings(got, want) {
		t.Errorf("version states = %v, want %v", got, want)
	}
}

func TestDeletingEveryVersionOfTheOnlyKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)

	c := newTestCLI(t)
	c.opt.Delete.All = true
	if err := c.cmdDelete("delete", "secret/app:password"); err != nil {
		t.Fatalf("cmdDelete --all: %v", err)
	}

	got := fv.versionStates("secret/app")
	want := []string{"deleted", "deleted"}
	if !equalStrings(got, want) {
		t.Errorf("version states = %v, want %v", got, want)
	}
}

func TestDestroyingOneKeyOfSeveralIsRefused(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app", map[string]string{"password": "one", "username": "admin"})

	c := newTestCLI(t)
	c.opt.Delete.Destroy = true
	err := c.cmdDelete("delete", "secret/app:password")
	if err == nil {
		t.Fatal("expected a refusal destroying one key of a secret that holds others, got nil")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("error %q should name the key", err)
	}

	//The value has to still be there. Reporting a destroy and leaving the key
	//	readable in the version it was already written to is the failure.
	if states := fv.versionStates("secret/app"); len(states) != 1 {
		t.Errorf("version states = %v, want the one version untouched", states)
	}
	assertVersionData(t, fv, "secret/app", 1, map[string]string{"password": "one", "username": "admin"})
}

func TestDeletingEveryVersionOfOneKeyOfSeveralIsRefused(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app", map[string]string{"password": "one", "username": "admin"})

	c := newTestCLI(t)
	c.opt.Delete.All = true
	err := c.cmdDelete("delete", "secret/app:password")
	if err == nil {
		t.Fatal("expected a refusal deleting every version of one key, got nil")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("error %q should name the key", err)
	}
	if states := fv.versionStates("secret/app"); len(states) != 1 {
		t.Errorf("version states = %v, want the one version untouched", states)
	}
}

// Without either flag the key still goes, and the rest of the secret carries
// on into a new version.
func TestDeletingOneKeyOfSeveralStillWorks(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app", map[string]string{"password": "one", "username": "admin"})

	c := newTestCLI(t)
	if err := c.cmdDelete("delete", "secret/app:password"); err != nil {
		t.Fatalf("cmdDelete: %v", err)
	}
	assertVersionData(t, fv, "secret/app", 2, map[string]string{"username": "admin"})
}
