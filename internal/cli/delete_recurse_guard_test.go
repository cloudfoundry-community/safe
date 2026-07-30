package cli

// -r deletes a tree of secrets. A key or a version names something inside one
// secret, which is not a tree, so the two cannot be asked for together.

import (
	"strings"
	"testing"
)

func TestRecursiveDeleteRefusesAKeyPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app", map[string]string{"password": "one", "username": "admin"})

	c := newTestCLI(t)
	c.opt.Delete.Recurse = true
	c.opt.Delete.Force = true
	err := c.cmdDelete("delete", "secret/app:password")
	if err == nil {
		t.Fatal("expected a refusal deleting a key recursively, got nil")
	}
	if !strings.Contains(err.Error(), "password") {
		t.Errorf("error %q should name the key", err)
	}

	//Quietly deleting the one key is not what -r asked for, and the reader of
	// the exit code has no way to tell the two apart.
	assertVersionData(t, fv, "secret/app", 1, map[string]string{"password": "one", "username": "admin"})
	if states := fv.versionStates("secret/app"); len(states) != 1 {
		t.Errorf("version states = %v, want the one version untouched", states)
	}
}

func TestRecursiveDeleteRefusesAVersionPath(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)

	c := newTestCLI(t)
	c.opt.Delete.Recurse = true
	c.opt.Delete.Force = true
	err := c.cmdDelete("delete", "secret/app^1")
	if err == nil {
		t.Fatal("expected a refusal deleting a version recursively, got nil")
	}
	if !strings.Contains(err.Error(), "1") {
		t.Errorf("error %q should name the version", err)
	}

	got := fv.versionStates("secret/app")
	want := []string{"alive", "alive"}
	if !equalStrings(got, want) {
		t.Errorf("version states = %v, want %v", got, want)
	}
}

// A path that names neither still takes the whole tree.
func TestRecursiveDeleteTakesTheTree(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app/one", map[string]string{"password": "a"})
	fv.setV2("secret/app/two", map[string]string{"password": "b"})

	c := newTestCLI(t)
	c.opt.Delete.Recurse = true
	c.opt.Delete.Force = true
	if err := c.cmdDelete("delete", "secret/app"); err != nil {
		t.Fatalf("cmdDelete -r: %v", err)
	}

	for _, path := range []string{"secret/app/one", "secret/app/two"} {
		got := fv.versionStates(path)
		want := []string{"deleted"}
		if !equalStrings(got, want) {
			t.Errorf("version states of %s = %v, want %v", path, got, want)
		}
	}
}

// Without -r a key path goes on meaning the key.
func TestDeletingAKeyWithoutRecurse(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app", map[string]string{"password": "one", "username": "admin"})

	c := newTestCLI(t)
	if err := c.cmdDelete("delete", "secret/app:password"); err != nil {
		t.Fatalf("cmdDelete: %v", err)
	}
	assertVersionData(t, fv, "secret/app", 2, map[string]string{"username": "admin"})
}
