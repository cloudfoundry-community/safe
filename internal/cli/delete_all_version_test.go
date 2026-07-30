package cli

// --all works on every version of a secret, so a path that also names one
// version asks for two different things at once. What safe did with that pair
// was take the --all and drop the version.

import (
	"strings"
	"testing"
)

func TestDeletingEveryVersionRefusesANamedVersion(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
		map[string]string{"password": "three"},
	)

	c := newTestCLI(t)
	c.opt.Delete.All = true
	err := c.cmdDelete("delete", "secret/app^2")
	if err == nil {
		t.Fatal("expected a refusal deleting every version of a path that names version 2, got nil")
	}
	if !strings.Contains(err.Error(), "2") {
		t.Errorf("error %q should name the version", err)
	}

	got := fv.versionStates("secret/app")
	want := []string{"alive", "alive", "alive"}
	if !equalStrings(got, want) {
		t.Errorf("version states = %v, want %v", got, want)
	}
}

func TestDestroyingEveryVersionRefusesANamedVersion(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
		map[string]string{"password": "three"},
	)

	c := newTestCLI(t)
	c.opt.Delete.Destroy = true
	c.opt.Delete.All = true
	err := c.cmdDelete("delete", "secret/app^2")
	if err == nil {
		t.Fatal("expected a refusal destroying every version of a path that names version 2, got nil")
	}

	//A destroy cannot be taken back, so this one has to be refused before it
	// reaches Vault rather than reported afterwards.
	got := fv.versionStates("secret/app")
	want := []string{"alive", "alive", "alive"}
	if !equalStrings(got, want) {
		t.Errorf("version states = %v, want %v", got, want)
	}
}

// The version named need not be one that was ever written. Without --all safe
// says so and stops; with it, the whole secret went.
func TestDestroyingEveryVersionRefusesAVersionThatNeverExisted(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)

	c := newTestCLI(t)
	c.opt.Delete.Destroy = true
	c.opt.Delete.All = true
	if err := c.cmdDelete("delete", "secret/app^99"); err == nil {
		t.Fatal("expected a refusal, got nil")
	}

	if states := fv.versionStates("secret/app"); len(states) != 2 {
		t.Errorf("version states = %v, want both versions still there", states)
	}
}

// Naming no version leaves --all meaning what it always meant.
func TestDeletingEveryVersionOfAWholeSecret(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)

	c := newTestCLI(t)
	c.opt.Delete.All = true
	if err := c.cmdDelete("delete", "secret/app"); err != nil {
		t.Fatalf("cmdDelete --all: %v", err)
	}

	got := fv.versionStates("secret/app")
	want := []string{"deleted", "deleted"}
	if !equalStrings(got, want) {
		t.Errorf("version states = %v, want %v", got, want)
	}
}

func TestDestroyingEveryVersionOfAWholeSecret(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)

	c := newTestCLI(t)
	c.opt.Delete.Destroy = true
	c.opt.Delete.All = true
	if err := c.cmdDelete("delete", "secret/app"); err != nil {
		t.Fatalf("cmdDelete --destroy --all: %v", err)
	}

	if states := fv.versionStates("secret/app"); len(states) != 0 {
		t.Errorf("version states = %v, want the secret gone", states)
	}
}

// One version at a time is what a named version has always meant, and it goes
// on meaning it.
func TestDeletingOneNamedVersionWithoutAll(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
		map[string]string{"password": "three"},
	)

	c := newTestCLI(t)
	if err := c.cmdDelete("delete", "secret/app^2"); err != nil {
		t.Fatalf("cmdDelete: %v", err)
	}

	got := fv.versionStates("secret/app")
	want := []string{"alive", "deleted", "alive"}
	if !equalStrings(got, want) {
		t.Errorf("version states = %v, want %v", got, want)
	}
}
