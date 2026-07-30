package cli

// `safe target delete` removed a key from the config map without checking that
// the name matched anything. A name that reached the target everywhere else --
// its URL -- matched nothing here, and neither did a typo, and both reported
// success. The target stayed in ~/.saferc with its token, which is the
// opposite of what someone deleting a target is asking for.

import (
	"encoding/json"
	"strings"
	"testing"
)

// twoNamedTargets writes a config holding alpha and beta, with beta current.
func twoNamedTargets(t *testing.T) {
	t.Helper()
	writeSaferc(t, `version: 1
current: beta
vaults:
  alpha:
    url: https://alpha.example.com
    token: token-alpha
  beta:
    url: https://beta.example.com
    token: token-beta
`)
}

func TestTargetDeleteRemovesTheTargetNamedByAlias(t *testing.T) {
	isolateHome(t)
	twoNamedTargets(t)
	c := newTestCLI(t)

	if err := c.cmdTargetDelete("target delete", "alpha"); err != nil {
		t.Fatalf("cmdTargetDelete: %v", err)
	}

	cfg := readConfig(t)
	if _, ok := cfg.Vaults["alpha"]; ok {
		t.Error("alpha is still in the config")
	}
	if _, ok := cfg.Vaults["beta"]; !ok {
		t.Error("beta should have been left alone")
	}
	if cfg.Current != "beta" {
		t.Errorf("current = %q, want beta", cfg.Current)
	}
}

// The URL is a name `safe target` accepts, so `safe target delete` accepts it.
func TestTargetDeleteRemovesTheTargetNamedByURL(t *testing.T) {
	isolateHome(t)
	twoNamedTargets(t)
	c := newTestCLI(t)

	if err := c.cmdTargetDelete("target delete", "https://alpha.example.com"); err != nil {
		t.Fatalf("cmdTargetDelete: %v", err)
	}

	cfg := readConfig(t)
	if _, ok := cfg.Vaults["alpha"]; ok {
		t.Error("alpha is still in the config after being deleted by URL")
	}
}

// The headline case: a name matching nothing must not report success.
func TestTargetDeleteReportsAnUnknownName(t *testing.T) {
	isolateHome(t)
	twoNamedTargets(t)
	c := newTestCLI(t)

	err := c.cmdTargetDelete("target delete", "typo")
	if err == nil {
		t.Fatal("deleting an unknown target should be an error, got nil")
	}
	if !strings.Contains(err.Error(), "typo") {
		t.Errorf("error %q should name the target it could not find", err)
	}

	cfg := readConfig(t)
	if len(cfg.Vaults) != 2 {
		t.Errorf("config holds %d targets, want both left in place", len(cfg.Vaults))
	}
}

func TestTargetDeleteClearsTheCurrentTargetItRemoved(t *testing.T) {
	isolateHome(t)
	twoNamedTargets(t)
	c := newTestCLI(t)

	if err := c.cmdTargetDelete("target delete", "https://beta.example.com"); err != nil {
		t.Fatalf("cmdTargetDelete: %v", err)
	}

	cfg := readConfig(t)
	if cfg.Current != "" {
		t.Errorf("current = %q, want it cleared along with the target it named", cfg.Current)
	}
}

// A config written before the current target was recorded by alias names it
// by URL instead. Deleting that target by alias left the selection naming a
// Vault that is no longer in the file, which every later command -- including
// the write that stores this deletion -- reports as a missing current target.
func TestTargetDeleteClearsACurrentTargetNamedByURL(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, `version: 1
current: https://alpha.example.com
vaults:
  alpha:
    url: https://alpha.example.com
    token: token-alpha
  beta:
    url: https://beta.example.com
    token: token-beta
`)
	c := newTestCLI(t)

	if err := c.cmdTargetDelete("target delete", "alpha"); err != nil {
		t.Fatalf("cmdTargetDelete: %v", err)
	}

	cfg := readConfig(t)
	if cfg.Current != "" {
		t.Errorf("current = %q, want it cleared along with the target it named", cfg.Current)
	}
	if _, err := cfg.Vault(""); err != nil {
		t.Errorf("reading the current target: %v", err)
	}
}

// Deleting one target leaves the selection on another alone, whichever way
// that selection names it.
func TestTargetDeleteKeepsACurrentTargetItDidNotRemove(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, `version: 1
current: https://beta.example.com
vaults:
  alpha:
    url: https://alpha.example.com
    token: token-alpha
  beta:
    url: https://beta.example.com
    token: token-beta
`)
	c := newTestCLI(t)

	if err := c.cmdTargetDelete("target delete", "alpha"); err != nil {
		t.Fatalf("cmdTargetDelete: %v", err)
	}

	cfg := readConfig(t)
	v, err := cfg.Vault("")
	if err != nil {
		t.Fatalf("reading the current target: %v", err)
	}
	if v.URL != "https://beta.example.com" {
		t.Errorf("current target is %s, want beta", v.URL)
	}
}

// Two aliases for one Vault leave a URL ambiguous, and guessing which to
// delete is worse than saying so.
func TestTargetDeleteRefusesAnAmbiguousURL(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, `version: 1
current: one
vaults:
  one:
    url: https://shared.example.com
    token: token-one
  two:
    url: https://shared.example.com
    token: token-two
`)
	c := newTestCLI(t)

	err := c.cmdTargetDelete("target delete", "https://shared.example.com")
	if err == nil {
		t.Fatal("an ambiguous URL should be an error, got nil")
	}
	if len(readConfig(t).Vaults) != 2 {
		t.Error("neither target should have been deleted")
	}
}

// The JSON listing is the machine-readable half of `safe targets`, which sorts.
// Ranging over the config map ordered it differently on every run.
func TestTargetsJSONListsInASortedOrder(t *testing.T) {
	isolateHome(t)
	writeSaferc(t, `version: 1
current: delta
vaults:
  zeta:
    url: https://zeta.example.com
  alpha:
    url: https://alpha.example.com
  delta:
    url: https://delta.example.com
  beta:
    url: https://beta.example.com
`)
	c := newTestCLI(t)
	c.opt.Targets.JSON = true

	want := []string{"alpha", "beta", "delta", "zeta"}
	//Repeated because map iteration order is random per run: one pass could
	// come out sorted by luck.
	for i := 0; i < 8; i++ {
		out := captureStdout(t, func() {
			if err := c.cmdTargets("targets"); err != nil {
				t.Fatalf("cmdTargets: %v", err)
			}
		})

		var listed []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(out), &listed); err != nil {
			t.Fatalf("targets --json is not JSON: %v\n%s", err, out)
		}

		got := make([]string, 0, len(listed))
		for _, v := range listed {
			got = append(got, v.Name)
		}
		if !sameNames(got, want) {
			t.Fatalf("run %d listed %v, want %v", i+1, got, want)
		}
	}
}

func sameNames(got, want []string) bool {
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
