package rc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setHome points HOME at a fresh temp directory for the duration of the test so
// saferc()/svtoken()/userHomeDir() resolve to an isolated, writable location.
// t.Setenv restores the previous value on cleanup, so the developer's real
// dotfiles are never read or written. It also forbids t.Parallel, which keeps
// the package-level cleanup state (toCleanup) free of cross-test races.
func setHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	// userHomeDir reads HOME on unix and USERPROFILE on Windows; set both so the
	// helper is correct on either platform. The Windows branch is not exercised
	// here (tests run on unix).
	t.Setenv("USERPROFILE", dir)
	return dir
}

// clearVaultEnv neutralizes the VAULT_* variables Config.Apply reads or writes
// so each test controls its own inputs. t.Setenv records the pre-test values
// and restores them on cleanup, undoing the os.Setenv calls Apply performs.
func clearVaultEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"VAULT_ADDR", "VAULT_TOKEN", "VAULT_SKIP_VERIFY",
		"VAULT_CACERT", "VAULT_NAMESPACE",
	} {
		t.Setenv(k, "")
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("writing %s: %s", path, err)
	}
}

// TestRead covers the four filesystem paths through Read: a missing file
// returns an empty v1 config without error; invalid YAML returns an error
// (QC-12 fix — prevents a subsequent Write from clobbering a recoverable
// .saferc); a modern v1 file round-trips; a legacy (version 0) file is
// converted.
func TestRead(t *testing.T) {
	t.Run("missing file yields empty v1 config", func(t *testing.T) {
		setHome(t)
		c, err := Read()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if c.Version != 1 {
			t.Errorf("Version: got %d, want 1", c.Version)
		}
		if len(c.Vaults) != 0 {
			t.Errorf("Vaults: got %d entries, want 0", len(c.Vaults))
		}
	})

	t.Run("invalid yaml returns error", func(t *testing.T) {
		home := setHome(t)
		writeFile(t, filepath.Join(home, ".saferc"), "vaults: [unterminated")
		_, err := Read()
		if err == nil {
			t.Fatal("expected error for malformed .saferc, got nil")
		}
		if !strings.Contains(err.Error(), "could not parse config") {
			t.Errorf("error message %q does not contain 'could not parse config'", err.Error())
		}
	})

	t.Run("parses a v1 config", func(t *testing.T) {
		home := setHome(t)
		writeFile(t, filepath.Join(home, ".saferc"), `version: 1
current: prod
vaults:
  prod:
    url: https://vault.prod:8200
    token: prod-token
  dev:
    url: https://vault.dev:8200
    token: dev-token
    skip_verify: true
    strongbox: true
    namespace: dev-ns
options:
  manage_vault_token: true
`)
		c, err := Read()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if c.Version != 1 || c.Current != "prod" {
			t.Fatalf("got version=%d current=%q, want 1/prod", c.Version, c.Current)
		}
		if len(c.Vaults) != 2 {
			t.Fatalf("Vaults: got %d, want 2", len(c.Vaults))
		}
		if prod := c.Vaults["prod"]; prod == nil || prod.URL != "https://vault.prod:8200" || prod.Token != "prod-token" {
			t.Errorf("prod vault wrong: %+v", prod)
		}
		dev := c.Vaults["dev"]
		if dev == nil || !dev.SkipVerify || !dev.Strongbox || dev.Namespace != "dev-ns" {
			t.Errorf("dev vault wrong: %+v", dev)
		}
		if !c.Options.ManageVaultToken {
			t.Error("expected ManageVaultToken to be true")
		}
	})

	t.Run("ignores the no_strongbox key older configs carry", func(t *testing.T) {
		home := setHome(t)
		//Both spellings a pre-opt-in config could hold: true asked for what is
		// now the default, and false asked for the Strongbox that now takes
		// strongbox: true to get. Neither target has one.
		writeFile(t, filepath.Join(home, ".saferc"), `version: 1
current: prod
vaults:
  prod:
    url: https://vault.prod:8200
    no_strongbox: false
  dev:
    url: https://vault.dev:8200
    no_strongbox: true
`)
		c, err := Read()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		for name, v := range c.Vaults {
			if v.Strongbox {
				t.Errorf("%s: got Strongbox, want none without strongbox: true", name)
			}
		}
	})

	t.Run("converts a legacy v0 config", func(t *testing.T) {
		home := setHome(t)
		writeFile(t, filepath.Join(home, ".saferc"), `Current: prod
Aliases:
  prod: https://vault.prod:8200
  dev: https://vault.dev:8200
Targets:
  https://vault.prod:8200: prod-token
  https://vault.dev:8200: dev-token
SkipVerify:
  https://vault.dev:8200: true
`)
		c, err := Read()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if c.Version != 1 {
			t.Errorf("Version: got %d, want 1 after conversion", c.Version)
		}
		if c.Current != "prod" {
			t.Errorf("Current: got %q, want prod", c.Current)
		}
		prod := c.Vaults["prod"]
		if prod == nil || prod.URL != "https://vault.prod:8200" || prod.Token != "prod-token" || prod.SkipVerify {
			t.Errorf("converted prod vault wrong: %+v", prod)
		}
		dev := c.Vaults["dev"]
		if dev == nil || dev.Token != "dev-token" || !dev.SkipVerify {
			t.Errorf("converted dev vault wrong: %+v", dev)
		}
	})
}

// TestWrite covers persisting a config: the saferc and svtoken files are
// created with 0600 permissions and the expected contents, the svtoken is
// removed when no target is current, and ManageVaultToken mirrors the token
// into ~/.vault-token.
func TestWrite(t *testing.T) {
	t.Run("creates saferc and svtoken with 0600 perms", func(t *testing.T) {
		home := setHome(t)
		c := Config{
			Version: 1,
			Current: "prod",
			Vaults: map[string]*Vault{
				"prod": {URL: "https://vault.prod:8200", Token: "prod-token", Namespace: "ns"},
			},
		}
		if err := c.Write(); err != nil {
			t.Fatalf("Write: %s", err)
		}

		assertPerm(t, filepath.Join(home, ".saferc"), 0600)
		assertPerm(t, filepath.Join(home, ".svtoken"), 0600)

		sv := readFile(t, filepath.Join(home, ".svtoken"))
		for _, want := range []string{"https://vault.prod:8200", "prod-token", "ns"} {
			if !strings.Contains(sv, want) {
				t.Errorf(".svtoken missing %q, got:\n%s", want, sv)
			}
		}
		if _, err := os.Stat(filepath.Join(home, ".vault-token")); !os.IsNotExist(err) {
			t.Errorf("expected no ~/.vault-token without ManageVaultToken (stat err: %v)", err)
		}
	})

	t.Run("removes svtoken when no target is current", func(t *testing.T) {
		home := setHome(t)
		// Pre-seed an svtoken to prove Write removes it.
		writeFile(t, filepath.Join(home, ".svtoken"), "stale: true\n")

		c := Config{Version: 1} // Current empty => Vault("") returns nil
		if err := c.Write(); err != nil {
			t.Fatalf("Write: %s", err)
		}
		if _, err := os.Stat(filepath.Join(home, ".saferc")); err != nil {
			t.Errorf("expected ~/.saferc to be written: %v", err)
		}
		if _, err := os.Stat(filepath.Join(home, ".svtoken")); !os.IsNotExist(err) {
			t.Errorf("expected ~/.svtoken to be removed, stat err: %v", err)
		}
	})

	t.Run("ManageVaultToken mirrors token into ~/.vault-token", func(t *testing.T) {
		home := setHome(t)
		c := Config{
			Version: 1,
			Current: "prod",
			Vaults:  map[string]*Vault{"prod": {URL: "https://vault.prod:8200", Token: "secret-token"}},
			Options: Options{ManageVaultToken: true},
		}
		if err := c.Write(); err != nil {
			t.Fatalf("Write: %s", err)
		}
		assertPerm(t, filepath.Join(home, ".vault-token"), 0600)
		if got := readFile(t, filepath.Join(home, ".vault-token")); got != "secret-token" {
			t.Errorf("~/.vault-token: got %q, want %q", got, "secret-token")
		}
	})

	t.Run("round-trips through Read", func(t *testing.T) {
		setHome(t)
		c := Config{
			Version: 1,
			Current: "prod",
			Vaults: map[string]*Vault{
				"prod": {URL: "https://vault.prod:8200", Token: "prod-token", SkipVerify: true, Namespace: "ns"},
			},
		}
		if err := c.Write(); err != nil {
			t.Fatalf("Write: %s", err)
		}
		got, err := Read()
		if err != nil {
			t.Fatalf("Read: %s", err)
		}
		if got.Current != c.Current || len(got.Vaults) != 1 {
			t.Fatalf("round-trip mismatch: %+v", got)
		}
		p := got.Vaults["prod"]
		if p == nil || p.URL != "https://vault.prod:8200" || p.Token != "prod-token" || !p.SkipVerify || p.Namespace != "ns" {
			t.Errorf("round-trip vault wrong: %+v", p)
		}
	})
}

// TestConfigApply covers the environment side effects of applying a target:
// populating VAULT_* from the selected vault (including a temp CA cert file),
// and the no-target fallback that reads ~/.vault-token only when VAULT_TOKEN
// is empty.
func TestConfigApply(t *testing.T) {
	t.Run("populates VAULT_* from the current vault", func(t *testing.T) {
		setHome(t)
		clearVaultEnv(t)
		t.Cleanup(Cleanup)

		c := Config{
			Version: 1,
			Current: "prod",
			Vaults: map[string]*Vault{
				"prod": {
					URL:        "https://vault.prod:8200",
					Token:      "prod-token",
					SkipVerify: true,
					CACerts:    []string{"-----BEGIN A-----", "-----BEGIN B-----"},
					Namespace:  "prod-ns",
				},
			},
		}
		if err := c.Apply(""); err != nil {
			t.Fatalf("Apply: %s", err)
		}
		assertEnv(t, "VAULT_ADDR", "https://vault.prod:8200")
		assertEnv(t, "VAULT_TOKEN", "prod-token")
		assertEnv(t, "VAULT_SKIP_VERIFY", "1")
		assertEnv(t, "VAULT_NAMESPACE", "prod-ns")

		caFile := os.Getenv("VAULT_CACERT")
		if caFile == "" {
			t.Fatal("expected VAULT_CACERT to be set to a temp file")
		}
		if got := readFile(t, caFile); got != "-----BEGIN A-----\n-----BEGIN B-----" {
			t.Errorf("CA cert file contents wrong: %q", got)
		}
	})

	t.Run("no target falls back to ~/.vault-token when VAULT_TOKEN empty", func(t *testing.T) {
		home := setHome(t)
		clearVaultEnv(t)
		writeFile(t, filepath.Join(home, ".vault-token"), "  file-token\n")

		c := Config{Version: 1} // no current target
		if err := c.Apply(""); err != nil {
			t.Fatalf("Apply: %s", err)
		}
		assertEnv(t, "VAULT_TOKEN", "file-token")
	})

	t.Run("no target keeps an existing VAULT_TOKEN", func(t *testing.T) {
		home := setHome(t)
		clearVaultEnv(t)
		t.Setenv("VAULT_TOKEN", "env-token")
		writeFile(t, filepath.Join(home, ".vault-token"), "file-token\n")

		c := Config{Version: 1}
		if err := c.Apply(""); err != nil {
			t.Fatalf("Apply: %s", err)
		}
		assertEnv(t, "VAULT_TOKEN", "env-token")
	})
}

// TestApply covers the package-level Apply, which reads ~/.saferc from disk and
// then applies the named target's environment.
func TestApply(t *testing.T) {
	home := setHome(t)
	clearVaultEnv(t)
	writeFile(t, filepath.Join(home, ".saferc"), `version: 1
current: prod
vaults:
  prod:
    url: https://vault.prod:8200
    token: prod-token
`)
	c, err := Apply("prod")
	if err != nil {
		t.Fatalf("Apply: %s", err)
	}
	if c.Current != "prod" {
		t.Errorf("Current: got %q, want prod", c.Current)
	}
	assertEnv(t, "VAULT_ADDR", "https://vault.prod:8200")
	assertEnv(t, "VAULT_TOKEN", "prod-token")
}

// TestWriteTempCACerts verifies the temp CA file is created with the certs
// joined by newlines, tracked for cleanup, and removed by Cleanup. Cleanup is
// also exercised for idempotency.
func TestWriteTempCACerts(t *testing.T) {
	Cleanup() // start from a clean cleanup list
	t.Cleanup(Cleanup)

	certs := []string{"-----BEGIN ONE-----", "-----BEGIN TWO-----"}
	path, err := writeTempCACerts(certs)
	if err != nil {
		t.Fatalf("writeTempCACerts: %s", err)
	}
	if got := readFile(t, path); got != "-----BEGIN ONE-----\n-----BEGIN TWO-----" {
		t.Errorf("temp CA contents wrong: %q", got)
	}

	Cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected Cleanup to remove %s, stat err: %v", path, err)
	}
	// A second Cleanup must be a harmless no-op.
	Cleanup()
}

// TestFind covers target resolution: an exact alias hit, a unique match by URL
// (with trailing-slash normalization), the ambiguous multi-URL error, and a
// miss. Write and Apply both lean on Find via Vault, so its branches matter.
func TestFind(t *testing.T) {
	c := Config{
		Vaults: map[string]*Vault{
			"prod":  {URL: "https://vault.prod:8200"},
			"alias": {URL: "https://vault.shared:8200"},
			"dupe":  {URL: "https://vault.shared:8200"},
		},
	}

	t.Run("exact alias hit", func(t *testing.T) {
		v, ok, err := c.Find("prod")
		if err != nil || !ok || v.URL != "https://vault.prod:8200" {
			t.Fatalf("got (%+v, %v, %v)", v, ok, err)
		}
	})

	t.Run("unique URL match with trailing slash", func(t *testing.T) {
		v, ok, err := c.Find("https://vault.prod:8200/")
		if err != nil || !ok || v.URL != "https://vault.prod:8200" {
			t.Fatalf("got (%+v, %v, %v)", v, ok, err)
		}
	})

	t.Run("ambiguous URL is an error", func(t *testing.T) {
		_, ok, err := c.Find("https://vault.shared:8200")
		if err == nil {
			t.Fatal("expected an ambiguity error")
		}
		if !ok {
			t.Error("expected ok=true alongside the ambiguity error")
		}
		if !strings.Contains(err.Error(), "More than one target") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("miss", func(t *testing.T) {
		v, ok, err := c.Find("nope")
		if err != nil || ok || v != nil {
			t.Fatalf("got (%+v, %v, %v), want (nil, false, nil)", v, ok, err)
		}
	})
}

// TestVault covers the current-target indirection: an empty argument resolves
// the current alias, an empty current is a non-error nil, and an unknown
// current surfaces an error.
func TestVault(t *testing.T) {
	c := Config{
		Current: "prod",
		Vaults:  map[string]*Vault{"prod": {URL: "https://vault.prod:8200"}},
	}

	t.Run("empty argument resolves current", func(t *testing.T) {
		v, err := c.Vault("")
		if err != nil || v == nil || v.URL != "https://vault.prod:8200" {
			t.Fatalf("got (%+v, %v)", v, err)
		}
	})

	t.Run("no current is a non-error nil", func(t *testing.T) {
		empty := Config{}
		v, err := empty.Vault("")
		if err != nil || v != nil {
			t.Fatalf("got (%+v, %v), want (nil, nil)", v, err)
		}
	})

	t.Run("unknown current errors", func(t *testing.T) {
		bad := Config{Current: "ghost"}
		if _, err := bad.Vault(""); err == nil {
			t.Fatal("expected error for unknown current target")
		}
	})
}

// TestConfigAccessors covers the in-memory mutators and current-target readers.
func TestConfigAccessors(t *testing.T) {
	t.Run("SetTarget makes the alias current and preserves token on same URL", func(t *testing.T) {
		var c Config // nil Vaults map; SetTarget must initialize it
		if err := c.SetTarget("prod", Vault{URL: "https://vault.prod:8200", Token: "tok"}); err != nil {
			t.Fatalf("SetTarget: %s", err)
		}
		if c.Current != "prod" || c.Vaults["prod"].Token != "tok" {
			t.Fatalf("after SetTarget: %+v", c)
		}
		// Re-targeting the same URL without a token keeps the existing one.
		if err := c.SetTarget("prod", Vault{URL: "https://vault.prod:8200"}); err != nil {
			t.Fatalf("SetTarget: %s", err)
		}
		if c.Vaults["prod"].Token != "tok" {
			t.Errorf("expected token preserved on same-URL retarget, got %q", c.Vaults["prod"].Token)
		}
	})

	t.Run("SetToken requires a current target", func(t *testing.T) {
		var c Config
		if err := c.SetToken("x"); err == nil {
			t.Error("expected error setting token with no current target")
		}
		if err := c.SetTarget("prod", Vault{URL: "u"}); err != nil {
			t.Fatalf("SetTarget: %s", err)
		}
		if err := c.SetToken("new"); err != nil {
			t.Fatalf("SetToken: %s", err)
		}
		if c.Vaults["prod"].Token != "new" {
			t.Errorf("token: got %q, want new", c.Vaults["prod"].Token)
		}
	})

	t.Run("SetTokenFor names its target and leaves the current one alone", func(t *testing.T) {
		c := Config{
			Current: "prod",
			Vaults: map[string]*Vault{
				"prod":  {URL: "https://prod:8200", Token: "prod-token"},
				"stage": {URL: "https://stage:8200", Token: "stage-token"},
			},
		}
		if err := c.SetTokenFor("stage", "new"); err != nil {
			t.Fatalf("SetTokenFor: %s", err)
		}
		if c.Vaults["stage"].Token != "new" {
			t.Errorf("stage token: got %q, want new", c.Vaults["stage"].Token)
		}
		if c.Vaults["prod"].Token != "prod-token" {
			t.Errorf("prod token: got %q, want it untouched", c.Vaults["prod"].Token)
		}
		if c.Current != "prod" {
			t.Errorf("current: got %q, want prod", c.Current)
		}
		if err := c.SetTokenFor("ghost", "x"); err == nil {
			t.Error("expected error setting a token on an unknown target")
		}
		if err := c.SetTokenFor("", "x"); err == nil {
			t.Error("expected error setting a token with no target named")
		}
	})

	t.Run("Alias resolves a name to the key it is stored under", func(t *testing.T) {
		c := Config{
			Vaults: map[string]*Vault{
				"prod":  {URL: "https://prod:8200"},
				"stage": {URL: "https://stage:8200/"},
			},
		}

		for _, tc := range []struct{ name, want string }{
			{"prod", "prod"},
			{"https://prod:8200", "prod"},
			{"https://prod:8200/", "prod"},
			{"https://stage:8200", "stage"},
		} {
			got, ok, err := c.Alias(tc.name)
			if err != nil || !ok {
				t.Fatalf("Alias(%q) = %q, %v, %v", tc.name, got, ok, err)
			}
			if got != tc.want {
				t.Errorf("Alias(%q) = %q, want %q", tc.name, got, tc.want)
			}
		}

		if _, ok, err := c.Alias("ghost"); ok || err != nil {
			t.Errorf("Alias(ghost) = %v, %v; want not found and no error", ok, err)
		}

		//An alias always wins over a URL, so a target named after another
		//target's URL still resolves to itself.
		shared := Config{
			Vaults: map[string]*Vault{
				"one": {URL: "https://shared:8200"},
				"two": {URL: "https://shared:8200"},
			},
		}
		if _, _, err := shared.Alias("https://shared:8200"); err == nil {
			t.Error("expected an error for a URL naming two targets")
		}
	})

	t.Run("SetCurrent validates the alias and can reskip", func(t *testing.T) {
		c := Config{Vaults: map[string]*Vault{"prod": {URL: "u"}}}
		if err := c.SetCurrent("ghost", false); err == nil {
			t.Error("expected error for unknown alias")
		}
		if err := c.SetCurrent("prod", true); err != nil {
			t.Fatalf("SetCurrent: %s", err)
		}
		if c.Current != "prod" || !c.Vaults["prod"].SkipVerify {
			t.Errorf("after SetCurrent reskip: %+v", c.Vaults["prod"])
		}
	})

	t.Run("current-target readers reflect the selected vault", func(t *testing.T) {
		c := Config{
			Current: "prod",
			Vaults: map[string]*Vault{"prod": {
				URL:        "https://vault.prod:8200",
				SkipVerify: true,
				Strongbox:  true,
				CACerts:    []string{"ca"},
				Namespace:  "ns",
			}},
		}
		if c.URL() != "https://vault.prod:8200" {
			t.Errorf("URL: got %q", c.URL())
		}
		if c.Verified() {
			t.Error("Verified: got true, want false (SkipVerify set)")
		}
		if !c.HasStrongbox() {
			t.Error("HasStrongbox: got false, want true (Strongbox set)")
		}
		if got := c.CACerts(); len(got) != 1 || got[0] != "ca" {
			t.Errorf("CACerts: got %v", got)
		}
		if c.Namespace() != "ns" {
			t.Errorf("Namespace: got %q", c.Namespace())
		}
	})

	t.Run("readers are safe with no current target", func(t *testing.T) {
		var c Config
		if c.URL() != "" || c.Verified() || c.HasStrongbox() || c.CACerts() != nil || c.Namespace() != "" {
			t.Error("expected zero values for an empty config")
		}
	})
}

func assertEnv(t *testing.T, key, want string) {
	t.Helper()
	if got := os.Getenv(key); got != want {
		t.Errorf("%s: got %q, want %q", key, got, want)
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %s", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s perms: got %#o, want %#o", path, got, want)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %s", path, err)
	}
	return string(b)
}
