package rc

// A target can be named by its alias or by its URL: Alias resolves either to
// the key the target is stored under. SetCurrent used to record the name it was
// handed rather than that key, so targeting by URL left `current' holding a URL
// -- a name that resolves only for as long as exactly one target still carries
// it.

import "testing"

func twoTargets() Config {
	return Config{
		Vaults: map[string]*Vault{
			"prod":  {URL: "https://prod.example.com:8200"},
			"stage": {URL: "https://stage.example.com:8200/"},
		},
	}
}

// The URL is a name for the target, not a name for the current selection.
func TestSetCurrentRecordsTheAliasWhenNamedByURL(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"prod", "prod"},
		{"https://prod.example.com:8200", "prod"},
		//Alias tolerates the trailing slash on either side of the comparison,
		// and so does the name that comes back.
		{"https://prod.example.com:8200/", "prod"},
		{"https://stage.example.com:8200", "stage"},
	} {
		c := twoTargets()
		if err := c.SetCurrent(tc.name, false); err != nil {
			t.Errorf("SetCurrent(%q): %v", tc.name, err)
			continue
		}
		if c.Current != tc.want {
			t.Errorf("SetCurrent(%q) left current = %q, want %q", tc.name, c.Current, tc.want)
		}
	}
}

// The stored name is what everything else compares against, so it has to be
// the map key: a lookup that happens to work today is not the same as a name
// that names the target.
func TestCurrentNamesAKeyOfTheVaultMap(t *testing.T) {
	c := twoTargets()
	if err := c.SetCurrent("https://stage.example.com:8200", false); err != nil {
		t.Fatalf("SetCurrent: %v", err)
	}
	if _, ok := c.Vaults[c.Current]; !ok {
		t.Errorf("current = %q, which is not one of the targets", c.Current)
	}
}

// A name that reaches no target is still refused, and leaves the selection
// alone rather than pointing it at nothing.
func TestSetCurrentRefusesAnUnknownName(t *testing.T) {
	c := twoTargets()
	c.Current = "prod"
	if err := c.SetCurrent("https://ghost.example.com", false); err == nil {
		t.Fatal("SetCurrent with an unknown URL returned nil, want a refusal")
	}
	if c.Current != "prod" {
		t.Errorf("current = %q, want the previous selection kept", c.Current)
	}
}

// --insecure applies to the target that was named, however it was named.
func TestSetCurrentReskipsTheTargetNamedByURL(t *testing.T) {
	c := twoTargets()
	if err := c.SetCurrent("https://prod.example.com:8200", true); err != nil {
		t.Fatalf("SetCurrent: %v", err)
	}
	if !c.Vaults["prod"].SkipVerify {
		t.Error("prod should have been marked skip_verify")
	}
	if c.Vaults["stage"].SkipVerify {
		t.Error("stage should have been left alone")
	}
}

// A URL two targets share names neither of them. The ambiguity is reported
// rather than resolved by whichever key the map happened to yield.
func TestSetCurrentReportsAnAmbiguousURL(t *testing.T) {
	c := Config{
		Current: "one",
		Vaults: map[string]*Vault{
			"one": {URL: "https://shared.example.com"},
			"two": {URL: "https://shared.example.com"},
		},
	}
	if err := c.SetCurrent("https://shared.example.com", false); err == nil {
		t.Fatal("SetCurrent with a shared URL returned nil, want a refusal")
	}
	if c.Current != "one" {
		t.Errorf("current = %q, want the previous selection kept", c.Current)
	}
}
