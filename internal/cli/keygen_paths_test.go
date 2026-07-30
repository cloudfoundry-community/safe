package cli

// safe ssh and safe rsa take a list of paths and give each one its own key.
// Nothing exercised that past the argument-count guard, so a change that made
// either of them stop after the first path went unnoticed.

import "testing"

func TestSshWritesAKeypairToEveryPathGiven(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	//1024 is the smallest key size Go will generate, and the size is not what
	// is under test here.
	if err := c.cmdSsh("ssh", "1024", "secret/one", "secret/two"); err != nil {
		t.Fatalf("cmdSsh: %v", err)
	}

	for _, path := range []string{"secret/one", "secret/two"} {
		for _, key := range []string{"private", "public", "fingerprint"} {
			if fv.get(path)[key] == "" {
				t.Errorf("%s has no %s, want a generated keypair", path, key)
			}
		}
	}
	if fv.get("secret/one")["public"] == fv.get("secret/two")["public"] {
		t.Error("both paths hold the same public key, want a keypair generated for each")
	}
}

func TestRsaWritesAKeypairToEveryPathGiven(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	if err := c.cmdRsa("rsa", "1024", "secret/one", "secret/two"); err != nil {
		t.Fatalf("cmdRsa: %v", err)
	}

	for _, path := range []string{"secret/one", "secret/two"} {
		for _, key := range []string{"private", "public"} {
			if fv.get(path)[key] == "" {
				t.Errorf("%s has no %s, want a generated keypair", path, key)
			}
		}
	}
	if fv.get("secret/one")["public"] == fv.get("secret/two")["public"] {
		t.Error("both paths hold the same public key, want a keypair generated for each")
	}
}

// A path that cannot be written to stops both of them before the first key is
// generated, rather than after the paths before it have been written.
func TestSshRefusesEveryPathBeforeGenerating(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	if err := c.cmdSsh("ssh", "1024", "secret/one", "secret/two:key"); err == nil {
		t.Fatal("expected a refusal of the path naming a key, got nil")
	}
	if kv := fv.get("secret/one"); len(kv) != 0 {
		t.Errorf("secret/one = %v, want nothing written", kv)
	}
}

func TestRsaRefusesEveryPathBeforeGenerating(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	if err := c.cmdRsa("rsa", "1024", "secret/one", "secret/two^2"); err == nil {
		t.Fatal("expected a refusal of the path naming a version, got nil")
	}
	if kv := fv.get("secret/one"); len(kv) != 0 {
		t.Errorf("secret/one = %v, want nothing written", kv)
	}
}
