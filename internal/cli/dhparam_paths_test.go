package cli

// safe dhparam took as many paths as were typed and generated parameters for
// the first one only, reporting the success of something nobody asked for. Its
// siblings, safe ssh and safe rsa, take a list and work through all of it.

import (
	"os/exec"
	"testing"
)

// requireOpenSSL skips when the openssl binary dhparam generation shells out to
// is not installed.
func requireOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl is not installed")
	}
}

func TestDhparamWritesEveryPathGiven(t *testing.T) {
	requireOpenSSL(t)
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	//1024 bits is the smallest size dhparam generation accepts, and this test
	// runs it once per path.
	if err := c.cmdDhparam("dhparam", "1024", "secret/one", "secret/two"); err != nil {
		t.Fatalf("cmdDhparam: %v", err)
	}

	for _, path := range []string{"secret/one", "secret/two"} {
		if pem := fv.get(path)["dhparam-pem"]; pem == "" {
			t.Errorf("%s has no dhparam-pem, want generated parameters", path)
		}
	}
	//Each path gets its own parameters, as each path gets its own key under
	// safe ssh and safe rsa.
	if fv.get("secret/one")["dhparam-pem"] == fv.get("secret/two")["dhparam-pem"] {
		t.Error("both paths hold the same parameters, want a set generated for each")
	}
}

// A refused path is refused before anything is generated: dhparam generation
// is slow, and the first path used to be written before the second was read.
func TestDhparamRefusesEveryPathBeforeGenerating(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := newKeygenCLI(t)
	if err := c.cmdDhparam("dhparam", "1024", "secret/one", "secret/two:key"); err == nil {
		t.Fatal("expected a refusal of the path naming a key, got nil")
	}

	if kv := fv.get("secret/one"); len(kv) != 0 {
		t.Errorf("secret/one = %v, want nothing written", kv)
	}
}
