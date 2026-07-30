package cli

// safe gen takes any number of secrets and keys, and used to read each pair as
// it came to it. A refusal on a later pair therefore arrived with the earlier
// ones already generated and written, and an argument list that ran out in the
// middle was answered with the usage after some of it had been carried out.

import (
	"strings"
	"testing"
)

// genCLI is newKeygenCLI with the character policy the real CLI sets when
// --policy is not given.
func genCLI(t *testing.T) *CLI {
	t.Helper()
	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	return c
}

// Each of these argument lists is refused on its second pair. The first pair
// names a secret that has to be left alone.
func TestNoPasswordIsWrittenWhenALaterPairIsRefused(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{
			name: "the list runs out before the key",
			args: []string{"secret/keep", "pw", "secret/second"},
		},
		{
			name: "the path names a version",
			args: []string{"secret/keep", "pw", "secret/second^3", "pw"},
		},
		{
			name: "the key names a key",
			args: []string{"secret/keep", "pw", "secret/second", "a:b"},
		},
		{
			name: "the key of a path:key pair names a version",
			args: []string{"secret/keep", "pw", "secret/second:pw^3"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			fv := newCLIFake(t)

			c := genCLI(t)
			if err := c.cmdGen("gen", tc.args...); err == nil {
				t.Fatal("expected a refusal, got nil")
			}

			if kv := fv.get("secret/keep"); len(kv) != 0 {
				t.Errorf("secret/keep = %v, want nothing written", kv)
			}
		})
	}
}

// A list that runs out before the key is a matter for the usage: what is
// wrong with it is an argument that is not there, rather than one that cannot
// be used.
func TestAnIncompleteGenListIsAUsageError(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := genCLI(t)
	assertUsageError(t, c.cmdGen("gen", "secret/keep", "pw", "secret/second"), "gen")

	if kv := fv.get("secret/keep"); len(kv) != 0 {
		t.Errorf("secret/keep = %v, want nothing written", kv)
	}
}

// A complete list still writes every pair, in either of the two forms.
func TestEveryPairIsWrittenWhenTheListIsComplete(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := genCLI(t)
	if err := c.cmdGen("gen", "16", "secret/one", "pw", "secret/two:token"); err != nil {
		t.Fatalf("cmdGen: %v", err)
	}

	for _, tc := range []struct{ path, key string }{
		{"secret/one", "pw"},
		{"secret/two", "token"},
	} {
		if got := fv.get(tc.path)[tc.key]; len(got) != 16 {
			t.Errorf("%s:%s = %q, want 16 characters", tc.path, tc.key, got)
		}
	}
}

// A length of zero comes back as a refusal rather than an empty password, and
// says so before anything is written.
func TestGeneratingNoCharactersIsRefused(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)

	c := genCLI(t)
	err := c.cmdGen("gen", "0", "secret/empty", "pw")
	if err == nil {
		t.Fatal("expected a refusal generating a password of no characters, got nil")
	}
	if !strings.Contains(err.Error(), "0") {
		t.Errorf("error %q should name the length", err)
	}
	if kv := fv.get("secret/empty"); len(kv) != 0 {
		t.Errorf("secret/empty = %v, want nothing written", kv)
	}
}
