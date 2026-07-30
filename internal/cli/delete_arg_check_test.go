package cli

// safe delete takes any number of paths. A refusal on the third of them used
// to arrive with the first two already gone.

import (
	"testing"
)

func TestNoPathGoesWhenAnotherIsRefused(t *testing.T) {
	cases := []struct {
		name  string
		setup func(c *CLI)
		args  []string
	}{
		{
			name:  "a key named alongside -r",
			setup: func(c *CLI) { c.opt.Delete.Recurse = true; c.opt.Delete.Force = true },
			args:  []string{"secret/keep", "secret/app:password"},
		},
		{
			name:  "a version named alongside -r",
			setup: func(c *CLI) { c.opt.Delete.Recurse = true; c.opt.Delete.Force = true },
			args:  []string{"secret/keep", "secret/app^1"},
		},
		{
			name:  "a version named alongside --all",
			setup: func(c *CLI) { c.opt.Delete.All = true },
			args:  []string{"secret/keep", "secret/app^1"},
		},
		{
			name:  "a version named alongside --destroy --all",
			setup: func(c *CLI) { c.opt.Delete.Destroy = true; c.opt.Delete.All = true },
			args:  []string{"secret/keep", "secret/app^1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			fv := newCLIFakeV2(t)
			fv.setV2("secret/keep", map[string]string{"password": "keep me"})
			fv.setV2("secret/app", map[string]string{"password": "one"})

			c := newTestCLI(t)
			tc.setup(c)
			if err := c.cmdDelete("delete", tc.args...); err == nil {
				t.Fatal("expected a refusal, got nil")
			}

			got := fv.versionStates("secret/keep")
			want := []string{"alive"}
			if !equalStrings(got, want) {
				t.Errorf("version states of secret/keep = %v, want %v", got, want)
			}
		})
	}
}

// Paths that are all fine still all go.
func TestEveryPathGoesWhenNoneIsRefused(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/one", map[string]string{"password": "a"})
	fv.setV2("secret/two", map[string]string{"password": "b"})

	c := newTestCLI(t)
	if err := c.cmdDelete("delete", "secret/one", "secret/two"); err != nil {
		t.Fatalf("cmdDelete: %v", err)
	}

	for _, path := range []string{"secret/one", "secret/two"} {
		got := fv.versionStates(path)
		want := []string{"deleted"}
		if !equalStrings(got, want) {
			t.Errorf("version states of %s = %v, want %v", path, got, want)
		}
	}
}
