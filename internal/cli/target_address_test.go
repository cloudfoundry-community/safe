package cli

// `safe target' takes an address and an alias in either order, and told them
// apart by looking for an http:// or https:// prefix on the second one. An
// address typed without its scheme matched neither test, so the two arguments
// were swapped on the assumption that the first one was the address: the
// target was then filed under the address and pointed at the alias, and every
// command run against it went to whatever answers on port 80 of localhost.

import (
	"strings"
	"testing"
)

func TestTargetTakesTheAddressInEitherOrder(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		wantAlias  string
		wantAddres string
	}{
		{
			name:       "address then alias",
			args:       []string{"https://vault.example.com", "ops"},
			wantAlias:  "ops",
			wantAddres: "https://vault.example.com",
		},
		{
			name:       "alias then address",
			args:       []string{"ops", "https://vault.example.com"},
			wantAlias:  "ops",
			wantAddres: "https://vault.example.com",
		},
		{
			name:       "an unencrypted address is still an address",
			args:       []string{"ops", "http://vault.example.com:8200"},
			wantAlias:  "ops",
			wantAddres: "http://vault.example.com:8200",
		},
		{
			//The scheme is matched the way a URL is read rather than by the
			// literal prefix it usually has.
			name:       "the scheme is not case sensitive",
			args:       []string{"ops", "HTTPS://vault.example.com"},
			wantAlias:  "ops",
			wantAddres: "HTTPS://vault.example.com",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			c := newTestCLI(t)
			c.opt.Quiet = true

			if err := c.cmdTarget("target", tc.args...); err != nil {
				t.Fatalf("cmdTarget %v: %v", tc.args, err)
			}

			cfg := readConfig(t)
			v, ok := cfg.Vaults[tc.wantAlias]
			if !ok {
				t.Fatalf("config holds %v, want a target named %s", cfg.Vaults, tc.wantAlias)
			}
			if v.URL != tc.wantAddres {
				t.Errorf("%s is at %q, want %q", tc.wantAlias, v.URL, tc.wantAddres)
			}
			if cfg.Current != tc.wantAlias {
				t.Errorf("current = %q, want %s", cfg.Current, tc.wantAlias)
			}
		})
	}
}

// Neither argument being an address is the case that used to be filed anyway.
func TestTargetRefusesTwoArgumentsWithNoAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "no scheme", args: []string{"ops", "vault.example.com"}},
		{name: "no scheme and a port", args: []string{"ops", "vault.example.com:8200"}},
		{name: "a scheme safe does not speak", args: []string{"ops", "ftp://vault.example.com"}},
		{name: "a scheme naming no host", args: []string{"ops", "https://"}},
		{name: "something no URL can be read out of", args: []string{"ops", "https://vault.example.com/%zz"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			c := newTestCLI(t)
			c.opt.Quiet = true

			err := c.cmdTarget("target", tc.args...)
			if err == nil {
				t.Fatalf("cmdTarget %v returned nil, want a refusal", tc.args)
			}
			for _, arg := range tc.args {
				if !strings.Contains(err.Error(), arg) {
					t.Errorf("error %q should quote the argument %q", err, arg)
				}
			}

			cfg := readConfig(t)
			if len(cfg.Vaults) != 0 {
				t.Errorf("config holds %v, want nothing filed", cfg.Vaults)
			}
			if cfg.Current != "" {
				t.Errorf("current = %q, want nothing targeted", cfg.Current)
			}
		})
	}
}
