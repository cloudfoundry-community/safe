package cli

// `safe renew all' renews the token of every configured target in turn, and
// it is the only command that applies more than one target in a single run.
// Applying a target sets the environment the Vault client is built from, and
// a setting the next target does not carry was left behind by the one before
// it: a target with certificate verification switched off switched it off for
// every target renewed after it, and a namespace was sent to a Vault that has
// none.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeRenewVault answers the token renewal endpoint and records what it was
// asked with. Renewal is the only request the command makes of it.
type fakeRenewVault struct {
	mu  sync.Mutex
	url string
	//renewals holds one entry per renewal served, oldest first.
	renewals []renewal
	//reject makes every renewal answer 403, the way a Vault answers for a
	// token that has already expired.
	reject bool
}

type renewal struct{ token, namespace string }

func newRenewFake(t *testing.T) *fakeRenewVault {
	t.Helper()
	f := &fakeRenewVault{}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

func (f *fakeRenewVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path != "/v1/auth/token/renew-self" || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.renewals = append(f.renewals, renewal{
		token:     r.Header.Get("X-Vault-Token"),
		namespace: r.Header.Get("X-Vault-Namespace"),
	})
	if f.reject {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// served returns the renewals this Vault answered, in order.
func (f *fakeRenewVault) served() []renewal {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]renewal(nil), f.renewals...)
}

// newRenewCLI builds a CLI with `renew' registered, so that a bad invocation
// can find its usage.
func newRenewCLI(t *testing.T) *CLI {
	t.Helper()
	r := NewRunner()
	c := &CLI{opt: &Options{}, r: r}
	r.Dispatch("renew", &Help{
		Summary: "Renew one or more authentication tokens",
		Usage:   "safe renew [all]\n",
		Type:    AdministrativeCommand,
	}, c.cmdRenew)
	return c
}

// A target that says nothing about certificate verification or namespaces is
// entitled to both: the settings of the target renewed before it are not its
// own.
func TestRenewAllDoesNotCarrySettingsBetweenTargets(t *testing.T) {
	isolateHome(t)
	alpha, beta := newRenewFake(t), newRenewFake(t)
	writeSaferc(t, `version: 1
current: alpha
vaults:
  alpha:
    url: `+alpha.url+`
    token: token-alpha
    namespace: alpha-ns
    skip_verify: true
  beta:
    url: `+beta.url+`
    token: token-beta
`)

	c := newRenewCLI(t)
	var err error
	warnings := captureStderr(t, func() {
		_ = captureStdout(t, func() { err = c.cmdRenew("renew", "all") })
	})
	if err != nil {
		t.Fatalf("renew all: %v", err)
	}

	got := beta.served()
	if len(got) != 1 {
		t.Fatalf("beta served %d renewals, want 1", len(got))
	}
	if got[0].namespace != "" {
		t.Errorf("beta was renewed in namespace %q, which belongs to alpha", got[0].namespace)
	}

	//Certificate verification being switched off is announced once per Vault
	// built with it off, which is the only place the setting shows.
	if n := strings.Count(warnings, "verification disabled"); n != 1 {
		t.Errorf("verification was disabled for %d targets, want 1\n---\n%s", n, warnings)
	}
}

// With no targets configured there is nothing for `renew all' to renew, and
// it used to say so by printing nothing at all and succeeding. The token in
// the environment, which plain `safe renew' does renew, is not a target and is
// not covered by all.
func TestRenewAllSaysWhenThereIsNothingToRenew(t *testing.T) {
	isolateHome(t)
	fv := newRenewFake(t)
	t.Setenv("VAULT_ADDR", fv.url)
	t.Setenv("VAULT_TOKEN", "token-from-the-environment")

	c := newRenewCLI(t)
	var err error
	said := captureStderr(t, func() {
		_ = captureStdout(t, func() { err = c.cmdRenew("renew", "all") })
	})
	if err != nil {
		t.Fatalf("renew all with no targets: %v", err)
	}
	if !strings.Contains(said, "no targets") {
		t.Errorf("output should say there are no targets to renew\n---\n%s", said)
	}
	if got := fv.served(); len(got) != 0 {
		t.Errorf("the environment is not a target, and served %v", got)
	}
}

// A target that cannot be connected to at all -- one carrying no address, or
// an address that will not parse -- used to end the whole run where it stood,
// with a message telling the user to target a Vault. The targets after it went
// unrenewed and unmentioned, and the count of what failed was never printed.
func TestRenewAllCarriesOnPastATargetItCannotConnectTo(t *testing.T) {
	isolateHome(t)
	good := newRenewFake(t)
	writeSaferc(t, `version: 1
current: zulu
vaults:
  aaa-broken:
    url: ""
    token: token-broken
  zulu:
    url: `+good.url+`
    token: token-zulu
`)

	c := newRenewCLI(t)
	var err error
	problems := captureStderr(t, func() {
		_ = captureStdout(t, func() { err = c.cmdRenew("renew", "all") })
	})

	if err == nil {
		t.Fatal("renew all over a broken target = nil, want an error")
	}
	if !strings.Contains(problems, "aaa-broken") {
		t.Errorf("the target that failed should be named\n---\n%s", problems)
	}
	if got := good.served(); len(got) != 1 {
		t.Errorf("the target after the broken one served %d renewals, want 1", len(got))
	}
}

// A token the Vault will not renew is counted, and the targets after it are
// still renewed.
func TestRenewAllCountsTheTokensItCouldNotRenew(t *testing.T) {
	isolateHome(t)
	alpha, beta := newRenewFake(t), newRenewFake(t)
	alpha.reject = true
	writeSaferc(t, `version: 1
current: alpha
vaults:
  alpha:
    url: `+alpha.url+`
    token: token-alpha
  beta:
    url: `+beta.url+`
    token: token-beta
`)

	c := newRenewCLI(t)
	var err error
	_ = captureStderr(t, func() {
		_ = captureStdout(t, func() { err = c.cmdRenew("renew", "all") })
	})

	if err == nil {
		t.Fatal("renew all over a rejected token = nil, want an error")
	}
	if !strings.Contains(err.Error(), "1") {
		t.Errorf("error %q should count the one token it could not renew", err)
	}
	if got := beta.served(); len(got) != 1 {
		t.Errorf("beta served %d renewals, want 1", len(got))
	}
}

// Targets were renewed in whatever order the config map happened to hand
// them over, so two runs over the same config reported them differently and
// neither could be read against the last.
func TestRenewAllVisitsTargetsInAStableOrder(t *testing.T) {
	isolateHome(t)
	aliases := []string{"delta", "alpha", "echo", "charlie", "bravo"}

	saferc := "version: 1\ncurrent: alpha\nvaults:\n"
	for _, alias := range aliases {
		fv := newRenewFake(t)
		saferc += "  " + alias + ":\n    url: " + fv.url + "\n    token: token-" + alias + "\n"
	}
	writeSaferc(t, saferc)

	c := newRenewCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdRenew("renew", "all") })
	if err != nil {
		t.Fatalf("renew all: %v", err)
	}

	var renewed []string
	for _, line := range strings.Split(out, "\n") {
		alias, ok := strings.CutPrefix(line, "renewing token against ")
		if !ok {
			continue
		}
		renewed = append(renewed, strings.TrimSuffix(alias, "..."))
	}

	want := []string{"alpha", "bravo", "charlie", "delta", "echo"}
	if strings.Join(renewed, ",") != strings.Join(want, ",") {
		t.Errorf("renewed %v, want %v", renewed, want)
	}
}

func TestRenewAllRenewsEveryTargetThatHasAToken(t *testing.T) {
	isolateHome(t)
	alpha, beta := newRenewFake(t), newRenewFake(t)
	writeSaferc(t, `version: 1
current: alpha
vaults:
  alpha:
    url: `+alpha.url+`
    token: token-alpha
  beta:
    url: `+beta.url+`
    token: ""
`)

	c := newRenewCLI(t)
	var err error
	out := captureStdout(t, func() { err = c.cmdRenew("renew", "all") })
	if err != nil {
		t.Fatalf("renew all: %v", err)
	}

	if got := alpha.served(); len(got) != 1 || got[0].token != "token-alpha" {
		t.Errorf("alpha served %v, want one renewal of token-alpha", got)
	}
	if got := beta.served(); len(got) != 0 {
		t.Errorf("beta has no token and served %v", got)
	}
	if !strings.Contains(out, "skipping") || !strings.Contains(out, "beta") {
		t.Errorf("output should say beta was skipped\n---\n%s", out)
	}
}
