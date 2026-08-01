//go:build unix

package cli

// The ticket's evidence table, as tests: four concurrent `safe local`
// processes sharing one $HOME used to leave one or two of four targets in
// ~/.saferc, or a corrupted file, and losers of the port race initialized
// each other's vaults ("Vault is already initialized"). All four must now
// come up, register, keep to their own servers, and clean up after
// themselves.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/rc"
)

var fleetNames = []string{"alpha", "beta", "gamma", "delta"}

// fleetMember is one fleet process plus the means to start it over, for the
// single failure a member may honestly retry (see awaitFleetReady), and when
// this attempt was launched, to tell that failure apart from a readiness
// regression producing the same message.
type fleetMember struct {
	*localProc
	relaunch  func() *localProc
	startedAt time.Time
}

// startFleet launches one `safe local --memory` per name against a shared
// home, all at once.
func startFleet(t *testing.T, home, engine string, extraFor func(name string) []string) []*fleetMember {
	t.Helper()
	fleet := make([]*fleetMember, 0, len(fleetNames))
	for _, name := range fleetNames {
		var extra []string
		if extraFor != nil {
			extra = extraFor(name)
		}
		launch := func() *localProc {
			return startSafeLocal(t, home, engine, name, extra...)
		}
		fleet = append(fleet, &fleetMember{localProc: launch(), relaunch: launch, startedAt: time.Now()})
	}
	return fleet
}

// awaitFleetReady waits for every process to print its "Now targeting" line.
// A member that dies fails the test right away, in the process's own words,
// instead of sitting out the deadline -- with one exception: an engine that
// lost to machine load is started over, a bounded number of times.
//
// That one exception used to be granted on message text alone: cmdLocal's
// own startup-timeout message ("...begin listening...") is what a genuine
// slow start under load produces, but it is also exactly what a readiness
// regression produces -- a shorter effective timeout, a changed banner, a
// probe pointed at the wrong address. All of those would go green here on
// message text alone. A member that ran the whole maxStartupWait budget
// before dying honestly waited it out; one that died in a fraction of that
// did not, and text-matching the same message would have retried it into
// passing regardless of why. Only the former is retried; the latter fails
// immediately, elapsed time and all, so a fast failure with this exact
// wording still reads as the finding it is.
func awaitFleetReady(t *testing.T, fleet []*fleetMember) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for _, m := range fleet {
		restarts := 0
		for {
			if strings.Contains(m.output.String(), "Now targeting") {
				break
			}
			if m.exited() {
				out := m.output.String()
				elapsed := time.Since(m.startedAt)
				if strings.Contains(out, "begin listening") && elapsed >= maxStartupWait && restarts < 2 {
					restarts++
					m.localProc = m.relaunch()
					m.startedAt = time.Now()
					continue
				}
				t.Fatalf("%s exited after %s before becoming ready:\n%s", m.name, elapsed, out)
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not become ready:\n%s", m.name, m.output.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// stopFleet interrupts every process group and waits for the exits.
func stopFleet(t *testing.T, fleet []*fleetMember) {
	t.Helper()
	for _, m := range fleet {
		_ = syscall.Kill(-m.cmd.Process.Pid, syscall.SIGINT)
	}
	for _, m := range fleet {
		if _, ok := m.waitExit(20 * time.Second); !ok {
			t.Errorf("%s did not exit after SIGINT:\n%s", m.name, m.output.String())
		}
	}
}

// checkFleetRegistered requires all four targets in one valid config, each
// on its own port, and returns the config.
func checkFleetRegistered(t *testing.T, home string) rc.Config {
	t.Helper()
	cfg, ok := readSafercAt(t, home)
	if !ok {
		t.Fatalf("no ~/.saferc after the fleet came up")
	}
	ports := map[string]string{}
	for _, name := range fleetNames {
		v, found := cfg.Vaults[name]
		if !found {
			t.Errorf("target %q lost to a concurrent safe local", name)
			continue
		}
		if v.Token == "" {
			t.Errorf("target %q has no stored token", name)
		}
		if holder, taken := ports[v.URL]; taken {
			t.Errorf("targets %q and %q share %s", holder, name, v.URL)
		}
		ports[v.URL] = name
	}
	return cfg
}

// vaultSecretRoundTrip writes {"owner": owner} at secret/probe on the vault
// behind url and reads it back, through the KV v2 API cmdLocal mounts.
func vaultSecretRoundTrip(t *testing.T, url, token, owner string) string {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}

	body, _ := json.Marshal(map[string]any{"data": map[string]string{"owner": owner}})
	req, _ := http.NewRequest(http.MethodPost, url+"/v1/secret/data/probe", bytes.NewReader(body))
	req.Header.Set("X-Vault-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("writing probe secret to %s: %v", url, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("writing probe secret to %s: HTTP %d", url, resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, url+"/v1/secret/data/probe", nil)
	req.Header.Set("X-Vault-Token", token)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("reading probe secret from %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding probe secret from %s: %v", url, err)
	}
	return out.Data.Data["owner"]
}

// Four concurrent auto-scan starts under one $HOME: all four targets
// registered on distinct ports, no process touched another's vault, and the
// teardowns remove exactly their own entries.
func TestConcurrentLocalAutoScan(t *testing.T) {
	engine := localEngine(t)
	home := t.TempDir()

	fleet := startFleet(t, home, engine, nil)
	awaitFleetReady(t, fleet)
	cfg := checkFleetRegistered(t, home)

	// The signature of cross-connection is a loser initializing the winner's
	// vault: "Vault is already initialized".
	for _, p := range fleet {
		if strings.Contains(p.output.String(), "already initialized") {
			t.Errorf("%s initialized someone else's vault:\n%s", p.name, p.output.String())
		}
	}

	// Each process's target must front its own vault: a unique marker
	// written through one target must read back identically, and the four
	// must not collapse onto fewer servers.
	if !t.Failed() {
		for _, name := range fleetNames {
			v := cfg.Vaults[name]
			if got := vaultSecretRoundTrip(t, v.URL, v.Token, name); got != name {
				t.Errorf("target %q's vault answered as %q", name, got)
			}
		}
	}

	stopFleet(t, fleet)

	// Every teardown removed its own target and only its own.
	if cfg, ok := readSafercAt(t, home); ok {
		for _, name := range fleetNames {
			if _, found := cfg.Vaults[name]; found {
				t.Errorf("target %q still present after teardown", name)
			}
		}
	}
}

// Four concurrent starts with explicit, distinct ports: same guarantees,
// with each target on exactly the port it was given.
func TestConcurrentLocalExplicitPorts(t *testing.T) {
	engine := localEngine(t)
	home := t.TempDir()

	ports := map[string]int{}
	next := localPortScanStart + 100
	for _, name := range fleetNames {
		port, err := findCandidatePort(next)
		if err != nil {
			t.Fatalf("choosing a port for %s: %v", name, err)
		}
		ports[name] = port
		next = port + 20
	}

	fleet := startFleet(t, home, engine, func(name string) []string {
		return []string{"--port", fmt.Sprintf("%d", ports[name])}
	})
	awaitFleetReady(t, fleet)
	cfg := checkFleetRegistered(t, home)

	for _, name := range fleetNames {
		if v, found := cfg.Vaults[name]; found {
			want := localVaultURL(fmt.Sprintf("127.0.0.1:%d", ports[name]))
			if v.URL != want {
				t.Errorf("target %q at %s, want %s", name, v.URL, want)
			}
		}
	}

	stopFleet(t, fleet)
}

// A home directory that cannot be written must fail `safe target` with an
// error, not report success with the old file still in place.
func TestTargetAddFailsWhenHomeUnwritable(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	isolateHome(t)
	home := os.Getenv("HOME")
	if err := os.Chmod(home, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0700) })

	err := newTestCLI(t).cmdTarget("target", "https://x.example.com", "x")
	if err == nil {
		t.Fatalf("cmdTarget reported success with an unwritable home")
	}
}
