package cli

// `safe local --keep-current` registers the temporary target without
// selecting it, so the operator's current target is never moved, not even
// for the length of the run.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/rc"
)

// watchSaferc polls ~/.saferc until stop is closed and returns every
// snapshot that held the named target.
func watchSaferc(name string, stop <-chan struct{}) (snapshots func() []rc.Config) {
	var (
		mu   sync.Mutex
		seen []rc.Config
		wg   sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if cfg, err := rc.Read(); err == nil && cfg.Vaults[name] != nil {
				mu.Lock()
				seen = append(seen, cfg)
				mu.Unlock()
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	return func() []rc.Config {
		wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		return seen
	}
}

func TestCmdLocal_KeepCurrentLeavesCurrentAloneWhileRunning(t *testing.T) {
	// No t.Parallel -- captureStderr mutates os.Stderr.
	for _, tc := range []struct {
		name  string
		saved string
		want  string
	}{
		{"an existing current", `version: 1
current: alpha
vaults:
  alpha:
    url: http://127.0.0.1:1
    token: token-alpha
    no_strongbox: true
`, "alpha"},
		{"no current", "version: 1\ncurrent: \"\"\nvaults: {}\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateHome(t)
			writeSaferc(t, tc.saved)
			installFakeLocalVault(t)
			c := localCLI(t)
			c.opt.Local.Memory = true
			c.opt.Local.KeepCurrent = true
			c.opt.Local.Port = freePort(t)
			c.opt.Local.As = "local-keep-test"

			stop := make(chan struct{})
			snapshots := watchSaferc("local-keep-test", stop)

			var err error
			var stderr string
			captureStdout(t, func() {
				stderr = captureStderr(t, func() {
					err = c.cmdLocal("local")
				})
			})
			close(stop)
			if err != nil {
				t.Fatalf("cmdLocal: %v\nstderr:\n%s", err, stderr)
			}

			var sawToken bool
			seen := snapshots()
			if len(seen) == 0 {
				t.Fatal("never saw the local target registered while running")
			}
			for _, cfg := range seen {
				if cfg.Current != tc.want {
					t.Errorf("current = %q while running, want %q", cfg.Current, tc.want)
				}
				if cfg.Vaults["local-keep-test"].Token == "local-root-token" {
					sawToken = true
				}
			}
			if !sawToken {
				t.Error("never saw the root token stored on the local target")
			}

			after := readConfig(t)
			if after.Vaults["local-keep-test"] != nil {
				t.Error("the local target was not removed on teardown")
			}
			if after.Current != tc.want {
				t.Errorf("current = %q after teardown, want %q", after.Current, tc.want)
			}

			if strings.Contains(stderr, "Now targeting") {
				t.Errorf("claimed the local target is current:\n%s", stderr)
			}
			if !strings.Contains(stderr, "local-keep-test") || !strings.Contains(stderr, "not selected") {
				t.Errorf("expected the registered-but-unselected notice:\n%s", stderr)
			}
		})
	}
}
