package rc

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/yamlenc"
)

// The lost-update defect, at full contention: every writer's delta must land,
// no matter how many read-mutate-write cycles overlap.
func TestConcurrentUpdatersLoseNothing(t *testing.T) {
	setHome(t)

	const writers = 8
	const rounds = 5
	var wg sync.WaitGroup
	var failures atomic.Int64

	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range rounds {
				name := fmt.Sprintf("w%02d-r%02d", w, r)
				if err := Update(func(c *Config) error {
					return c.SetTarget(name, Vault{URL: "http://" + name})
				}); err != nil {
					t.Errorf("Update(%s): %s", name, err)
					failures.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	if failures.Load() > 0 {
		return
	}
	c, err := Read()
	if err != nil {
		t.Fatalf("Read: %s", err)
	}
	if len(c.Vaults) != writers*rounds {
		t.Errorf("%d targets survived, want %d", len(c.Vaults), writers*rounds)
	}
	for w := range writers {
		for r := range rounds {
			name := fmt.Sprintf("w%02d-r%02d", w, r)
			if _, ok := c.Vaults[name]; !ok {
				t.Errorf("target %q lost", name)
			}
		}
	}
}

// The torn-file defect: the production artifact was a complete YAML document
// with the tail of a longer one appended -- a truncating rewrite caught
// mid-flight. Readers hammering the file during a write storm must only ever
// see complete, parseable documents, and never fewer targets than they saw
// before (this file only grows during the storm).
func TestReadersNeverSeeATornFile(t *testing.T) {
	setHome(t)

	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	for range 4 {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			most := 0
			for {
				select {
				case <-stop:
					return
				default:
				}

				b, err := os.ReadFile(saferc())
				if err != nil {
					if os.IsNotExist(err) {
						continue
					}
					t.Errorf("reading .saferc: %s", err)
					return
				}
				var c Config
				if err := yamlenc.Unmarshal(b, &c); err != nil {
					t.Errorf("torn .saferc observed: %s\n%s", err, b)
					return
				}
				if len(c.Vaults) < most {
					t.Errorf("targets went backwards: saw %d after %d", len(c.Vaults), most)
					return
				}
				most = len(c.Vaults)
			}
		}()
	}

	const writers = 6
	const rounds = 8
	var writerWG sync.WaitGroup
	for w := range writers {
		writerWG.Add(1)
		go func() {
			defer writerWG.Done()
			for r := range rounds {
				name := fmt.Sprintf("storm-w%02d-r%02d", w, r)
				if err := Update(func(c *Config) error {
					return c.SetTarget(name, Vault{URL: "http://" + name})
				}); err != nil {
					t.Errorf("Update(%s): %s", name, err)
				}
			}
		}()
	}
	writerWG.Wait()
	close(stop)
	readerWG.Wait()

	c, err := Read()
	if err != nil {
		t.Fatalf("Read after storm: %s", err)
	}
	if len(c.Vaults) != writers*rounds {
		t.Errorf("%d targets survived the storm, want %d", len(c.Vaults), writers*rounds)
	}
}
