// Black-box coverage for the dhparamGen seam (dhparam.go), which cmdDhparam
// in internal/cli relies on to generate several secrets' Diffie-Hellman
// parameters concurrently without every case paying for a real openssl
// invocation. internal/cli cannot reach the unexported dhparamGen var or
// genDHParam directly, so the seam and its concurrency contract are proven
// here instead, via the SetDhparamGenForTest hook in export_test.go.
package vault_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// TestDhparamGenSeamRunsConcurrently stubs dhparamGen with a function that
// parks every caller on a barrier until n have arrived, then drives n
// concurrent Secret.DHParam calls -- one per simulated secret path -- and
// asserts they actually overlapped (the barrier tripped) and that each
// secret ended up with its own distinct value, i.e. one generation per
// secret rather than one shared result racing the others.
func TestDhparamGenSeamRunsConcurrently(t *testing.T) {
	const n = 4

	var mu sync.Mutex
	arrived := 0
	release := make(chan struct{})
	var tripped bool

	restore := vault.SetDhparamGenForTest(func(_ context.Context, bits int) (string, error) {
		mu.Lock()
		arrived++
		if arrived >= n && !tripped {
			tripped = true
			close(release)
		}
		mu.Unlock()

		select {
		case <-release:
		case <-time.After(5 * time.Second):
			t.Error("dhparamGen stub never observed n concurrent arrivals")
		}
		return fmt.Sprintf("dhparam-%d", bits), nil
	})
	t.Cleanup(restore)

	secrets := make([]*vault.Secret, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		secrets[i] = vault.NewSecret()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := secrets[i].DHParam(1024+i, false); err != nil {
				t.Errorf("DHParam: %v", err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	gotArrived := arrived
	mu.Unlock()
	if gotArrived != n {
		t.Fatalf("arrived = %d, want %d (not all calls reached the stub)", gotArrived, n)
	}

	seen := map[string]bool{}
	for i, s := range secrets {
		want := fmt.Sprintf("dhparam-%d", 1024+i)
		got := s.Get("dhparam-pem")
		if got != want {
			t.Errorf("secret %d dhparam-pem = %q, want %q", i, got, want)
		}
		seen[got] = true
	}
	if len(seen) != n {
		t.Errorf("only %d distinct values written, want %d (one generation per secret)", len(seen), n)
	}
}

// TestDhparamGenSeamRestoresAfterCleanup verifies SetDhparamGenForTest's
// restore func actually puts the real generator back, so a stub installed
// by one test cannot leak into another that runs after it.
func TestDhparamGenSeamRestoresAfterCleanup(t *testing.T) {
	restore := vault.SetDhparamGenForTest(func(_ context.Context, bits int) (string, error) {
		return "stubbed", nil
	})

	s := vault.NewSecret()
	if err := s.DHParam(1024, false); err != nil {
		t.Fatalf("DHParam: %v", err)
	}
	if got := s.Get("dhparam-pem"); got != "stubbed" {
		t.Fatalf("dhparam-pem = %q, want %q", got, "stubbed")
	}

	restore()

	s2 := vault.NewSecret()
	if err := s2.DHParam(1024, false); err != nil {
		t.Fatalf("DHParam after restore: %v", err)
	}
	if got := s2.Get("dhparam-pem"); got == "stubbed" {
		t.Fatal("dhparam-pem still reads the stub after restore")
	}
}
