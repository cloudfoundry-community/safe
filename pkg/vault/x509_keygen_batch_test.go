// GenerateKeysWhileFetching is the batch shape of GenerateKeyWhileFetching:
// n independent key draws race one fetch. As with the single form, the
// seam these tests stub is unreachable from internal/cli, so the contracts
// — every certificate gets its own full-quality draw, and a fetch failure
// comes back without waiting the draws out — are proven here.
package vault_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// Every certificate in a batch gets its own key: n draws, none shared,
// none discarded.
func TestGenerateKeysDrawsOneIndependentKeyPerCertificate(t *testing.T) {
	var mu sync.Mutex
	draws := 0
	restore := vault.SetGenerateKeyForTest(func(spec vault.KeySpec) (crypto.Signer, error) {
		mu.Lock()
		draws++
		mu.Unlock()
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	})
	t.Cleanup(restore)

	keys, err := vault.GenerateKeysWhileFetching(vault.KeySpec{Algorithm: "ed25519"}, 4, 2, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("GenerateKeysWhileFetching: %v", err)
	}
	if len(keys) != 4 {
		t.Fatalf("got %d keys, want 4", len(keys))
	}
	if draws != 4 {
		t.Errorf("the generator ran %d times, want exactly 4: one draw per certificate", draws)
	}
	seen := map[string]bool{}
	for i, key := range keys {
		if key == nil {
			t.Fatalf("key %d is nil", i)
		}
		pub := string(key.Public().(ed25519.PublicKey))
		if seen[pub] {
			t.Errorf("key %d repeats another key in the batch", i)
		}
		seen[pub] = true
	}
}

// A fetch failure returns without waiting the batch out; the abandoned
// draws finish into a buffered result nobody reads rather than leaking a
// parked goroutine.
func TestGenerateKeysFetchFailureAbandonsTheBatch(t *testing.T) {
	release := make(chan struct{})
	stubDone := make(chan struct{}, 2)
	restore := vault.SetGenerateKeyForTest(func(spec vault.KeySpec) (crypto.Signer, error) {
		<-release
		stubDone <- struct{}{}
		return nil, errors.New("keygen finished after abandonment")
	})
	t.Cleanup(restore)

	fetchErr := errors.New("the CA read failed")
	keys, err := vault.GenerateKeysWhileFetching(vault.KeySpec{Algorithm: "ed25519"}, 2, 2, func() error {
		return fetchErr
	})
	if !errors.Is(err, fetchErr) {
		t.Fatalf("err = %v, want the fetch failure", err)
	}
	if keys != nil {
		t.Fatalf("keys = %v, want none alongside a fetch failure", keys)
	}

	//The stubs are still parked on their release channel, so the fetch
	// failure above cannot have waited for the generation to finish.
	select {
	case <-stubDone:
		t.Fatal("a draw finished before the fetch failure returned; the batch was waited on, not abandoned")
	default:
	}

	close(release)
	for i := 0; i < 2; i++ {
		select {
		case <-stubDone:
		case <-time.After(10 * time.Second):
			t.Fatal("an abandoned draw never finished")
		}
	}
}

// One failed draw fails the batch, naming the generation rather than the
// fetch.
func TestGenerateKeysSurfacesADrawFailure(t *testing.T) {
	restore := vault.SetGenerateKeyForTest(func(spec vault.KeySpec) (crypto.Signer, error) {
		return nil, errors.New("entropy ran dry")
	})
	t.Cleanup(restore)

	_, err := vault.GenerateKeysWhileFetching(vault.KeySpec{Algorithm: "ed25519"}, 3, 2, func() error {
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "key generation failed") {
		t.Fatalf("err = %v, want a key generation failure", err)
	}
}
