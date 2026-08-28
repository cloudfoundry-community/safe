// Black-box coverage for GenerateKeyWhileFetching (x509.go), which runs a
// certificate's key generation concurrently with the read of its signing CA.
// internal/cli cannot reach the unexported generateKeyFn seam, so the
// overlap and abandonment contracts are proven here, via the
// SetGenerateKeyForTest hook in export_test.go; internal/cli's own tests
// stick to request budgets and output ordering.
package vault_test

import (
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// TestGenerateKeyOverlapsTheCAFetch parks the keygen stub and the CA's data
// GET at the same time -- the stub on its own release channel, the GET on a
// request gate that needs an arrival count it never reaches -- and only
// releases either after observing both in flight. Reaching the release at
// all is the proof that the key was being generated while the CA read was
// on the wire.
func TestGenerateKeyOverlapsTheCAFetch(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")

	ca := caNamed(t, "authority")
	s, err := ca.Secret(false)
	if err != nil {
		t.Fatalf("Secret: %v", err)
	}
	data := map[string]string{}
	for _, k := range s.Keys() {
		data[k] = s.Get(k)
	}
	fv.setV2("kv2/ca", data)

	//Warm the mount cache, so the read under the gate below is the data GET
	// alone and never parks while holding vaultkv's mount-resolution lock.
	if _, err := v.Read("kv2/ca"); err != nil {
		t.Fatalf("warming read: %v", err)
	}

	preKey, err := vault.GenerateKey(vault.KeySpec{Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	stubArrived := make(chan struct{})
	stubRelease := make(chan struct{})
	// stubTimedOut is closed by the stub goroutine instead of calling
	// t.Error directly: the enclosing test may already have returned via
	// one of its own t.Fatal calls by the time a 10 s timeout this deep
	// fires, and logging from a goroutine after the test completes
	// panics. The test body checks it after done resolves instead.
	stubTimedOut := make(chan struct{})
	restore := vault.SetGenerateKeyForTest(func(spec vault.KeySpec) (crypto.Signer, error) {
		close(stubArrived)
		select {
		case <-stubRelease:
		case <-time.After(10 * time.Second):
			close(stubTimedOut)
		}
		return preKey, nil
	})
	t.Cleanup(restore)

	fv.resetRequestLog()
	//Two arrivals are demanded and only one request will ever come, so the
	// CA GET parks until the gate is replaced below.
	fv.holdRequests(2, `GET /v1/kv2/data/ca`)

	type outcome struct {
		key crypto.Signer
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		key, kerr := vault.GenerateKeyWhileFetching(vault.KeySpec{Algorithm: "ed25519"}, func() error {
			_, rerr := v.Read("kv2/ca")
			return rerr
		})
		done <- outcome{key, kerr}
	}()

	select {
	case <-stubArrived:
	case <-time.After(10 * time.Second):
		t.Fatal("key generation never started")
	}
	deadline := time.Now().Add(10 * time.Second)
	for fv.requestCount(`GET /v1/kv2/data/ca`) < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the CA GET never arrived while key generation was parked")
		}
		time.Sleep(time.Millisecond)
	}

	//Both are in flight right now. Let them finish.
	close(stubRelease)
	fv.holdRequests(0, `never-matches`)

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("GenerateKeyWhileFetching: %v", res.err)
		}
		eq, ok := res.key.(interface{ Equal(crypto.PrivateKey) bool })
		if !ok || !eq.Equal(preKey) {
			t.Error("the stub's key did not come back from the join")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("GenerateKeyWhileFetching never returned")
	}

	select {
	case <-stubTimedOut:
		t.Error("keygen stub never released; the CA GET was never observed alongside it")
	default:
	}
}

// TestGenerateKeyFetchFailureCollectsTheKeygen proves a fetch error comes
// back without waiting out the key generation, and that the abandoned
// generation goroutine still runs to completion -- its result lands in a
// buffered channel nobody reads -- rather than leaking parked on a send.
func TestGenerateKeyFetchFailureCollectsTheKeygen(t *testing.T) {
	release := make(chan struct{})
	stubDone := make(chan struct{})
	restore := vault.SetGenerateKeyForTest(func(spec vault.KeySpec) (crypto.Signer, error) {
		defer close(stubDone)
		<-release
		return nil, errors.New("keygen finished after abandonment")
	})
	t.Cleanup(restore)

	fetchErr := errors.New("the CA read failed")
	key, err := vault.GenerateKeyWhileFetching(vault.KeySpec{Algorithm: "ed25519"}, func() error {
		return fetchErr
	})
	if !errors.Is(err, fetchErr) {
		t.Fatalf("err = %v, want the fetch failure", err)
	}
	if key != nil {
		t.Fatalf("key = %v, want none alongside a fetch failure", key)
	}

	//The stub is still parked on its release channel, so the fetch failure
	// above cannot have waited for the generation to finish.
	select {
	case <-stubDone:
		t.Fatal("keygen finished before the fetch failure returned; it was waited on, not abandoned")
	default:
	}

	close(release)
	select {
	case <-stubDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the abandoned keygen goroutine never finished")
	}
}

// TestGenerateKeySeamRestoresAfterCleanup verifies SetGenerateKeyForTest's
// restore func puts the real generator back, so a stub installed by one
// test cannot leak into another that runs after it.
func TestGenerateKeySeamRestoresAfterCleanup(t *testing.T) {
	restore := vault.SetGenerateKeyForTest(func(spec vault.KeySpec) (crypto.Signer, error) {
		return nil, errors.New("stubbed")
	})

	if _, err := vault.GenerateKey(vault.KeySpec{Algorithm: "ed25519"}); err == nil || !strings.Contains(err.Error(), "stubbed") {
		t.Fatalf("GenerateKey with the stub installed: err = %v, want the stub's", err)
	}

	restore()

	key, err := vault.GenerateKey(vault.KeySpec{Algorithm: "ed25519"})
	if err != nil {
		t.Fatalf("GenerateKey after restore: %v", err)
	}
	if key == nil {
		t.Fatal("GenerateKey after restore returned no key")
	}
}
