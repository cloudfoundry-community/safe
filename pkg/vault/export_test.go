package vault

import (
	"context"
	"crypto"
	"net/http"
	"time"
)

// TunedTransportForTest digs the tuned *http.Transport out from under v's
// retrying round tripper for tests in vault_test, the external test
// package, which cannot reach the unexported retryTransport type. ok is
// false when the client's transport is not the expected wrapping.
func TunedTransportForTest(v *Vault) (tr *http.Transport, ok bool) {
	rt, ok := v.client.Client.Client.Transport.(*retryTransport)
	if !ok {
		return nil, false
	}
	tr, ok = rt.next.(*http.Transport)
	return tr, ok
}

// SetRetrySleepForTest replaces v's retry backoff sleep so tests can
// record requested waits instead of serving them. It reports false when
// v's transport is not the retrying round tripper.
func SetRetrySleepForTest(v *Vault, fn func(ctx context.Context, d time.Duration) error) bool {
	rt, ok := v.client.Client.Client.Transport.(*retryTransport)
	if !ok {
		return false
	}
	rt.sleep = fn
	return true
}

// SetDhparamGenForTest overrides the package's DH parameter generator seam
// for tests in vault_test, the external test package, which cannot reach
// the unexported dhparamGen var directly. Call the returned restore func
// (typically via t.Cleanup) to put the real generator back.
func SetDhparamGenForTest(fn func(ctx context.Context, bits int) (string, error)) (restore func()) {
	orig := dhparamGen
	dhparamGen = fn
	return func() { dhparamGen = orig }
}

// SetGenerateKeyForTest overrides the package's key generator seam for
// tests in vault_test, the external test package, which cannot reach the
// unexported generateKeyFn var directly. Call the returned restore func
// (typically via t.Cleanup) to put the real generator back.
func SetGenerateKeyForTest(fn func(spec KeySpec) (crypto.Signer, error)) (restore func()) {
	orig := generateKeyFn
	generateKeyFn = fn
	return func() { generateKeyFn = orig }
}
