package vault

import "crypto"

// SetDhparamGenForTest overrides the package's DH parameter generator seam
// for tests in vault_test, the external test package, which cannot reach
// the unexported dhparamGen var directly. Call the returned restore func
// (typically via t.Cleanup) to put the real generator back.
func SetDhparamGenForTest(fn func(bits int) (string, error)) (restore func()) {
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
