package vault

import "context"

// SetDhparamGenForTest overrides the package's DH parameter generator seam
// for tests in vault_test, the external test package, which cannot reach
// the unexported dhparamGen var directly. Call the returned restore func
// (typically via t.Cleanup) to put the real generator back.
func SetDhparamGenForTest(fn func(ctx context.Context, bits int) (string, error)) (restore func()) {
	orig := dhparamGen
	dhparamGen = fn
	return func() { dhparamGen = orig }
}
