// Black-box tests for Secret.DHParamContext. The context has to reach the
// generator seam intact -- cmdDhparam's fan-out cancels it when a sibling
// path fails, and exec.CommandContext is what turns that into a killed
// openssl child -- and the no-context DHParam has to keep working by
// delegating a live background context. These tests live here rather than
// in internal/cli because the SetDhparamGenForTest seam is only reachable
// from vault_test (see internal/cli/dhparam_parallel_test.go).
package vault_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

type dhparamCtxKey struct{}

func TestDHParamContextHandsItsContextToTheGenerator(t *testing.T) {
	var got context.Context
	restore := vault.SetDhparamGenForTest(func(ctx context.Context, bits int) (string, error) {
		got = ctx
		return "stubbed", nil
	})
	t.Cleanup(restore)

	ctx := context.WithValue(context.Background(), dhparamCtxKey{}, "marked")
	s := vault.NewSecret()
	if err := s.DHParamContext(ctx, 1024, false); err != nil {
		t.Fatalf("DHParamContext: %v", err)
	}
	if got == nil || got.Value(dhparamCtxKey{}) != "marked" {
		t.Error("the generator did not receive the caller's context")
	}
}

func TestDHParamDelegatesALiveContext(t *testing.T) {
	var got context.Context
	restore := vault.SetDhparamGenForTest(func(ctx context.Context, bits int) (string, error) {
		got = ctx
		return "stubbed", nil
	})
	t.Cleanup(restore)

	s := vault.NewSecret()
	if err := s.DHParam(1024, false); err != nil {
		t.Fatalf("DHParam: %v", err)
	}
	if got == nil {
		t.Fatal("the generator received no context")
	}
	if err := got.Err(); err != nil {
		t.Errorf("the delegated context is already dead: %v", err)
	}
}

// A cancelled context stops the real generator before openssl produces
// anything, and nothing is stored.
func TestDHParamContextCancelledStopsGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := vault.NewSecret()
	err := s.DHParamContext(ctx, 1024, false)
	if err == nil {
		t.Fatal("expected an error from a cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if !s.Empty() {
		t.Errorf("secret is not empty after a cancelled DHParamContext: %v", s.Keys())
	}
}
