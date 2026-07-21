package cli

import (
	"errors"
	"testing"
)

func TestResolveRootTokenPrefersInitToken(t *testing.T) {
	called := false
	token, err := resolveRootToken("s.init-token", func() (string, error) {
		called = true
		return "s.generated", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if token != "s.init-token" {
		t.Errorf("expected init token to win, got %q", token)
	}
	if called {
		t.Error("generate-root must not be called when init supplied a token")
	}
}

func TestResolveRootTokenGeneratesWhenInitTokenAbsent(t *testing.T) {
	token, err := resolveRootToken("", func() (string, error) {
		return "s.generated", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if token != "s.generated" {
		t.Errorf("expected generated token, got %q", token)
	}
}

func TestResolveRootTokenPropagatesGenerateError(t *testing.T) {
	genErr := errors.New("unsupported operation")
	_, err := resolveRootToken("", func() (string, error) {
		return "", genErr
	})
	if !errors.Is(err, genErr) {
		t.Errorf("expected generate error to propagate, got %v", err)
	}
}
