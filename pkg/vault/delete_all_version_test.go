package vault_test

// Delete refuses --all together with a version named on the path. The refusal
// belongs here rather than in the command, because deleteEntireSecret has no
// way to honour both and every caller of Delete would otherwise have to know
// that.

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func TestDeleteRefusesAllWithANamedVersion(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/app", map[string]string{"password": "one"})

	for _, opts := range []vault.DeleteOpts{
		{All: true},
		{All: true, Destroy: true},
	} {
		err := v.Delete("secret/app^2", opts)
		if err == nil {
			t.Fatalf("Delete(%+v) on a path naming a version returned nil, want a refusal", opts)
		}
		//Said so that it is clear which of the two the caller has to give up;
		// a plain "no version 2 exists" would be true of the v1 mount here
		// and would say nothing about the pair.
		for _, want := range []string{"secret/app", "--all", "2"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should mention %q", err, want)
			}
		}
		//Nothing is read or written before the refusal, so the secret is
		// still whole.
		if _, err := v.Read("secret/app"); err != nil {
			t.Fatalf("reading the secret afterwards: %v", err)
		}
	}
}

// An escaped caret is part of the name rather than a version, and a secret
// named that way deletes like any other.
func TestDeleteAllAcceptsAnEscapedCaret(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/od^d", map[string]string{"password": "one"})

	if err := v.Delete(`secret/od\^d`, vault.DeleteOpts{All: true}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := v.Read(`secret/od\^d`); !vault.IsNotFound(err) {
		t.Fatalf("reading the secret afterwards: %v, want not found", err)
	}
}
