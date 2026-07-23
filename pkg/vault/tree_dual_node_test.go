package vault_test

import (
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// A path that is both a secret and a folder must yield the leaf secret AND
// every child when its subtree is walked.
func TestConstructSecrets_SecretAndFolderDualNode(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)

	fv.set("secret/bosh/uaa", map[string]string{"admin": "dummy"})
	fv.set("secret/bosh/uaa/clients/hm", map[string]string{"secret": "dummy"})
	fv.set("secret/bosh/uaa/clients/prometheus", map[string]string{"secret": "dummy"})

	s, err := v.ConstructSecrets("secret/bosh/uaa", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	got := map[string]bool{}
	for _, entry := range s {
		got[entry.Path] = true
	}
	for _, want := range []string{
		"secret/bosh/uaa",
		"secret/bosh/uaa/clients/hm",
		"secret/bosh/uaa/clients/prometheus",
	} {
		if !got[want] {
			t.Errorf("walk of secret/bosh/uaa missing %q (got %v)", want, s.Paths())
		}
	}
}

// Walking a folder that contains a name-prefix sibling pair (nats,
// nats_sync_password) plus a folder colliding with the shorter name must
// return all leaves.
func TestConstructSecrets_PrefixSiblingsWithFolderCollision(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)

	fv.set("secret/bosh/nats", map[string]string{"password": "dummy"})
	fv.set("secret/bosh/nats/cert", map[string]string{"ca": "dummy"})
	fv.set("secret/bosh/nats_sync_password", map[string]string{"value": "dummy"})

	s, err := v.ConstructSecrets("secret/bosh", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	got := map[string]bool{}
	for _, entry := range s {
		got[entry.Path] = true
	}
	for _, want := range []string{
		"secret/bosh/nats",
		"secret/bosh/nats/cert",
		"secret/bosh/nats_sync_password",
	} {
		if !got[want] {
			t.Errorf("walk of secret/bosh missing %q (got %v)", want, s.Paths())
		}
	}
}
