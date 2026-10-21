package vault_test

// Update is not the only read-modify-write. Removing one key, copying or
// moving one key, and copying a whole secret all read what is there and
// write it back, and each must send the values it did not change with the
// JSON types they were read with. See update_typed_values_test.go for the
// shapes and the helpers these share.

import (
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func TestDeleteKeyOnAuthRoleSendsOtherFieldsTyped(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "auth/approle/role/web", endpointRole, approleRead)

	if err := v.Delete("auth/approle/role/web:token_type", vault.DeleteOpts{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	body := onlyWrite(t, fv, "auth/approle/role/web")
	assertSentJSON(t, body, "alias_metadata", `{}`)
	assertSentJSON(t, body, "token_policies", `["a"]`)
	assertSentJSON(t, body, "token_ttl", `3600`)
	assertSentJSON(t, body, "bind_secret_id", `true`)
	if _, sent := body["token_type"]; sent {
		t.Errorf("write sent the removed key token_type = %s", body["token_type"])
	}
}

func TestDeleteKeyOnKVv1KeepsOtherValuesTyped(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "secret/typed", endpointKV1, typedKVSecret)

	if err := v.Delete("secret/typed:password", vault.DeleteOpts{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	body := onlyWrite(t, fv, "secret/typed")
	assertSentJSON(t, body, "config", `{"b":[1,2],"a":"x"}`)
	assertSentJSON(t, body, "count", `12345678901234567890`)
	assertSentJSON(t, body, "enabled", `false`)
	if _, sent := body["password"]; sent {
		t.Errorf("write sent the removed key password = %s", body["password"])
	}
}

// Naming the version reads that version rather than the latest one, and
// what it read is what goes forward.
func TestDeleteKeyAtANamedVersionOnKVv2KeepsOtherValuesTyped(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv")
	fv.typedEndpoint(t, "kv/data/typed", endpointKV2, typedKVSecret)

	if err := v.Delete("kv/typed:password^1", vault.DeleteOpts{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	body := onlyWrite(t, fv, "kv/data/typed")
	assertSentJSON(t, body, "config", `{"b":[1,2],"a":"x"}`)
	assertSentJSON(t, body, "count", `12345678901234567890`)
	assertSentJSON(t, body, "enabled", `false`)
	if _, sent := body["password"]; sent {
		t.Errorf("write sent the removed key password = %s", body["password"])
	}
}

// typedSource is a secret one key of which gets copied or moved.
const typedSource = `{"conf": {"x": [1]}, "n": 7}`

// The destination keeps its own untouched values typed, and the copied
// value lands with the type it had at the source.
func TestCopyKeyKeepsBothValuesTyped(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "secret/src", endpointKV1, typedSource)
	fv.typedEndpoint(t, "secret/dst", endpointKV1, typedKVSecret)

	if err := v.Copy("secret/src:conf", "secret/dst:copied", vault.MoveCopyOpts{}); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	body := onlyWrite(t, fv, "secret/dst")
	assertSentJSON(t, body, "copied", `{"x":[1]}`)
	assertSentJSON(t, body, "config", `{"b":[1,2],"a":"x"}`)
	assertSentJSON(t, body, "count", `12345678901234567890`)
	assertSentJSON(t, body, "enabled", `false`)
	assertSentJSON(t, body, "password", `"old"`)
	if writes := fv.endpointWrites("secret/src"); len(writes) != 0 {
		t.Errorf("copy wrote to its source: %v", writes)
	}
}

// A copied string overwrites a typed value at the destination, and goes
// out as a string.
func TestCopyKeyOverATypedValueSendsTheString(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "secret/src", endpointKV1, `{"word": "plain"}`)
	fv.typedEndpoint(t, "secret/dst", endpointKV1, typedKVSecret)

	if err := v.Copy("secret/src:word", "secret/dst:config", vault.MoveCopyOpts{}); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	body := onlyWrite(t, fv, "secret/dst")
	assertSentJSON(t, body, "config", `"plain"`)
	assertSentJSON(t, body, "count", `12345678901234567890`)
}

// A move is a copy followed by removing the key from its source, so both
// writes must keep what they did not touch typed.
func TestMoveKeyKeepsBothSidesTyped(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "secret/src", endpointKV1, typedSource)
	fv.typedEndpoint(t, "secret/dst", endpointKV1, typedKVSecret)

	if err := v.Move("secret/src:conf", "secret/dst:moved", vault.MoveCopyOpts{}); err != nil {
		t.Fatalf("Move: %v", err)
	}

	dst := onlyWrite(t, fv, "secret/dst")
	assertSentJSON(t, dst, "moved", `{"x":[1]}`)
	assertSentJSON(t, dst, "config", `{"b":[1,2],"a":"x"}`)
	assertSentJSON(t, dst, "count", `12345678901234567890`)

	src := onlyWrite(t, fv, "secret/src")
	assertSentJSON(t, src, "n", `7`)
	if _, sent := src["conf"]; sent {
		t.Errorf("source write still sent the moved key conf = %s", src["conf"])
	}
}

// Copying a whole secret goes through the tree walk rather than Read, and
// writes each version it collected.
func TestCopySecretOnKVv1KeepsValuesTyped(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "secret/src", endpointKV1, typedKVSecret)
	fv.typedEndpoint(t, "secret/dst", endpointKV1, `{}`)

	if err := v.Copy("secret/src", "secret/dst", vault.MoveCopyOpts{}); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	body := onlyWrite(t, fv, "secret/dst")
	assertSentJSON(t, body, "config", `{"b":[1,2],"a":"x"}`)
	assertSentJSON(t, body, "count", `12345678901234567890`)
	assertSentJSON(t, body, "enabled", `false`)
	assertSentJSON(t, body, "password", `"old"`)
}

// On a v2 mount the walk reads the latest version together with its
// metadata, in one request of its own.
func TestCopySecretOnKVv2KeepsValuesTyped(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv")
	fv.typedEndpoint(t, "kv/data/src", endpointKV2, typedKVSecret)
	fv.typedEndpoint(t, "kv/data/dst", endpointKV2, `{}`)

	if err := v.Copy("kv/src", "kv/dst", vault.MoveCopyOpts{}); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	body := onlyWrite(t, fv, "kv/data/dst")
	assertSentJSON(t, body, "config", `{"b":[1,2],"a":"x"}`)
	assertSentJSON(t, body, "count", `12345678901234567890`)
	assertSentJSON(t, body, "enabled", `false`)
	assertSentJSON(t, body, "password", `"old"`)
}

// What the tree walk reports for a typed value is the string get prints.
func TestTreeWalkShowsTypedValuesAsTheirJSONStrings(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv")
	fv.typedEndpoint(t, "kv/data/src", endpointKV2, typedKVSecret)

	secrets, err := v.ConstructSecrets("kv/src", vault.TreeOpts{FetchKeys: true, GetOnly: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}
	if len(secrets) != 1 || len(secrets[0].Versions) != 1 {
		t.Fatalf("walk found %d secrets, want one with one version", len(secrets))
	}
	data := secrets[0].Versions[0].Data
	for k, want := range map[string]string{
		"config":   `{"a":"x","b":[1,2]}`,
		"count":    `12345678901234567000`,
		"enabled":  `false`,
		"password": `old`,
	} {
		if got := data.Get(k); got != want {
			t.Errorf("walk shows %s = %q, want %q", k, got, want)
		}
	}
}
