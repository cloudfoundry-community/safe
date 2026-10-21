package vault_test

// A read-modify-write sends back every key the read returned, not just the
// ones the caller changed. These pin that the untouched keys go back with
// the JSON types the read gave them. Vault CE 1.21.3 and later return
// alias_metadata: {} on every auth role that uses the shared token fields,
// and refuse the string "{}" for it, so a stringified write-back broke
// `safe set` on every such role.

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// approleRead is what Vault 1.21.3 answers for an AppRole role read, cut
// down to one field of each JSON type.
const approleRead = `{
	"alias_metadata": {},
	"token_policies": ["a"],
	"token_ttl": 3600,
	"bind_secret_id": true,
	"secret_id_bound_cidrs": null,
	"token_type": "default"
}`

// assertSentJSON fails unless body sent key as exactly the JSON in want,
// compared after compacting both.
func assertSentJSON(t *testing.T, body map[string]json.RawMessage, key, want string) {
	t.Helper()
	raw, ok := body[key]
	if !ok {
		t.Errorf("write did not send %s at all", key)
		return
	}
	var got, exp bytes.Buffer
	if err := json.Compact(&got, raw); err != nil {
		t.Errorf("write sent %s as invalid JSON %q: %v", key, raw, err)
		return
	}
	if err := json.Compact(&exp, []byte(want)); err != nil {
		t.Fatalf("bad want for %s: %v", key, err)
	}
	if got.String() != exp.String() {
		t.Errorf("write sent %s = %s, want %s", key, got.String(), exp.String())
	}
}

// onlyWrite returns the single write sent to path, failing if there was
// not exactly one.
func onlyWrite(t *testing.T, fv *fakeVault, path string) map[string]json.RawMessage {
	t.Helper()
	writes := fv.endpointWrites(path)
	if len(writes) != 1 {
		t.Fatalf("%d writes to %s, want 1", len(writes), path)
	}
	return writes[0]
}

func setKey(key, value string) func(*vault.Secret, bool) (*vault.Secret, bool, error) {
	return func(s *vault.Secret, _ bool) (*vault.Secret, bool, error) {
		return nil, true, s.Set(key, value, false)
	}
}

func TestUpdateOnAuthRoleSendsUntouchedFieldsTyped(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "auth/approle/role/web", endpointRole, approleRead)

	if _, err := v.Update("auth/approle/role/web", setKey("token_type", "service")); err != nil {
		t.Fatalf("Update: %v", err)
	}

	body := onlyWrite(t, fv, "auth/approle/role/web")
	assertSentJSON(t, body, "alias_metadata", `{}`)
	assertSentJSON(t, body, "token_policies", `["a"]`)
	assertSentJSON(t, body, "token_ttl", `3600`)
	assertSentJSON(t, body, "bind_secret_id", `true`)
	assertSentJSON(t, body, "secret_id_bound_cidrs", `null`)
	assertSentJSON(t, body, "token_type", `"service"`)
}

// The callback still sees every value as the string safe has always shown
// for it, which is what get, export, and the formats print.
func TestUpdateShowsTypedFieldsAsTheirJSONStrings(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "auth/approle/role/web", endpointRole, approleRead)

	want := map[string]string{
		"alias_metadata":        `{}`,
		"token_policies":        `["a"]`,
		"token_ttl":             `3600`,
		"bind_secret_id":        `true`,
		"secret_id_bound_cidrs": `null`,
		"token_type":            `default`,
	}
	_, err := v.Update("auth/approle/role/web", func(s *vault.Secret, exists bool) (*vault.Secret, bool, error) {
		if !exists {
			t.Errorf("exists = false, want true")
		}
		for k, w := range want {
			if got := s.Get(k); got != w {
				t.Errorf("s.Get(%q) = %q, want %q", k, got, w)
			}
		}
		return nil, false, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
}

// A key the caller sets goes out as the string it was given, even when the
// string spells the JSON the read returned, and a key the caller deletes
// goes out not at all.
func TestUpdateSendsTouchedFieldsAsGiven(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "auth/approle/role/web", endpointRole, approleRead)

	_, err := v.Update("auth/approle/role/web", func(s *vault.Secret, _ bool) (*vault.Secret, bool, error) {
		if err := s.Set("token_policies", "a,b", false); err != nil {
			return nil, false, err
		}
		if err := s.Set("token_ttl", "3600", false); err != nil {
			return nil, false, err
		}
		s.Delete("secret_id_bound_cidrs")
		return nil, true, nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	body := onlyWrite(t, fv, "auth/approle/role/web")
	assertSentJSON(t, body, "token_policies", `"a,b"`)
	assertSentJSON(t, body, "token_ttl", `"3600"`)
	assertSentJSON(t, body, "alias_metadata", `{}`)
	if _, sent := body["secret_id_bound_cidrs"]; sent {
		t.Errorf("write sent deleted key secret_id_bound_cidrs = %s", body["secret_id_bound_cidrs"])
	}
}

// A KV secret written by another tool can hold the same JSON types, and a
// `safe set` of one key must not turn the rest into strings. The number is
// past float64's exact range, so it only survives if it goes back as the
// bytes it came in as.
const typedKVSecret = `{
	"config": {"b": [1, 2], "a": "x"},
	"count": 12345678901234567890,
	"enabled": false,
	"password": "old"
}`

func TestUpdateOnKVv1KeepsUntouchedValuesTyped(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "secret/typed", endpointKV1, typedKVSecret)

	before, err := v.Read("secret/typed")
	if err != nil {
		t.Fatalf("Read before: %v", err)
	}

	if _, err := v.Update("secret/typed", setKey("password", "new")); err != nil {
		t.Fatalf("Update: %v", err)
	}

	body := onlyWrite(t, fv, "secret/typed")
	assertSentJSON(t, body, "config", `{"b":[1,2],"a":"x"}`)
	assertSentJSON(t, body, "count", `12345678901234567890`)
	assertSentJSON(t, body, "enabled", `false`)
	assertSentJSON(t, body, "password", `"new"`)

	//What get prints for the untouched keys is what it printed before.
	after, err := v.Read("secret/typed")
	if err != nil {
		t.Fatalf("Read after: %v", err)
	}
	for _, k := range []string{"config", "count", "enabled"} {
		if after.Get(k) != before.Get(k) {
			t.Errorf("get %s = %q after the update, %q before", k, after.Get(k), before.Get(k))
		}
	}
	if got := after.Get("config"); got != `{"a":"x","b":[1,2]}` {
		t.Errorf("get config = %q, want the re-marshalled JSON safe has always shown", got)
	}
}

func TestUpdateOnKVv2KeepsUntouchedValuesTyped(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv")
	fv.typedEndpoint(t, "kv/data/typed", endpointKV2, typedKVSecret)

	version, err := v.Update("kv/typed", setKey("password", "new"))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if version != 2 {
		t.Errorf("Update assigned version %d, want 2", version)
	}

	body := onlyWrite(t, fv, "kv/data/typed")
	assertSentJSON(t, body, "config", `{"b":[1,2],"a":"x"}`)
	assertSentJSON(t, body, "count", `12345678901234567890`)
	assertSentJSON(t, body, "enabled", `false`)
	assertSentJSON(t, body, "password", `"new"`)
}

// UpdateSteps writes the accumulated secret once per step, and every one of
// those writes must carry the untouched fields typed.
func TestUpdateStepsOnAuthRoleSendsUntouchedFieldsTyped(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "auth/approle/role/web", endpointRole, approleRead)

	keys := []string{"token_type", "token_num_uses"}
	vals := []string{"service", "5"}
	err := v.UpdateSteps("auth/approle/role/web", len(keys), func(step int, s *vault.Secret, _ bool) (bool, error) {
		return true, s.Set(keys[step], vals[step], false)
	})
	if err != nil {
		t.Fatalf("UpdateSteps: %v", err)
	}

	writes := fv.endpointWrites("auth/approle/role/web")
	if len(writes) != 2 {
		t.Fatalf("%d writes, want 2", len(writes))
	}
	for _, body := range writes {
		assertSentJSON(t, body, "alias_metadata", `{}`)
		assertSentJSON(t, body, "token_policies", `["a"]`)
		assertSentJSON(t, body, "token_type", `"service"`)
	}
	assertSentJSON(t, writes[1], "token_num_uses", `"5"`)
}
