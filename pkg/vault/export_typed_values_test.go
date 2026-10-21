package vault_test

// safe export reads every secret through the tree walk and safe import
// writes each one back. For a value that was not a string to survive that
// trip, the walk has to keep the JSON it read, the export has to be able to
// print it, and the import has to be able to turn it back into a Secret
// that writes it with its type. These cover the pkg/vault half of each
// step; internal/cli covers the file format itself.

import (
	"encoding/json"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// typedKVWant is typedKVSecret key by key, as the JSON each value should
// travel as.
var typedKVWant = map[string]string{
	"config":   `{"b":[1,2],"a":"x"}`,
	"count":    `12345678901234567890`,
	"enabled":  `false`,
	"password": `"old"`,
}

// assertTypedJSON fails unless MarshalTypedJSON of s gives exactly the JSON
// in want for every key, and no other key.
func assertTypedJSON(t *testing.T, s *vault.Secret, want map[string]string) {
	t.Helper()
	b, err := s.MarshalTypedJSON()
	if err != nil {
		t.Fatalf("MarshalTypedJSON: %v", err)
	}
	got := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("MarshalTypedJSON gave %s, not a JSON object: %v", b, err)
	}
	if len(got) != len(want) {
		t.Errorf("MarshalTypedJSON gave %d keys, want %d: %s", len(got), len(want), b)
	}
	for key, w := range want {
		assertSentJSON(t, got, key, w)
	}
}

// onlySecret walks path and returns the one secret it finds.
func onlySecret(t *testing.T, v *vault.Vault, path string, opts vault.TreeOpts) vault.SecretEntry {
	t.Helper()
	secrets, err := v.ConstructSecrets(path, opts)
	if err != nil {
		t.Fatalf("ConstructSecrets(%s): %v", path, err)
	}
	if len(secrets) != 1 {
		t.Fatalf("ConstructSecrets(%s) found %d secrets, want 1", path, len(secrets))
	}
	return secrets[0]
}

func TestConstructSecretsKeepsTypesOnKVv1(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "secret/typed", endpointKV1, typedKVSecret)

	entry := onlySecret(t, v, "secret/typed", vault.TreeOpts{FetchKeys: true})
	if len(entry.Versions) != 1 {
		t.Fatalf("walk found %d versions, want 1", len(entry.Versions))
	}
	data := entry.Versions[0].Data
	if !data.HasTypedValues() {
		t.Fatalf("walk kept no typed values")
	}
	assertTypedJSON(t, data, typedKVWant)
}

// The latest-only walk answers a KV v2 secret in one data read, and the
// whole-history walk reads each version on its own. Both have to keep the
// types.
func TestConstructSecretsKeepsTypesOnKVv2(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts vault.TreeOpts
	}{
		{"latest", vault.TreeOpts{FetchKeys: true}},
		{"all versions", vault.TreeOpts{FetchKeys: true, FetchAllVersions: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, fv := newTestVault(t)
			fv.mountV2("kv")
			fv.typedEndpoint(t, "kv/data/typed", endpointKV2, typedKVSecret)

			entry := onlySecret(t, v, "kv/typed", tc.opts)
			if len(entry.Versions) != 1 {
				t.Fatalf("walk found %d versions, want 1", len(entry.Versions))
			}
			assertTypedJSON(t, entry.Versions[0].Data, typedKVWant)
		})
	}
}

// A secret holding only strings has nothing typed, which is what lets
// export keep writing the v1 and v2 formats for it.
func TestHasTypedValuesIsFalseForStrings(t *testing.T) {
	v, fv := newTestVault(t)
	fv.set("secret/plain", map[string]string{"k": "v", "n": "3"})

	entry := onlySecret(t, v, "secret/plain", vault.TreeOpts{FetchKeys: true})
	if entry.Versions[0].Data.HasTypedValues() {
		t.Errorf("HasTypedValues = true for a secret of strings")
	}
	if vault.NewSecret().HasTypedValues() {
		t.Errorf("HasTypedValues = true for an empty secret")
	}
}

// MarshalJSON is what every other JSON rendering of a Secret goes through,
// and its output does not change: values that were not strings still come
// out as the strings safe shows for them.
func TestMarshalJSONStaysStringOnlyForTypedValues(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "secret/typed", endpointKV1, typedKVSecret)

	s, err := v.Read("secret/typed")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	got := map[string]string{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("MarshalJSON gave %s, which is not an object of strings: %v", b, err)
	}
	if got["enabled"] != "false" || got["password"] != "old" {
		t.Errorf("MarshalJSON = %s, want enabled and password as strings", b)
	}
}

// What UnmarshalTypedJSON builds writes every value back with the JSON type
// it was given, and reads back the same strings a Read would give.
func TestUnmarshalTypedJSONWritesTypes(t *testing.T) {
	v, fv := newTestVault(t)
	fv.typedEndpoint(t, "secret/typed", endpointKV1, `{}`)

	s := vault.NewSecret()
	if err := s.UnmarshalTypedJSON([]byte(typedKVSecret)); err != nil {
		t.Fatalf("UnmarshalTypedJSON: %v", err)
	}
	if got := s.Get("password"); got != "old" {
		t.Errorf("Get(password) = %q, want old", got)
	}
	if got := s.Get("enabled"); got != "false" {
		t.Errorf("Get(enabled) = %q, want false", got)
	}
	assertTypedJSON(t, s, typedKVWant)

	if err := v.Write("secret/typed", s); err != nil {
		t.Fatalf("Write: %v", err)
	}
	body := onlyWrite(t, fv, "secret/typed")
	for key, want := range typedKVWant {
		assertSentJSON(t, body, key, want)
	}
}

// Decoding replaces what the Secret held, the way UnmarshalJSON does, so a
// value typed before is not carried into data that holds a string there.
func TestUnmarshalTypedJSONReplacesWhatWasThere(t *testing.T) {
	s := vault.NewSecret()
	if err := s.UnmarshalTypedJSON([]byte(`{"a":1,"b":true}`)); err != nil {
		t.Fatalf("UnmarshalTypedJSON: %v", err)
	}
	if err := s.UnmarshalTypedJSON([]byte(`{"a":"one"}`)); err != nil {
		t.Fatalf("UnmarshalTypedJSON: %v", err)
	}
	if s.HasTypedValues() {
		t.Errorf("HasTypedValues = true after decoding only strings")
	}
	assertTypedJSON(t, s, map[string]string{"a": `"one"`})
}

func TestUnmarshalTypedJSONRefusesWhatIsNotAnObject(t *testing.T) {
	for _, in := range []string{`[1,2]`, `"x"`, `3`, `{"a":`, ``} {
		s := vault.NewSecret()
		if err := s.UnmarshalTypedJSON([]byte(in)); err == nil {
			t.Errorf("UnmarshalTypedJSON(%q) = nil, want an error", in)
		}
	}
}
