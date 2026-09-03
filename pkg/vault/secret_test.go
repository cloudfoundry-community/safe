package vault_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
	"github.com/cloudfoundry-community/safe/pkg/yamlenc"
)

// newTestSecret builds a Secret with the given key/value pairs.
func newTestSecret(pairs ...string) *vault.Secret {
	s := vault.NewSecret()
	if len(pairs)%2 != 0 {
		panic("newTestSecret: pairs must be even (key, value, ...)")
	}
	for i := 0; i < len(pairs); i += 2 {
		if err := s.Set(pairs[i], pairs[i+1], false); err != nil {
			panic("newTestSecret Set: " + err.Error())
		}
	}
	return s
}

// --- Has ---

func TestSecret_Has(t *testing.T) {
	cases := []struct {
		name   string
		keys   []string
		lookup string
		want   bool
	}{
		{name: "present key", keys: []string{"a", "b"}, lookup: "a", want: true},
		{name: "absent key", keys: []string{"a", "b"}, lookup: "z", want: false},
		{name: "empty secret", keys: nil, lookup: "a", want: false},
		{name: "empty string key present", keys: []string{"", "v"}, lookup: "", want: true},
		{name: "empty string key absent", keys: []string{"a", "v"}, lookup: "", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := vault.NewSecret()
			for i := 0; i < len(tc.keys); i += 2 {
				_ = s.Set(tc.keys[i], tc.keys[i+1], false)
			}
			if got := s.Has(tc.lookup); got != tc.want {
				t.Errorf("Has(%q) = %v; want %v", tc.lookup, got, tc.want)
			}
		})
	}
}

// --- Get ---

func TestSecret_Get(t *testing.T) {
	cases := []struct {
		name  string
		setup []string
		key   string
		want  string
	}{
		{name: "existing key", setup: []string{"foo", "bar"}, key: "foo", want: "bar"},
		{name: "missing key returns empty", setup: []string{"foo", "bar"}, key: "baz", want: ""},
		{name: "empty value", setup: []string{"k", ""}, key: "k", want: ""},
		{name: "empty secret", setup: nil, key: "x", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := vault.NewSecret()
			for i := 0; i < len(tc.setup); i += 2 {
				_ = s.Set(tc.setup[i], tc.setup[i+1], false)
			}
			if got := s.Get(tc.key); got != tc.want {
				t.Errorf("Get(%q) = %q; want %q", tc.key, got, tc.want)
			}
		})
	}
}

// --- Set ---

func TestSecret_Set(t *testing.T) {
	t.Run("set new key", func(t *testing.T) {
		s := vault.NewSecret()
		if err := s.Set("k", "v", false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s.Get("k") != "v" {
			t.Errorf("Get after Set = %q; want %q", s.Get("k"), "v")
		}
	})

	t.Run("overwrite existing key when skipIfExists false", func(t *testing.T) {
		s := newTestSecret("k", "old")
		if err := s.Set("k", "new", false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s.Get("k") != "new" {
			t.Errorf("Get after overwrite = %q; want %q", s.Get("k"), "new")
		}
	})

	t.Run("skip overwrite when skipIfExists true", func(t *testing.T) {
		s := newTestSecret("k", "original")
		err := s.Set("k", "new", true)
		if err == nil {
			t.Fatal("expected error when skipIfExists=true and key exists, got nil")
		}
		if s.Get("k") != "original" {
			t.Errorf("value mutated despite skipIfExists=true: got %q", s.Get("k"))
		}
	})

	t.Run("set new key with skipIfExists true succeeds", func(t *testing.T) {
		s := vault.NewSecret()
		if err := s.Set("fresh", "val", true); err != nil {
			t.Fatalf("unexpected error setting new key with skipIfExists=true: %v", err)
		}
		if s.Get("fresh") != "val" {
			t.Errorf("Get = %q; want %q", s.Get("fresh"), "val")
		}
	})

	t.Run("set empty string value", func(t *testing.T) {
		s := vault.NewSecret()
		if err := s.Set("k", "", false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !s.Has("k") {
			t.Error("key absent after Set with empty string value")
		}
		if s.Get("k") != "" {
			t.Errorf("Get = %q; want empty string", s.Get("k"))
		}
	})
}

// --- Delete ---

func TestSecret_Delete(t *testing.T) {
	t.Run("delete existing key returns true", func(t *testing.T) {
		s := newTestSecret("a", "1")
		if !s.Delete("a") {
			t.Error("Delete returned false; want true")
		}
		if s.Has("a") {
			t.Error("key still present after Delete")
		}
	})

	t.Run("delete absent key returns false", func(t *testing.T) {
		s := newTestSecret("a", "1")
		if s.Delete("missing") {
			t.Error("Delete returned true for absent key; want false")
		}
	})

	t.Run("delete from empty secret returns false", func(t *testing.T) {
		s := vault.NewSecret()
		if s.Delete("x") {
			t.Error("Delete returned true on empty secret; want false")
		}
	})

	t.Run("delete then set key again", func(t *testing.T) {
		s := newTestSecret("k", "old")
		s.Delete("k")
		if err := s.Set("k", "new", false); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if s.Get("k") != "new" {
			t.Errorf("Get after delete+set = %q; want %q", s.Get("k"), "new")
		}
	})
}

// --- Empty ---

func TestSecret_Empty(t *testing.T) {
	t.Run("new secret is empty", func(t *testing.T) {
		if !vault.NewSecret().Empty() {
			t.Error("NewSecret().Empty() = false; want true")
		}
	})

	t.Run("secret with a key is not empty", func(t *testing.T) {
		s := newTestSecret("k", "v")
		if s.Empty() {
			t.Error("Empty() = true for non-empty secret; want false")
		}
	})

	t.Run("empty after deleting all keys", func(t *testing.T) {
		s := newTestSecret("k", "v")
		s.Delete("k")
		if !s.Empty() {
			t.Error("Empty() = false after deleting all keys; want true")
		}
	})
}

// --- Keys ---

func TestSecret_Keys(t *testing.T) {
	t.Run("empty secret returns empty slice", func(t *testing.T) {
		keys := vault.NewSecret().Keys()
		if len(keys) != 0 {
			t.Errorf("Keys() = %v; want []", keys)
		}
	})

	t.Run("returns all keys sorted", func(t *testing.T) {
		s := newTestSecret("z", "1", "a", "2", "m", "3")
		got := s.Keys()
		want := []string{"a", "m", "z"}
		if len(got) != len(want) {
			t.Fatalf("Keys() len = %d; want %d", len(got), len(want))
		}
		// confirm sorted
		sorted := make([]string, len(got))
		copy(sorted, got)
		sort.Strings(sorted)
		for i, k := range sorted {
			if got[i] != k {
				t.Errorf("Keys()[%d] = %q; want sorted %q", i, got[i], k)
			}
		}
		for i, k := range want {
			if got[i] != k {
				t.Errorf("Keys()[%d] = %q; want %q", i, got[i], k)
			}
		}
	})

	t.Run("keys after delete reflect removal", func(t *testing.T) {
		s := newTestSecret("a", "1", "b", "2")
		s.Delete("a")
		keys := s.Keys()
		if len(keys) != 1 || keys[0] != "b" {
			t.Errorf("Keys() after delete = %v; want [b]", keys)
		}
	})
}

// --- SingleValue ---

func TestSecret_SingleValue(t *testing.T) {
	t.Run("exactly one key returns value", func(t *testing.T) {
		s := newTestSecret("k", "val")
		v, err := s.SingleValue()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v != "val" {
			t.Errorf("SingleValue() = %q; want %q", v, "val")
		}
	})

	t.Run("zero keys returns error", func(t *testing.T) {
		_, err := vault.NewSecret().SingleValue()
		if err == nil {
			t.Error("SingleValue() on empty secret: expected error, got nil")
		}
	})

	t.Run("multiple keys returns error", func(t *testing.T) {
		s := newTestSecret("a", "1", "b", "2")
		_, err := s.SingleValue()
		if err == nil {
			t.Error("SingleValue() with 2 keys: expected error, got nil")
		}
	})

	t.Run("empty string value is valid", func(t *testing.T) {
		s := newTestSecret("k", "")
		v, err := s.SingleValue()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if v != "" {
			t.Errorf("SingleValue() = %q; want empty string", v)
		}
	})
}

// --- JSON ---

func TestSecret_JSON(t *testing.T) {
	t.Run("empty secret produces valid empty JSON object", func(t *testing.T) {
		j := vault.NewSecret().JSON()
		var m map[string]string
		if err := json.Unmarshal([]byte(j), &m); err != nil {
			t.Fatalf("JSON() produced invalid JSON: %v (got %q)", err, j)
		}
		if len(m) != 0 {
			t.Errorf("expected empty map; got %v", m)
		}
	})

	t.Run("populated secret produces correct JSON", func(t *testing.T) {
		s := newTestSecret("foo", "bar", "baz", "qux")
		j := s.JSON()
		var m map[string]string
		if err := json.Unmarshal([]byte(j), &m); err != nil {
			t.Fatalf("JSON() produced invalid JSON: %v (got %q)", err, j)
		}
		if m["foo"] != "bar" {
			t.Errorf("m[foo] = %q; want %q", m["foo"], "bar")
		}
		if m["baz"] != "qux" {
			t.Errorf("m[baz] = %q; want %q", m["baz"], "qux")
		}
	})

	t.Run("special characters are preserved", func(t *testing.T) {
		s := newTestSecret("key", `val"with"quotes`)
		j := s.JSON()
		var m map[string]string
		if err := json.Unmarshal([]byte(j), &m); err != nil {
			t.Fatalf("JSON() produced invalid JSON: %v (got %q)", err, j)
		}
		if m["key"] != `val"with"quotes` {
			t.Errorf("m[key] = %q; want val\"with\"quotes", m["key"])
		}
	})
}

// --- YAML ---

func TestSecret_YAML(t *testing.T) {
	t.Run("empty secret produces non-empty YAML with empty map", func(t *testing.T) {
		y := vault.NewSecret().YAML()
		// yaml.Marshal of empty map produces "{}\n"
		if y == "" {
			t.Error("YAML() returned empty string for empty secret")
		}
	})

	t.Run("populated secret produces parseable YAML", func(t *testing.T) {
		s := newTestSecret("alpha", "one")
		y := s.YAML()
		if !strings.Contains(y, "alpha") {
			t.Errorf("YAML() output missing key 'alpha': %q", y)
		}
		if !strings.Contains(y, "one") {
			t.Errorf("YAML() output missing value 'one': %q", y)
		}
	})

	t.Run("hostile values survive a YAML round trip", func(t *testing.T) {
		s := newTestSecret(
			"question", "? x",
			"exponent", "1e3",
			"infinity", ".inf",
			"crlf", "line1\r\nline2",
			"tabbed", "a\tb",
			"truthy", "yes",
			"pem", "-----BEGIN-----\nAAA\n-----END-----\n",
			"plain", "it's a secret",
		)
		var back map[string]string
		if err := yamlenc.Unmarshal([]byte(s.YAML()), &back); err != nil {
			t.Fatalf("YAML() output does not parse: %v\n%s", err, s.YAML())
		}
		for _, k := range s.Keys() {
			if back[k] != s.Get(k) {
				t.Errorf("%s: got %q, want %q", k, back[k], s.Get(k))
			}
		}
	})
}

// --- MarshalJSON / UnmarshalJSON round-trip ---

func TestSecret_MarshalUnmarshalJSON(t *testing.T) {
	t.Run("round-trip empty secret", func(t *testing.T) {
		original := vault.NewSecret()
		b, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		restored := vault.NewSecret()
		if err := json.Unmarshal(b, restored); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if !restored.Empty() {
			t.Errorf("restored secret not empty; keys = %v", restored.Keys())
		}
	})

	t.Run("round-trip populated secret", func(t *testing.T) {
		original := newTestSecret("user", "admin", "pass", "s3cr3t")
		b, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		restored := vault.NewSecret()
		if err := json.Unmarshal(b, restored); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		for _, k := range original.Keys() {
			if restored.Get(k) != original.Get(k) {
				t.Errorf("key %q: restored=%q; want=%q", k, restored.Get(k), original.Get(k))
			}
		}
		if len(restored.Keys()) != len(original.Keys()) {
			t.Errorf("key count mismatch: restored=%d, original=%d",
				len(restored.Keys()), len(original.Keys()))
		}
	})

	t.Run("unmarshal raw JSON", func(t *testing.T) {
		raw := `{"hostname":"vault.example.com","port":"8200"}`
		s := vault.NewSecret()
		if err := json.Unmarshal([]byte(raw), s); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if s.Get("hostname") != "vault.example.com" {
			t.Errorf("hostname = %q; want vault.example.com", s.Get("hostname"))
		}
		if s.Get("port") != "8200" {
			t.Errorf("port = %q; want 8200", s.Get("port"))
		}
	})

	t.Run("marshal then check JSON validity", func(t *testing.T) {
		s := newTestSecret("a", "1", "b", "2", "c", "3")
		b, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		if !json.Valid(b) {
			t.Errorf("Marshal produced invalid JSON: %s", b)
		}
	})
}

// --- set → get → delete workflow ---

func TestSecret_SetGetDeleteWorkflow(t *testing.T) {
	s := vault.NewSecret()

	// Empty at start.
	if !s.Empty() {
		t.Fatal("new secret should be empty")
	}

	// Set three keys.
	keys := []string{"x", "y", "z"}
	for i, k := range keys {
		if err := s.Set(k, k+k, false); err != nil {
			t.Fatalf("Set(%q): %v", k, err)
		}
		_ = i
	}
	if s.Empty() {
		t.Fatal("secret should not be empty after sets")
	}

	// Get each key.
	for _, k := range keys {
		if got := s.Get(k); got != k+k {
			t.Errorf("Get(%q) = %q; want %q", k, got, k+k)
		}
	}

	// Delete one key.
	if !s.Delete("y") {
		t.Error("Delete(y) = false; want true")
	}
	if s.Has("y") {
		t.Error("y still present after Delete")
	}
	remaining := s.Keys()
	if len(remaining) != 2 {
		t.Errorf("expected 2 keys after delete; got %v", remaining)
	}

	// Delete remaining keys.
	s.Delete("x")
	s.Delete("z")
	if !s.Empty() {
		t.Errorf("expected empty after all deletes; keys = %v", s.Keys())
	}
}
