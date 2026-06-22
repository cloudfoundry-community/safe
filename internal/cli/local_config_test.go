package cli

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// TestParseConfigKV covers splitting a "key=value" CLI argument. Only format
// and key-identifier checks are performed; the value is returned verbatim
// (trimmed) for the renderer to type.
func TestParseConfigKV(t *testing.T) {
	cases := []struct {
		input     string
		wantKey   string
		wantValue string
		wantErr   bool
	}{
		// Valid pairs.
		{"max_json_string_value_length=8388608", "max_json_string_value_length", "8388608", false},
		{"disable_mlock=false", "disable_mlock", "false", false},
		{"tls_disable=1", "tls_disable", "1", false},
		{`address="127.0.0.1:9000"`, "address", `"127.0.0.1:9000"`, false},

		// Surrounding whitespace is trimmed from key and value.
		{"  log_level = trace  ", "log_level", "trace", false},

		// Value may itself contain '=' (only the first '=' splits).
		{"x_forwarded_for_authorized_addrs=a=b", "x_forwarded_for_authorized_addrs", "a=b", false},

		// Empty value is allowed (renders to an empty string literal).
		{"foo=", "foo", "", false},

		// Invalid: no '=' separator.
		{"justakey", "", "", true},

		// Invalid: empty key.
		{"=value", "", "", true},
		{"  =value", "", "", true},

		// Invalid: key is not a valid HCL identifier.
		{"bad-key=1", "", "", true},
		{"1leading=1", "", "", true},
		{"has space=1", "", "", true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			key, value, err := parseConfigKV(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("parseConfigKV(%q): expected error, got key=%q value=%q", tc.input, key, value)
				}
				return
			}
			if err != nil {
				t.Errorf("parseConfigKV(%q): unexpected error: %v", tc.input, err)
				return
			}
			if key != tc.wantKey || value != tc.wantValue {
				t.Errorf("parseConfigKV(%q): got (%q, %q), want (%q, %q)",
					tc.input, key, value, tc.wantKey, tc.wantValue)
			}
		})
	}
}

// TestRenderHCLValue covers type inference for raw CLI values: integers,
// floats, and booleans are emitted bare; everything else is quoted. Already
// quoted values pass through unchanged.
func TestRenderHCLValue(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		// Integers stay bare.
		{"8388608", "8388608"},
		{"0", "0"},
		{"-5", "-5"},

		// Floats stay bare.
		{"1.5", "1.5"},
		{"0.0", "0.0"},

		// Booleans stay bare.
		{"true", "true"},
		{"false", "false"},

		// Bare strings get quoted.
		{"trace", `"trace"`},
		{"127.0.0.1:9000", `"127.0.0.1:9000"`},
		{"", `""`},

		// Already-quoted values pass through untouched.
		{`"already"`, `"already"`},
		{`"127.0.0.1:9000"`, `"127.0.0.1:9000"`},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.raw, func(t *testing.T) {
			got := renderHCLValue(tc.raw)
			if got != tc.want {
				t.Errorf("renderHCLValue(%q): got %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestApplyConfigKV verifies overrides replace defaults in place while new
// keys append in order, and that parse errors surface unchanged.
func TestApplyConfigKV(t *testing.T) {
	defaults := []hclField{
		{key: "disable_mlock", val: "true"},
	}

	t.Run("appends new key", func(t *testing.T) {
		got, err := applyConfigKV(defaults, []string{"max_json_string_value_length=8388608"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []hclField{
			{key: "disable_mlock", val: "true"},
			{key: "max_json_string_value_length", val: "8388608"},
		}
		assertFields(t, got, want)
	})

	t.Run("overrides existing key in place", func(t *testing.T) {
		got, err := applyConfigKV(defaults, []string{"disable_mlock=false"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []hclField{
			{key: "disable_mlock", val: "false"},
		}
		assertFields(t, got, want)
	})

	t.Run("does not mutate caller's defaults", func(t *testing.T) {
		_, err := applyConfigKV(defaults, []string{"disable_mlock=false"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if defaults[0].val != "true" {
			t.Errorf("defaults mutated: disable_mlock = %q, want %q", defaults[0].val, "true")
		}
	})

	t.Run("propagates parse error", func(t *testing.T) {
		_, err := applyConfigKV(defaults, []string{"bad-key=1"})
		if err == nil {
			t.Errorf("expected error for invalid key, got nil")
		}
	})
}

// TestBuildLocalConfig covers rendering the full Vault HCL config, including
// default contents, storage backends, and user overrides.
func TestBuildLocalConfig(t *testing.T) {
	t.Run("memory backend defaults", func(t *testing.T) {
		body, err := buildLocalConfig(localConfigParams{
			port:       8201,
			storageKey: "storage",
			memory:     true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, body, "disable_mlock = true")
		mustContain(t, body, `listener "tcp" {`)
		mustContain(t, body, `address = "127.0.0.1:8201"`)
		mustContain(t, body, "tls_disable = 1")
		mustContain(t, body, `storage "inmem" {}`)
	})

	t.Run("file backend uses storage key and path", func(t *testing.T) {
		body, err := buildLocalConfig(localConfigParams{
			port:       9000,
			storageKey: "backend",
			filePath:   "/tmp/vault data",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, body, `backend "file" { path = "/tmp/vault data" }`)
	})

	t.Run("global override adds top-level option", func(t *testing.T) {
		body, err := buildLocalConfig(localConfigParams{
			port:       8201,
			storageKey: "storage",
			memory:     true,
			global:     []string{"max_json_string_value_length=8388608"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, body, "max_json_string_value_length = 8388608")
		// The override must sit at the top level, not inside the listener stanza.
		top := body[:strings.Index(body, `listener "tcp"`)]
		mustContain(t, top, "max_json_string_value_length = 8388608")
	})

	t.Run("listener override adds option inside stanza", func(t *testing.T) {
		body, err := buildLocalConfig(localConfigParams{
			port:       8201,
			storageKey: "storage",
			memory:     true,
			listener:   []string{`proxy_protocol_behavior=use_always`},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, body, `proxy_protocol_behavior = "use_always"`)
		start := strings.Index(body, `listener "tcp" {`)
		end := strings.Index(body[start:], "}") + start
		stanza := body[start:end]
		mustContain(t, stanza, `proxy_protocol_behavior = "use_always"`)
	})

	t.Run("listener override can replace a default", func(t *testing.T) {
		body, err := buildLocalConfig(localConfigParams{
			port:       8201,
			storageKey: "storage",
			memory:     true,
			listener:   []string{"tls_disable=0"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mustContain(t, body, "tls_disable = 0")
		if strings.Contains(body, "tls_disable = 1") {
			t.Errorf("expected tls_disable default to be replaced, got:\n%s", body)
		}
	})

	t.Run("invalid global override surfaces error", func(t *testing.T) {
		_, err := buildLocalConfig(localConfigParams{
			port:       8201,
			storageKey: "storage",
			memory:     true,
			global:     []string{"no-equals-sign"},
		})
		if err == nil {
			t.Errorf("expected error for invalid override, got nil")
		}
	})

	t.Run("invalid listener override surfaces error", func(t *testing.T) {
		_, err := buildLocalConfig(localConfigParams{
			port:       8201,
			storageKey: "storage",
			memory:     true,
			listener:   []string{"bad-key=1"},
		})
		if err == nil {
			t.Errorf("expected error for invalid listener override, got nil")
		}
	})
}

// TestLockedBuffer verifies the goroutine-safe buffer accumulates writes and
// reads back its contents. Run under -race, concurrent writers must not trip
// the detector.
func TestLockedBuffer(t *testing.T) {
	t.Run("accumulates writes in order", func(t *testing.T) {
		var b lockedBuffer
		if _, err := b.Write([]byte("hello ")); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := b.Write([]byte("world")); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := b.String(); got != "hello world" {
			t.Errorf("String(): got %q, want %q", got, "hello world")
		}
	})

	t.Run("concurrent writers are race-free", func(t *testing.T) {
		var b lockedBuffer
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				for range 64 {
					_, _ = b.Write([]byte("x"))
					_ = b.String()
				}
			})
		}
		wg.Wait()
		if got := len(b.String()); got != 16*64 {
			t.Errorf("len(String()): got %d, want %d", got, 16*64)
		}
	})
}

// TestVaultStartupError covers all three fallbacks: prefer trimmed stderr,
// then the wait error, then a constant when both are empty.
func TestVaultStartupError(t *testing.T) {
	cases := []struct {
		name    string
		stderr  string
		waitErr error
		want    string
	}{
		{"prefers stderr", "  config rejected\n", errors.New("exit status 1"), "config rejected"},
		{"falls back to wait error", "   \n", errors.New("exit status 2"), "exit status 2"},
		{"falls back to wait error when stderr empty", "", errors.New("signal: killed"), "signal: killed"},
		{"constant when both empty", "  ", nil, "exited without output"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := vaultStartupError(tc.stderr, tc.waitErr)
			if got != tc.want {
				t.Errorf("vaultStartupError(%q, %v): got %q, want %q", tc.stderr, tc.waitErr, got, tc.want)
			}
		})
	}
}

func assertFields(t *testing.T, got, want []hclField) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("field count: got %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func mustContain(t *testing.T, body, want string) {
	t.Helper()
	if !strings.Contains(body, want) {
		t.Errorf("expected config to contain %q, got:\n%s", want, body)
	}
}
