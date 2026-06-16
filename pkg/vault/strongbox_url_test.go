// Black-box tests for StrongboxURL (strongbox.go).
package vault_test

import (
	"net/url"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// mustParseURL is a test helper that parses a URL or fails the test.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestStrongboxURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "https with default port stripped",
			input: "https://vault.example.com:443",
			want:  "http://vault.example.com:8484/strongbox",
		},
		{
			name:  "http with port stripped",
			input: "http://vault.example.com:8200",
			want:  "http://vault.example.com:8484/strongbox",
		},
		{
			name:  "no port in host unchanged then 8484 appended",
			input: "http://vault.example.com",
			want:  "http://vault.example.com:8484/strongbox",
		},
		{
			name:  "trailing slash on path does not affect host",
			input: "https://vault.example.com:8200/",
			want:  "http://vault.example.com:8484/strongbox",
		},
		{
			name:  "localhost with port",
			input: "http://localhost:8200",
			want:  "http://localhost:8484/strongbox",
		},
		{
			name:  "localhost without port",
			input: "http://localhost",
			want:  "http://localhost:8484/strongbox",
		},
		{
			name:  "127.0.0.1 with port",
			input: "https://127.0.0.1:9000",
			want:  "http://127.0.0.1:8484/strongbox",
		},
		{
			name:  "high port number",
			input: "http://vault.internal:65535",
			want:  "http://vault.internal:8484/strongbox",
		},
		{
			name:  "single digit port",
			input: "http://vault.internal:80",
			want:  "http://vault.internal:8484/strongbox",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u := mustParseURL(t, tc.input)
			got := vault.StrongboxURL(u)
			if got != tc.want {
				t.Errorf("StrongboxURL(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestStrongboxURLAlwaysHTTP verifies the scheme is always "http://"
// regardless of the input scheme.
func TestStrongboxURLAlwaysHTTP(t *testing.T) {
	t.Parallel()

	for _, scheme := range []string{"http", "https"} {
		scheme := scheme
		t.Run(scheme, func(t *testing.T) {
			t.Parallel()
			u := mustParseURL(t, scheme+"://vault.example.com:8200")
			got := vault.StrongboxURL(u)
			if len(got) < 7 || got[:7] != "http://" {
				t.Errorf("StrongboxURL scheme: got %q; want http:// prefix", got)
			}
		})
	}
}

// TestStrongboxURLAlwaysEndpoint verifies the path always ends with
// ":8484/strongbox".
func TestStrongboxURLAlwaysEndpoint(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"https://vault.example.com:443",
		"http://vault.example.com:8200",
		"http://localhost",
	}

	for _, raw := range inputs {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			u := mustParseURL(t, raw)
			got := vault.StrongboxURL(u)
			const suffix = ":8484/strongbox"
			if len(got) < len(suffix) || got[len(got)-len(suffix):] != suffix {
				t.Errorf("StrongboxURL(%q) = %q; want suffix %q", raw, got, suffix)
			}
		})
	}
}
