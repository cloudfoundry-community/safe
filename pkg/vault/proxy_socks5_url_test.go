// The ssh+socks5:// proxy URL: which parts of it name the private key, and
// what is said when they do not.
package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openHelper runs openSOCKS5Helper against a throwaway known_hosts file, so a
// test never reads or writes the one belonging to whoever is running it.
func openHelper(t *testing.T, proxyURL string) (string, error) {
	t.Helper()
	return openSOCKS5Helper(proxyURL, filepath.Join(t.TempDir(), "known_hosts"), false)
}

// TestSOCKS5URLNamesThePrivateKey checks the two ways of naming the key, both
// of which the README offers. Neither can connect here -- there is no host to
// connect to -- but the path each one produces is in the error, which is how
// we can see that the right part of the URL was read.
func TestSOCKS5URLNamesThePrivateKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		url  string
		want string
	}{
		{
			name: "as the path",
			url:  "ssh+socks5://you@bastion.example.com/keys/id_ed25519",
			want: "/keys/id_ed25519",
		},
		{
			name: "as a query parameter",
			url:  "ssh+socks5://you@bastion.example.com?private-key=keys/id_ed25519",
			want: "keys/id_ed25519",
		},
		{
			name: "alongside a port",
			url:  "ssh+socks5://you@bastion.example.com:2222/keys/id_ed25519",
			want: "/keys/id_ed25519",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := openHelper(t, tc.url)
			if err == nil {
				t.Fatal("expected the missing key file to be reported")
			}
			if !strings.Contains(err.Error(), "could not read private key file") {
				t.Fatalf("failed before reading the key: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("looked for the key somewhere other than %s: %v", tc.want, err)
			}
		})
	}
}

// TestSOCKS5URLRefusals checks what is said about a URL that cannot be used.
func TestSOCKS5URLRefusals(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		url  string
		want string
	}{
		{
			name: "no user to log in as",
			url:  "ssh+socks5://bastion.example.com/keys/id_ed25519",
			want: "no user provided",
		},
		{
			name: "no key at all",
			url:  "ssh+socks5://you@bastion.example.com",
			want: "no private key path provided",
		},
		{
			name: "a bare host with a trailing slash names no key",
			url:  "ssh+socks5://you@bastion.example.com/",
			want: "no private key path provided",
		},
		{
			name: "a key named both ways at once",
			url:  "ssh+socks5://you@bastion.example.com/keys/a?private-key=keys/b",
			want: "more than one private key",
		},
		{
			name: "two keys named as query parameters",
			url:  "ssh+socks5://you@bastion.example.com?private-key=keys/a&private-key=keys/b",
			want: "more than one private key",
		},
		{
			name: "not a URL",
			url:  "ssh+socks5://you@bastion.example.com:port/keys/a",
			want: "could not parse proxy URL",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := openHelper(t, tc.url)
			if err == nil {
				t.Fatalf("%s was accepted", tc.url)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error for %s does not mention %q: %v", tc.url, tc.want, err)
			}
		})
	}
}

// TestSOCKS5URLKeyMustBeUsable checks that a key file which is not a key is
// reported as such, rather than as a failure to reach the host.
func TestSOCKS5URLKeyMustBeUsable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("this is not a private key\n"), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	_, err := openHelper(t, "ssh+socks5://you@bastion.example.com?private-key="+keyPath)
	if err == nil {
		t.Fatal("expected the unusable key to be refused")
	}
	if !strings.Contains(err.Error(), "signer for private key") {
		t.Errorf("unusable key reported as something else: %v", err)
	}
}
