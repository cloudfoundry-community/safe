// Which known_hosts line the host-key-changed warning names. A reader who
// deletes the line safe points at has to be deleting the right one.
package vault

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// makeRSAPublicKey generates a fresh RSA SSH public key, for tests that need
// two entries of differing type for one host.
func makeRSAPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return pub
}

// seedKnownHosts writes one entry per key, in order, all for the same host.
func seedKnownHosts(t *testing.T, path, host string, keys ...ssh.PublicKey) {
	t.Helper()
	normalized := knownhosts.Normalize(host)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s\n", knownhosts.Line([]string{normalized}, k))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
}

var offendingLine = regexp.MustCompile(`Offending (\S+) key in \S+:(\d+)`)

// offendingKey pulls the type and line number that the warning names.
func offendingKey(t *testing.T, err error) (string, int) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a host key conflict, got nil")
	}
	m := offendingLine.FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("no offending-key line in warning:\n%v", err)
	}
	line, convErr := strconv.Atoi(m[2])
	if convErr != nil {
		t.Fatalf("line number %q: %v", m[2], convErr)
	}
	return m[1], line
}

// TestConflictNamesTheLineOfTheOfferedKeyType checks that where a host has
// entries of two types, the warning names the one that conflicts with the key
// the host offered — not whichever entry happens to come first or last.
func TestConflictNamesTheLineOfTheOfferedKeyType(t *testing.T) {
	t.Parallel()
	const host = "conflict.example.com:22"

	//The offered key is ed25519 both times. Only the position of the ed25519
	// entry in the file moves, so the line named has to move with it.
	for _, tc := range []struct {
		name string
		keys func(rsa, ed ssh.PublicKey) []ssh.PublicKey
		want int
	}{
		{
			name: "ed25519 second",
			keys: func(r, e ssh.PublicKey) []ssh.PublicKey { return []ssh.PublicKey{r, e} },
			want: 2,
		},
		{
			name: "ed25519 first",
			keys: func(r, e ssh.PublicKey) []ssh.PublicKey { return []ssh.PublicKey{e, r} },
			want: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "known_hosts")
			seedKnownHosts(t, path, host, tc.keys(makeRSAPublicKey(t), makeEd25519PublicKey(t))...)

			cb, err := knownHostsPromptCallback(path)
			if err != nil {
				t.Fatalf("knownHostsPromptCallback: %v", err)
			}

			//A different ed25519 key: the stored ed25519 entry is what it
			// conflicts with.
			typ, line := offendingKey(t, cb(host, fakeNetAddr("127.0.0.1:22"), makeEd25519PublicKey(t)))
			if line != tc.want {
				t.Errorf("warning names known_hosts line %d; the conflicting entry is on line %d", line, tc.want)
			}
			if typ != ssh.KeyAlgoED25519 {
				t.Errorf("warning names a %s key; the conflicting entry is %s", typ, ssh.KeyAlgoED25519)
			}
		})
	}
}

// TestConflictNamesTheFirstEntryOfTheOfferedType covers a host with more than
// one entry of the same type, where every one of them conflicts. ssh names the
// first, and someone working through the file from the top expects the same.
func TestConflictNamesTheFirstEntryOfTheOfferedType(t *testing.T) {
	t.Parallel()
	const host = "doubled.example.com:22"
	path := filepath.Join(t.TempDir(), "known_hosts")
	seedKnownHosts(t, path, host,
		makeEd25519PublicKey(t), makeRSAPublicKey(t), makeEd25519PublicKey(t))

	cb, err := knownHostsPromptCallback(path)
	if err != nil {
		t.Fatalf("knownHostsPromptCallback: %v", err)
	}

	_, line := offendingKey(t, cb(host, fakeNetAddr("127.0.0.1:22"), makeEd25519PublicKey(t)))
	if line != 1 {
		t.Errorf("warning names known_hosts line %d; the first conflicting entry is on line 1", line)
	}
}

// TestConflictNamesTheStoredKeyType checks the case where the host has no
// entry of the offered type at all. The warning still names a line, so the
// type it prints must be the type of the key written there.
func TestConflictNamesTheStoredKeyType(t *testing.T) {
	t.Parallel()
	const host = "mismatched.example.com:22"
	path := filepath.Join(t.TempDir(), "known_hosts")
	seedKnownHosts(t, path, host, makeRSAPublicKey(t))

	cb, err := knownHostsPromptCallback(path)
	if err != nil {
		t.Fatalf("knownHostsPromptCallback: %v", err)
	}

	typ, line := offendingKey(t, cb(host, fakeNetAddr("127.0.0.1:22"), makeEd25519PublicKey(t)))
	if line != 1 {
		t.Errorf("warning names known_hosts line %d; the only entry is on line 1", line)
	}
	if typ != ssh.KeyAlgoRSA {
		t.Errorf("warning names a %s key on a line holding an %s key", typ, ssh.KeyAlgoRSA)
	}
}
