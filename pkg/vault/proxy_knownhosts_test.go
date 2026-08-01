// TV-08: writeKnownHosts file I/O and knownHostsPromptCallback conflict branch.
// Uses t.TempDir for file isolation. No network required.
package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
	"golang.org/x/crypto/ssh"
)

// makeEd25519PublicKey generates a fresh Ed25519 SSH public key.
// Small and fast — no RSA needed.
func makeEd25519PublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return sshPub
}

// writeKnownHostsFixture seeds a known_hosts file with a single entry for host.
func writeKnownHostsFixture(t *testing.T, path, host string, key ssh.PublicKey) {
	t.Helper()
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("create known_hosts: %v", err)
	}
	if err := writeKnownHosts(path, host, key); err != nil {
		t.Fatalf("seed known_hosts with %s: %v", host, err)
	}
}

// ---------------------------------------------------------------------------
// writeKnownHosts file I/O
// ---------------------------------------------------------------------------

// TestWriteKnownHostsEmptyFile verifies that writing to an empty file produces
// a valid known_hosts line containing the hostname and a trailing newline.
func TestWriteKnownHostsEmptyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("create empty known_hosts: %v", err)
	}

	key := makeEd25519PublicKey(t)
	if err := writeKnownHosts(path, "myhost.example.com", key); err != nil {
		t.Fatalf("writeKnownHosts: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	s := string(contents)
	if !strings.Contains(s, "myhost.example.com") {
		t.Errorf("known_hosts does not contain hostname; got:\n%s", s)
	}
	if !strings.HasSuffix(s, "\n") {
		t.Errorf("file should end with newline; got: %q", s)
	}
}

// TestWriteKnownHostsNoTrailingNewline verifies that writing to a file without
// a trailing newline results in a newline being inserted before the new entry,
// and the file still ends with a newline.
func TestWriteKnownHostsNoTrailingNewline(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	// Existing content with no trailing newline.
	existing := "other.host ssh-ed25519 AAAA..."
	if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
		t.Fatalf("create known_hosts: %v", err)
	}

	key := makeEd25519PublicKey(t)
	if err := writeKnownHosts(path, "newhost.example.com", key); err != nil {
		t.Fatalf("writeKnownHosts: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	s := string(contents)
	if !strings.Contains(s, "other.host") {
		t.Errorf("original entry missing; got:\n%s", s)
	}
	if !strings.Contains(s, "newhost.example.com") {
		t.Errorf("new entry missing; got:\n%s", s)
	}
	if !strings.HasSuffix(s, "\n") {
		t.Errorf("file should end with newline; got: %q", s)
	}
	// The function must insert a newline after the existing content.
	if !strings.Contains(s, existing+"\n") {
		t.Errorf("expected newline after existing content; got:\n%s", s)
	}
}

// TestWriteKnownHostsWithTrailingNewline verifies that a file already ending
// with a newline does not get a spurious blank line inserted.
func TestWriteKnownHostsWithTrailingNewline(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")
	existing := "other.host ssh-ed25519 AAAA...\n"
	if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
		t.Fatalf("create known_hosts: %v", err)
	}

	key := makeEd25519PublicKey(t)
	if err := writeKnownHosts(path, "second.host", key); err != nil {
		t.Fatalf("writeKnownHosts: %v", err)
	}

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	s := string(contents)
	if !strings.Contains(s, "second.host") {
		t.Errorf("new entry missing; got:\n%s", s)
	}
	// Must not contain a double blank line between entries.
	if strings.Contains(s, "\n\n") {
		t.Errorf("unexpected blank line in known_hosts:\n%s", s)
	}
}

// ---------------------------------------------------------------------------
// knownHostsPromptCallback — conflict branch (host-key-changed)
// ---------------------------------------------------------------------------

// TestKnownHostsConflictRejected verifies that knownHostsPromptCallback
// returns an error containing "Host key verification failed" when the host
// presents a key that differs from the known entry.
//
// The test seeds known_hosts with key1, then calls the callback with key2.
// The inner knownhosts.New callback will return a *knownhosts.KeyError with
// Want set, triggering the MITM-warning branch — no real network required.
func TestKnownHostsConflictRejected(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")

	key1 := makeEd25519PublicKey(t)
	key2 := makeEd25519PublicKey(t)

	// Seed known_hosts with key1 for the host.
	// knownhosts.Normalize adds "[host]:port" for non-standard ports; use :22
	// so we can call the callback with a consistent hostname:port format.
	writeKnownHostsFixture(t, path, "conflict.host:22", key1)

	cb, err := knownHostsPromptCallback(path)
	if err != nil {
		t.Fatalf("knownHostsPromptCallback: %v", err)
	}

	// Present key2 — differs from the known key1 → KeyError.Want is non-empty.
	fakeAddr := fakeNetAddr("127.0.0.1:22")
	cbErr := cb("conflict.host:22", fakeAddr, key2)
	if cbErr == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if !strings.Contains(cbErr.Error(), "Host key verification failed") {
		t.Errorf("conflict error should contain 'Host key verification failed'; got: %v", cbErr)
	}
}

// TestKnownHostsMatchingKeyAccepted verifies that the callback returns nil
// when the presented key matches the one stored in known_hosts.
func TestKnownHostsMatchingKeyAccepted(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts")

	key := makeEd25519PublicKey(t)
	writeKnownHostsFixture(t, path, "good.host:22", key)

	cb, err := knownHostsPromptCallback(path)
	if err != nil {
		t.Fatalf("knownHostsPromptCallback: %v", err)
	}

	fakeAddr := fakeNetAddr("127.0.0.1:22")
	if err := cb("good.host:22", fakeAddr, key); err != nil {
		t.Errorf("expected nil error for matching key, got: %v", err)
	}
}

// TestUnknownHostPromptGatesOnStdinNotStderr covers an unknown host key
// reaching the interactive-accept branch. The prompt reads its yes/no answer
// from stdin, so whether it runs has to depend on stdin being a terminal, not
// stderr's: an interactive stderr with redirected stdin
// (`safe -T bastion import < data.json`) must be refused without trying to
// read the answer out of the redirected payload, and an interactive stdin
// with redirected stderr must still be asked.
func TestUnknownHostPromptGatesOnStdinNotStderr(t *testing.T) {
	for _, tc := range []struct {
		name       string
		stdinTTY   bool
		stderrTTY  bool
		wantAccept bool
	}{
		{"redirected stdin, interactive stderr: refused without reading", false, true, false},
		{"interactive stdin, redirected stderr: prompt runs", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "known_hosts")
			if err := os.WriteFile(path, []byte{}, 0600); err != nil {
				t.Fatalf("create empty known_hosts: %v", err)
			}
			cb, err := knownHostsPromptCallback(path)
			if err != nil {
				t.Fatalf("knownHostsPromptCallback: %v", err)
			}

			restore := isTerminal
			isTerminal = func(fd uintptr) bool {
				switch fd {
				case os.Stdin.Fd():
					return tc.stdinTTY
				case os.Stderr.Fd():
					return tc.stderrTTY
				default:
					return false
				}
			}
			t.Cleanup(func() { isTerminal = restore })

			prompt.SetReader(strings.NewReader("yes\n"))
			t.Cleanup(func() { prompt.SetReader(nil) })

			key := makeEd25519PublicKey(t)
			cbErr := cb("unknown.example.com:22", fakeNetAddr("127.0.0.1:22"), key)
			accepted := cbErr == nil
			if accepted != tc.wantAccept {
				t.Errorf("accepted = %v (err: %v), want %v", accepted, cbErr, tc.wantAccept)
			}
		})
	}
}

// fakeNetAddr is a minimal net.Addr implementation for tests.
type fakeNetAddr string

func (f fakeNetAddr) Network() string { return "tcp" }
func (f fakeNetAddr) String() string  { return string(f) }
