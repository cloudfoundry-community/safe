// Reaching a host through the SSH proxy on a machine that has no known_hosts
// file yet.
package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKnownHostsFileIsCreatedWhenAbsent covers the first connection from a
// machine that has never run ssh. Host keys are checked by reading the file,
// and a file that is not there cannot be read, so the connection used to fail
// before it was attempted.
func TestKnownHostsFileIsCreatedWhenAbsent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), ".ssh", "known_hosts")

	if err := ensureKnownHostsFile(path); err != nil {
		t.Fatalf("ensureKnownHostsFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("known_hosts was not created: %v", err)
	}
	if info.Size() != 0 {
		t.Errorf("new known_hosts holds %d bytes, want none", info.Size())
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("new known_hosts is mode %04o, want 0600", perm)
	}

	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("directory for known_hosts was not created: %v", err)
	}
	if perm := dir.Mode().Perm(); perm != 0700 {
		t.Errorf("directory for known_hosts is mode %04o, want 0700", perm)
	}

	//The point of creating it is that the host key check can now be set up.
	if _, err := knownHostsPromptCallback(path); err != nil {
		t.Errorf("host key checking could not be set up against the new file: %v", err)
	}
}

// TestKnownHostsFileIsLeftAloneWhenPresent checks that an existing file keeps
// its entries. Emptying it would throw away every host a person has trusted.
func TestKnownHostsFileIsLeftAloneWhenPresent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "known_hosts")
	writeKnownHostsFixture(t, path, "already.known:22", makeEd25519PublicKey(t))

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if err := ensureKnownHostsFile(path); err != nil {
		t.Fatalf("ensureKnownHostsFile: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("known_hosts was changed\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

// TestStartSSHTunnelCreatesDerivedKnownHostsFile checks the same through the
// caller, for the case where no known_hosts file was named at all and safe
// derives ~/.ssh/known_hosts. The tunnel cannot be made here -- the private
// key is not one -- but the file has to exist by the time that is the reason
// it fails, because a missing file used to be the reason instead.
//
// t.Setenv forbids t.Parallel, so this test runs serially.
func TestStartSSHTunnelCreatesDerivedKnownHostsFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".ssh", "known_hosts")

	_, err := StartSSHTunnel(SOCKS5SSHConfig{
		Host:       "127.0.0.1:22",
		User:       "someone",
		PrivateKey: []byte("this is not a private key"),
	})
	if err == nil {
		t.Fatal("expected the unusable private key to be refused")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("tunnel failed for some reason other than the key: %v", err)
	}

	if _, statErr := os.Stat(path); statErr != nil {
		t.Errorf("known_hosts was not created: %v", statErr)
	}
}

// TestStartSSHTunnelRefusesMissingExplicitKnownHostsFile covers a
// SAFE_KNOWN_HOSTS_FILE that names a curated file which is not there --
// typically a typo'd path, or a mount that has not appeared yet. Before this
// behavior was fixed, safe created an empty file at the mistake and silently
// fell back to trust-on-first-use for whatever key the host offered, in
// place of the verification the operator configured. A path the caller named
// explicitly must fail hard instead, the way ssh itself refuses a bad
// -o UserKnownHostsFile.
func TestStartSSHTunnelRefusesMissingExplicitKnownHostsFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "curated", "known_hosts")

	_, err := StartSSHTunnel(SOCKS5SSHConfig{
		Host:           "127.0.0.1:22",
		User:           "someone",
		PrivateKey:     []byte("this is not a private key"),
		KnownHostsFile: path,
	})
	if err == nil {
		t.Fatal("expected the missing explicit known_hosts file to be refused")
	}
	if !strings.Contains(err.Error(), "known_hosts") && !strings.Contains(err.Error(), "known hosts") {
		t.Errorf("tunnel failed for some reason other than the known_hosts file: %v", err)
	}

	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("explicit known_hosts file was created at a typo'd path: %v", statErr)
	}
}

// TestKnownHostsFileIsNotCreatedWhenChecksAreOff covers the case where host
// key validation is turned off: there is nothing to read the file for, so
// nothing should be written to disk.
func TestKnownHostsFileIsNotCreatedWhenChecksAreOff(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), ".ssh", "known_hosts")

	_, err := StartSSHTunnel(SOCKS5SSHConfig{
		Host:                  "127.0.0.1:22",
		User:                  "someone",
		PrivateKey:            []byte("this is not a private key"),
		KnownHostsFile:        path,
		SkipHostKeyValidation: true,
	})
	if err == nil {
		t.Fatal("expected the unusable private key to be refused")
	}

	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("known_hosts was created although host keys are not being checked: %v", statErr)
	}
}
