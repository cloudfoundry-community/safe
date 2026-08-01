// DeleteVersions and Undelete are the two whole-version operations `safe rm`
// and `safe undelete` stand on. On a KV v2 mount, deleting marks versions
// recoverable and undeleting brings one back; on v1 there are no versions to
// mark, so DeleteVersions destroys outright. Undelete also explains what it
// could not restore -- a key, a missing secret, a destroyed or never-written
// version -- and its version errors are deliberately plain errors rather
// than not-found ones, so that MoveCopyTree's walk does not swallow them.

package vault_test

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

func TestDeleteVersionsMarksV2VersionsDeleted(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)

	if err := v.DeleteVersions("kv2/app", []uint{1}); err != nil {
		t.Fatalf("DeleteVersions: %v", err)
	}

	got := fv.v2States("kv2/app")
	want := []string{"deleted", "alive"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("version states = %v, want %v", got, want)
	}
	//The latest version was not named, so the secret still reads.
	s, err := v.Read("kv2/app")
	if err != nil {
		t.Fatalf("Read after deleting version 1: %v", err)
	}
	if s.Get("password") != "two" {
		t.Errorf("password = %q, want %q", s.Get("password"), "two")
	}
}

func TestDeleteVersionsCanNameEveryVersion(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)

	if err := v.DeleteVersions("kv2/app", []uint{1, 2}); err != nil {
		t.Fatalf("DeleteVersions: %v", err)
	}

	got := fv.v2States("kv2/app")
	want := []string{"deleted", "deleted"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("version states = %v, want %v", got, want)
	}
	_, err := v.Read("kv2/app")
	assertSecretNotFound(t, err)
}

// A v1 backend has nothing to mark, so DeleteVersions falls through to a
// real delete and the secret is gone for good.
func TestDeleteVersionsDestroysOnAV1Mount(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.set("secret/app", map[string]string{"password": "one"})

	if err := v.DeleteVersions("secret/app", []uint{1}); err != nil {
		t.Fatalf("DeleteVersions: %v", err)
	}

	secretAbsent(t, fv, "secret/app")
}

// With no version named, Undelete restores the newest version and leaves
// older deletions alone.
func TestUndeleteRestoresTheLatestVersion(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)
	fv.deleteV2("kv2/app", 1, 2)

	if err := v.Undelete("kv2/app"); err != nil {
		t.Fatalf("Undelete: %v", err)
	}

	got := fv.v2States("kv2/app")
	want := []string{"deleted", "alive"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("version states = %v, want %v", got, want)
	}
	s, err := v.Read("kv2/app")
	if err != nil {
		t.Fatalf("Read after undelete: %v", err)
	}
	if s.Get("password") != "two" {
		t.Errorf("password = %q, want %q", s.Get("password"), "two")
	}
}

func TestUndeleteRestoresANamedVersion(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)
	fv.deleteV2("kv2/app", 1)

	if err := v.Undelete("kv2/app^1"); err != nil {
		t.Fatalf("Undelete: %v", err)
	}

	got := fv.v2States("kv2/app")
	want := []string{"alive", "alive"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("version states = %v, want %v", got, want)
	}
	s, err := v.Read("kv2/app^1")
	if err != nil {
		t.Fatalf("Read of the restored version: %v", err)
	}
	if s.Get("password") != "one" {
		t.Errorf("password = %q, want %q", s.Get("password"), "one")
	}
}

// Deletion works on whole versions, so a path naming a key has nothing
// Undelete could restore on its own.
func TestUndeleteRefusesAKey(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app", map[string]string{"password": "one"})

	err := v.Undelete("kv2/app:password")
	if err == nil {
		t.Fatal("Undelete of a key returned nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "cannot undelete specific key") {
		t.Errorf("error %q should say a key cannot be undeleted", err)
	}
}

func TestUndeleteOfAMissingSecret(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")

	err := v.Undelete("kv2/nowhere")
	assertSecretNotFound(t, err)
}

// The version errors below are plain errors on purpose: Undelete is called
// from the tree walk, and MoveCopyTree drops walk errors that answer to
// IsNotFound, so an error that did would vanish without a word.
func TestUndeleteOfADestroyedVersion(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)
	fv.destroyV2("kv2/app", 1)

	err := v.Undelete("kv2/app^1")
	if err == nil {
		t.Fatal("Undelete of a destroyed version returned nil, want an error")
	}
	want := vault.VersionNotFoundMessage("kv2/app", 1, "destroyed")
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	if vault.IsNotFound(err) {
		t.Error("the error answers to IsNotFound, and the tree walk would drop it")
	}
}

// A version below the oldest the metadata still lists was trimmed away, and
// trimming destroys.
func TestUndeleteOfATrimmedVersion(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
		map[string]string{"password": "three"},
	)
	fv.trimV2("kv2/app", 2)

	err := v.Undelete("kv2/app^1")
	if err == nil {
		t.Fatal("Undelete of a trimmed version returned nil, want an error")
	}
	want := vault.VersionNotFoundMessage("kv2/app", 1, "destroyed")
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	if vault.IsNotFound(err) {
		t.Error("the error answers to IsNotFound, and the tree walk would drop it")
	}
}

func TestUndeleteOfAVersionNeverWritten(t *testing.T) {
	t.Parallel()
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app",
		map[string]string{"password": "one"},
		map[string]string{"password": "two"},
	)

	err := v.Undelete("kv2/app^5")
	if err == nil {
		t.Fatal("Undelete of an unwritten version returned nil, want an error")
	}
	want := vault.VersionNotFoundMessage("kv2/app", 5, "")
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	if vault.IsNotFound(err) {
		t.Error("the error answers to IsNotFound, and the tree walk would drop it")
	}
}
