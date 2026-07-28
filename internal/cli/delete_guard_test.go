package cli

// End-to-end coverage for the -r guard in cmdDelete, driven through the fake
// Vault in vault_fake_test.go.

import "testing"

// safe rm -r on a path naming a key or a version must not recurse. The comment
// at the guard says so; the condition must agree with it. Without the guard the
// recursive branch drops the key and the version and deletes the whole subtree.
func TestCmdDeleteRecurseIgnoredForKeyOrVersion(t *testing.T) {
	isolateHome(t)
	fv := newCLIFake(t)
	fv.set("secret/foo", map[string]string{"key": "v", "other": "keep"})
	fv.set("secret/foo/a", map[string]string{"k": "1"})
	fv.set("secret/foo/b", map[string]string{"k": "2"})

	c := newTestCLI(t)
	c.opt.Delete.Recurse = true
	c.opt.Delete.Force = true
	_ = c.cmdDelete("delete", "secret/foo:key^2")

	for _, path := range []string{"secret/foo/a", "secret/foo/b"} {
		if fv.get(path) == nil {
			t.Errorf("%s was deleted; -r must not recurse when the path names a key or version", path)
		}
	}
	if kv := fv.get("secret/foo"); kv == nil || kv["other"] != "keep" {
		t.Errorf("secret/foo = %v, want its other key intact", kv)
	}
}
