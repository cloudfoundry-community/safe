package cli

// -q on tree is documented as the flag that trades accuracy for speed: it
// skips the per-secret version lookup, so secrets whose newest version is
// deleted stay in the listing and a large Vault comes back sooner. It bought
// the first half and none of the second. tree left TreeOpts.SkipVersionInfo
// at its zero value, so the walk fetched the version metadata of every secret
// and then threw the answer away, doing all of the work of the check with
// none of the filtering. paths, which sets the field, was genuinely quicker.
//
// Request counts are the only place this shows up: the output of a quick walk
// was already correct.

import (
	"strings"
	"testing"
)

// versionLookups counts the per-secret version metadata reads served so far.
// A listing of a folder is a metadata request too, hence the list=true
// exclusion, and the walk probes its own root before it knows whether the
// root is a secret, which lands on /v1/secret/metadata with nothing after it.
func versionLookups(fv *cliFakeVault) int {
	n := 0
	for _, entry := range fv.requests() {
		if strings.Contains(entry, "list=true") {
			continue
		}
		if _, ok := strings.CutPrefix(entry, "GET /v1/secret/metadata/"); ok {
			n++
		}
	}
	return n
}

// treeOut renders a tree of the whole mount.
func treeOut(t *testing.T, c *CLI) string {
	t.Helper()
	return captureStdout(t, func() {
		if err := c.cmdTree("tree", "secret"); err != nil {
			t.Fatalf("cmdTree: %v", err)
		}
	})
}

// The fixture holds three secrets, so a walk that checks liveness looks up
// three version histories and a quick one looks up none.
func TestQuickTreeSkipsThePerSecretVersionLookups(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	c := newTestCLI(t)
	c.opt.Tree.Quick = true

	fv.forgetRequests()
	treeOut(t, c)

	if got := versionLookups(fv); got != 0 {
		t.Errorf("tree -q looked up %d version histories, want 0:\n%s",
			got, strings.Join(fv.requests(), "\n"))
	}
}

// The control: under --exact the lookups are what the check is made of. This
// used to be the no-flag case, before the quick walk became the default.
func TestTreeLooksUpEveryVersionHistoryWhenExact(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	c := newTestCLI(t)
	c.opt.Tree.Exact = true

	fv.forgetRequests()
	treeOut(t, c)

	if got := versionLookups(fv); got != 3 {
		t.Errorf("tree --exact looked up %d version histories, want one per secret (3):\n%s",
			got, strings.Join(fv.requests(), "\n"))
	}
}

// --keys used to need the version history to reach the keys, so -q could not
// skip the lookup there. It no longer does: a keyed walk that also does not
// ask for every version or a deleted one reads each secret's newest version
// in a single data GET, with no metadata lookup at all.
func TestQuickTreeWithKeysSkipsVersionLookupsToo(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	c := newTestCLI(t)
	c.opt.Tree.Quick = true
	c.opt.Tree.ShowKeys = true

	fv.forgetRequests()
	out := treeOut(t, c)

	if got := versionLookups(fv); got != 0 {
		t.Errorf("tree -q --keys looked up %d version histories, want 0:\n%s",
			got, strings.Join(fv.requests(), "\n"))
	}
	for _, want := range []string{"pw", "tok"} {
		if !strings.Contains(out, want) {
			t.Errorf("tree -q --keys is missing key %q:\n%s", want, out)
		}
	}
}

// What -q does buy is unchanged: the secret whose newest version is deleted
// stays in the listing, because nothing looked.
func TestQuickTreeStillKeepsADeletedLatestSecret(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)
	c.opt.Tree.Quick = true

	if out := treeOut(t, c); !strings.Contains(out, "db") {
		t.Errorf("tree -q should list db regardless of version state:\n%s", out)
	}
}

// And a walk that does look still drops it.
func TestExactTreeStillOmitsADeletedLatestSecret(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)
	c.opt.Tree.Exact = true

	out := treeOut(t, c)
	if strings.Contains(out, "db") {
		t.Errorf("tree --exact lists db, whose newest version is deleted:\n%s", out)
	}
	if !strings.Contains(out, "api") {
		t.Errorf("tree --exact is missing api:\n%s", out)
	}
}
