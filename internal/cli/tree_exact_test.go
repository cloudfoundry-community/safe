package cli

// tree and paths used to hide a secret whose newest version is deleted, and
// paid one version-metadata read per leaf to find out which ones those were.
// On a 300 secret tree that was 300 of the walk's 413 requests. The quick walk
// is now the default and the filtering moved behind --exact, so the common
// listing costs the walk and nothing else.
//
// -q keeps working. It names the default now rather than an opt-in, so every
// invocation that carries it produces exactly what it produced before.

import (
	"strings"
	"testing"
)

// pathsOut renders the flat listing of the whole mount.
func pathsOut(t *testing.T, c *CLI) string {
	t.Helper()
	return captureStdout(t, func() {
		if err := c.cmdPaths("paths", "secret"); err != nil {
			t.Fatalf("cmdPaths: %v", err)
		}
	})
}

// The fixture holds three secrets. By default none of them is looked up.
func TestTreeSkipsVersionLookupsByDefault(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	c := newTestCLI(t)

	fv.forgetRequests()
	treeOut(t, c)

	if got := versionLookups(fv); got != 0 {
		t.Errorf("tree looked up %d version histories, want 0:\n%s",
			got, strings.Join(fv.requests(), "\n"))
	}
}

func TestPathsSkipsVersionLookupsByDefault(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	c := newTestCLI(t)

	fv.forgetRequests()
	pathsOut(t, c)

	if got := versionLookups(fv); got != 0 {
		t.Errorf("paths looked up %d version histories, want 0:\n%s",
			got, strings.Join(fv.requests(), "\n"))
	}
}

// The visible half of the same change: nothing looked, so a deleted-latest
// secret stays in the listing.
func TestTreeKeepsADeletedLatestSecretByDefault(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)

	if out := treeOut(t, c); !strings.Contains(out, "db") {
		t.Errorf("tree should list db by default, whatever its version state:\n%s", out)
	}
}

func TestPathsKeepsADeletedLatestSecretByDefault(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)

	if out := pathsOut(t, c); !strings.Contains(out, "db") {
		t.Errorf("paths should list db by default, whatever its version state:\n%s", out)
	}
}

// --exact buys back the filtering, at one lookup per secret.
func TestExactTreeLooksUpEveryVersionHistory(t *testing.T) {
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

func TestExactPathsOmitsADeletedLatestSecret(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)
	c.opt.Paths.Exact = true

	out := pathsOut(t, c)
	if strings.Contains(out, "db") {
		t.Errorf("paths --exact lists db, whose newest version is deleted:\n%s", out)
	}
	if !strings.Contains(out, "api") {
		t.Errorf("paths --exact is missing api:\n%s", out)
	}
}

// -q asks for what is already the default, so it cannot contradict an explicit
// --exact. The filtering wins.
func TestExactBeatsQuickOnTree(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)
	c.opt.Tree.Quick = true
	c.opt.Tree.Exact = true

	if out := treeOut(t, c); strings.Contains(out, "db") {
		t.Errorf("tree -q --exact should still filter db:\n%s", out)
	}
}

// A caller that already passes -q keeps the output it has today.
func TestQuickMatchesTheDefaultOnTree(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)

	plain := newTestCLI(t)
	quick := newTestCLI(t)
	quick.opt.Tree.Quick = true

	if got, want := treeOut(t, quick), treeOut(t, plain); got != want {
		t.Errorf("tree -q differs from plain tree:\n-q:\n%s\nplain:\n%s", got, want)
	}
}
