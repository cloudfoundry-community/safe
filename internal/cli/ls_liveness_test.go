package cli

// ls decides whether to print a name by finding out whether the secret behind
// it can still be read. It found that out by reading the secret: a GET of
// /secret/data/<path> for every entry in the folder, whose response body is
// the secret itself. ls prints none of that. The value crossed the wire, sat
// in memory, and left a read of every secret in the folder in the audit log,
// to answer a question the version metadata already answers.
//
// The metadata lookup is the same request the tree walk makes for the same
// decision, so this also settles ls and tree on one notion of liveness.

import (
	"sort"
	"strings"
	"testing"
)

// dataReads counts the secret reads served so far.
func dataReads(fv *cliFakeVault) int {
	n := 0
	for _, entry := range fv.requests() {
		if strings.Contains(entry, "GET /v1/secret/data/") {
			n++
		}
	}
	return n
}

// lsOut lists one folder.
func lsOut(t *testing.T, c *CLI, path string) []string {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = c.cmdLs("ls", path) })
	if err != nil {
		t.Fatalf("cmdLs(%q): %v", path, err)
	}
	return entriesOf(out)
}

// The headline: listing a folder reads none of the secrets in it.
func TestListChecksLivenessWithoutReadingTheSecrets(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	c := newTestCLI(t)

	fv.forgetRequests()
	got := lsOut(t, c, "secret/app")

	if reads := dataReads(fv); reads != 0 {
		t.Errorf("ls read %d secrets to list their names:\n%s",
			reads, strings.Join(fv.requests(), "\n"))
	}
	want := []string{"api", "db"}
	if !sameEntries(got, want) {
		t.Errorf("ls secret/app = %v, want %v", got, want)
	}
}

// The check still drops a secret whose newest version is deleted, which is the
// whole reason it is made.
func TestListStillOmitsADeletedLatestSecret(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)

	fv.forgetRequests()
	got := lsOut(t, c, "secret/app")

	if reads := dataReads(fv); reads != 0 {
		t.Errorf("ls read %d secrets:\n%s", reads, strings.Join(fv.requests(), "\n"))
	}
	if !sameEntries(got, []string{"api"}) {
		t.Errorf("ls secret/app = %v, want [api] with the deleted db left out", got)
	}
}

// A destroyed newest version is no more readable than a deleted one.
func TestListStillOmitsADestroyedLatestSecret(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.destroyV2("secret/app/db", 2)
	c := newTestCLI(t)

	if got := lsOut(t, c, "secret/app"); !sameEntries(got, []string{"api"}) {
		t.Errorf("ls secret/app = %v, want [api] with the destroyed db left out", got)
	}
}

// A live older version does not rescue a secret whose newest version is gone.
// safe delete leaves exactly this state behind on a version 2 mount, so a
// listing that kept these would show every deleted secret forever.
func TestListStillOmitsADeletedLatestWithALiveOlderVersion(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)

	//The fixture wrote two versions of db, and only the newest is deleted.
	if states := fv.versionStates("secret/app/db"); len(states) != 2 || states[0] != "alive" {
		t.Fatalf("secret/app/db states = %v, want an alive version 1", states)
	}
	if got := lsOut(t, c, "secret/app"); !sameEntries(got, []string{"api"}) {
		t.Errorf("ls secret/app = %v, want [api]", got)
	}
}

// -q keeps skipping the lookup altogether, so it asks the Vault for neither
// the metadata nor the data of any secret.
func TestQuickListAsksForNeitherMetadataNorData(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)
	c.opt.List.Quick = true

	fv.forgetRequests()
	got := lsOut(t, c, "secret/app")

	if reads := dataReads(fv); reads != 0 {
		t.Errorf("ls -q read %d secrets:\n%s", reads, strings.Join(fv.requests(), "\n"))
	}
	if lookups := versionLookups(fv); lookups != 0 {
		t.Errorf("ls -q looked up %d version histories:\n%s",
			lookups, strings.Join(fv.requests(), "\n"))
	}
	if !sameEntries(got, []string{"api", "db"}) {
		t.Errorf("ls -q secret/app = %v, want both entries", got)
	}
}

// Folders are named by the listing itself and are not secrets, so they are
// never looked up.
func TestListDoesNotLookUpFolders(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	c := newTestCLI(t)

	fv.forgetRequests()
	got := lsOut(t, c, "secret")

	if lookups := versionLookups(fv); lookups != 1 {
		t.Errorf("ls looked up %d version histories, want one for the single "+
			"secret at this level:\n%s", lookups, strings.Join(fv.requests(), "\n"))
	}
	if !sameEntries(got, []string{"app/", "top"}) {
		t.Errorf("ls secret = %v, want [app/ top]", got)
	}
}

// A token that can list and read the data of a folder's secrets, but was
// never granted read on their metadata, used to list the folder before the
// liveness check moved to the metadata endpoint. It has to be able to list
// the folder still: a 403 on the metadata lookup falls back to the data read
// the check used to make, rather than aborting the whole listing.
func TestListFallsBackToADataReadWhenMetadataIsForbidden(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.denyMetadataGet("secret/app/db")
	c := newTestCLI(t)

	fv.forgetRequests()
	got := lsOut(t, c, "secret/app")

	if !sameEntries(got, []string{"api", "db"}) {
		t.Errorf("ls secret/app = %v, want [api db] with the fallback keeping db", got)
	}
	if reads := dataReads(fv); reads != 1 {
		t.Errorf("ls fell back with %d data reads, want 1 (only for the "+
			"secret denied metadata):\n%s", reads, strings.Join(fv.requests(), "\n"))
	}
}

// The fallback still drops a secret that is not there at all, on either
// endpoint, rather than treating a metadata 403 as automatic liveness.
func TestListFallbackStillOmitsASecretMissingFromBothEndpoints(t *testing.T) {
	isolateHome(t)
	fv := walkFixture(t)
	fv.denyMetadataGet("secret/app/db")
	fv.deleteV2("secret/app/db", 2)
	c := newTestCLI(t)

	got := lsOut(t, c, "secret/app")

	if !sameEntries(got, []string{"api"}) {
		t.Errorf("ls secret/app = %v, want [api] with the deleted, forbidden-metadata db left out", got)
	}
}

// sameEntries compares two listings without caring about order.
func sameEntries(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	left := append([]string(nil), got...)
	right := append([]string(nil), want...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
