package cli

// The CA read-modify-write behind issue, reissue, renew, revoke, and
// crl --renew runs under check-and-set on KV v2 mounts: a CA write landing
// between a command's CA read and its CA write -- a concurrent issuance
// moving the serial counter, a concurrent revocation extending the CRL --
// now forces a retry against the fresh CA instead of being overwritten.
// The retry re-parses the CA from that attempt's read (X509.Secret bumps
// the CRL number through the shared CRL pointer, so a reused object would
// double-bump), draws fresh serials, and re-signs the leaves, so no
// stale-serial certificate survives. The leaves' keys were generated
// before the loop and are never drawn again.
//
// Fixtures newCA/newLeaf live in x509_revoke_test.go; the concurrent
// writers here are played through the fake's afterRequest hook, building
// their competing CA states with the same pkg/vault code a real process
// would run.

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// secretToKV flattens a vault.Secret for seeding the fake.
func secretToKV(s *vault.Secret) map[string]string {
	kv := map[string]string{}
	for _, k := range s.Keys() {
		kv[k] = s.Get(k)
	}
	return kv
}

// storeCertV2 writes a certificate as the next version at a literal path
// on the v2 fake, the way safe would.
func storeCertV2(t *testing.T, fv *cliFakeVault, path string, x *vault.X509) {
	t.Helper()
	s, err := x.Secret(false)
	if err != nil {
		t.Fatalf("Secret for %s: %v", path, err)
	}
	fv.setV2(path, secretToKV(s))
}

// parseStoredCA rebuilds an X509 from the newest version at path. Safe to
// call from an afterRequest hook: it reports failures with t.Error, which
// unlike Fatal may be called off the test goroutine.
func parseStoredCA(t *testing.T, fv *cliFakeVault, path string) *vault.X509 {
	data, ok := latestV2Safe(fv, path)
	if !ok {
		t.Errorf("no versions at %s", path)
		return nil
	}
	s := vault.NewSecret()
	for k, v := range data {
		if err := s.Set(k, v, false); err != nil {
			t.Errorf("rebuild %s: %v", path, err)
			return nil
		}
	}
	ca, err := s.X509(true)
	if err != nil {
		t.Errorf("parse the CA at %s: %v", path, err)
		return nil
	}
	return ca
}

// A broken fixture -- no versions at the path parseStoredCA is asked to
// parse -- must not hang the caller. parseStoredCA runs on the httptest
// server's own goroutine when an afterRequest hook calls it, and calling
// Fatal there is undefined by testing's own contract: Fatal/FailNow must
// run on the goroutine executing the test, unlike Error/Errorf, which are
// documented safe from any goroutine. parseStoredCA reports failures with
// t.Error precisely to honor that contract.
//
// The hook is handed a standalone *testing.T rather than this test's own:
// that keeps its (expected, deliberate) failure from propagating to this
// test's result -- Go's runner fails an ancestor whenever any t.Run child
// does -- while still exercising the exact reporting path (Errorf, mutex
// and all) a real *testing.T uses. The round trip is bounded well under a
// real client's own timeout, so a regression that reintroduces a
// Fatal-based call here fails this test promptly instead of hanging it.
func TestParseStoredCAReportsBrokenFixtureWithoutHanging(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/other", map[string]string{"k": strings.Repeat("x", 4096)})

	sub := &testing.T{}
	fv.afterRequest(`^GET /v1/secret/data/other(\?.*)?$`, 1, func() {
		parseStoredCA(sub, fv, "secret/never-written")
	})

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy

	done := make(chan error, 1)
	go func() { done <- c.cmdGen("gen", "16", "secret/other", "trigger") }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cmdGen: %v", err)
		}
	case <-time.After(3 * time.Second):
		// A hang here means the hook abandoned the response mid-flight
		// instead of reporting through t.Error.
		t.Fatal("cmdGen did not return within 3s: the afterRequest hook appears to have hung the response")
	}

	if !sub.Failed() {
		t.Error("expected parseStoredCA to record the broken fixture at secret/never-written as a failure")
	}
}

// latestCASerialV2 parses the hex serial counter of the newest CA version.
func latestCASerialV2(t *testing.T, fv *cliFakeVault, path string) *big.Int {
	t.Helper()
	serial, ok := new(big.Int).SetString(latestV2(t, fv, path)["serial"], 16)
	if !ok {
		t.Fatalf("%s holds no parseable serial (%q)", path, latestV2(t, fv, path)["serial"])
	}
	return serial
}

// latestCRLV2 parses the newest CA version's revocation list.
func latestCRLV2(t *testing.T, fv *cliFakeVault, path string) *x509.RevocationList {
	t.Helper()
	block, _ := pem.Decode([]byte(latestV2(t, fv, path)["crl"]))
	if block == nil {
		t.Fatalf("%s holds no CRL", path)
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("parse the CRL at %s: %v", path, err)
	}
	return crl
}

// latestLeafCertV2 parses the certificate in the newest version at path.
func latestLeafCertV2(t *testing.T, fv *cliFakeVault, path string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(latestV2(t, fv, path)["certificate"]))
	if block == nil {
		t.Fatalf("%s holds no certificate", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse the certificate at %s: %v", path, err)
	}
	return cert
}

// injectConcurrentIssuance plays a process that issued one certificate
// under the stored CA: the counter advances by one and the CA is written
// back, CRL re-signed with the next number.
func injectConcurrentIssuance(t *testing.T, fv *cliFakeVault, caPath string) func() {
	return func() {
		their := parseStoredCA(t, fv, caPath)
		if their == nil {
			return
		}
		their.ReserveSerials(1)
		s, err := their.Secret(false)
		if err != nil {
			t.Errorf("concurrent issuance at %s: %v", caPath, err)
			return
		}
		fv.setV2(caPath, secretToKV(s))
	}
}

// injectConcurrentCAKeySwap replaces the stored CA with a different
// authority whose key is a different type, simulating a concurrent CA
// rotation mid-retry -- the hazard a per-attempt signature-algorithm reset
// exists to survive.
func injectConcurrentCAKeySwap(t *testing.T, fv *cliFakeVault, caPath string, swap *vault.X509) func() {
	return func() {
		s, err := swap.Secret(false)
		if err != nil {
			t.Errorf("swap CA at %s: %v", caPath, err)
			return
		}
		fv.setV2(caPath, secretToKV(s))
	}
}

// injectConcurrentRevocation plays a process that revoked leaf under the
// stored CA.
func injectConcurrentRevocation(t *testing.T, fv *cliFakeVault, caPath string, leaf *vault.X509) func() {
	return func() {
		their := parseStoredCA(t, fv, caPath)
		if their == nil {
			return
		}
		their.Revoke(leaf)
		s, err := their.Secret(false)
		if err != nil {
			t.Errorf("concurrent revocation at %s: %v", caPath, err)
			return
		}
		fv.setV2(caPath, secretToKV(s))
	}
}

// A serial-counter bump landing between the CA read and the CA write
// conflicts the check-and-set: the retry re-reads, draws a fresh serial,
// and re-signs, so the issued certificate's serial matches the persisted
// counter instead of colliding with the concurrent writer's. The exchange
// costs exactly 2 CA reads and 2 CA writes.
func TestX509IssueRetriesWithFreshSerialAfterConflict(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	storeCertV2(t, fv, "secret/ca", newCA(t, "authority"))

	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 1,
		injectConcurrentIssuance(t, fv, "secret/ca"))

	c := batchIssueCLI(t)
	if err := c.cmdX509Issue("x509 issue", "secret/x/a"); err != nil {
		t.Fatalf("issue: %v", err)
	}

	issued := latestLeafCertV2(t, fv, "secret/x/a").SerialNumber
	counter := latestCASerialV2(t, fv, "secret/ca")
	if issued.Cmp(counter) != 0 {
		t.Errorf("issued serial %s != persisted CA counter %s: the retry did not re-draw against fresh state", issued, counter)
	}
	//The stored counter began at 1 and the concurrent issuance moved it
	// to 2, so a cert carrying anything below 3 was signed with a stale
	// serial.
	if issued.Cmp(big.NewInt(3)) != 0 {
		t.Errorf("issued serial = %s, want 3 (past the concurrent writer's 2)", issued)
	}
	if gets, puts := v2DataTraffic(fv, "ca"); gets != 2 || puts != 2 {
		t.Errorf("CA traffic = %d GETs, %d PUTs; want exactly 2 and 2", gets, puts)
	}
	if gets, puts := v2DataTraffic(fv, "x/a"); gets != 0 || puts != 1 {
		t.Errorf("cert traffic = %d GETs, %d PUTs; want 0 and 1", gets, puts)
	}
}

// The CRL number moves by exactly one per persisted write, whatever the
// retries did: after one conflict the persisted number is the concurrent
// writer's plus one -- a retry that reused the first attempt's parsed CA
// would double-bump through the shared CRL pointer and land elsewhere.
func TestX509IssueCRLNumberBumpsOnceAcrossRetry(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	storeCertV2(t, fv, "secret/ca", newCA(t, "authority"))

	//The competing writer publishes two CRLs -- number 2, then 3 -- so
	// the correct outcome (theirs+1 = 4) and the reused-object bug's
	// outcome (1+2 = 3, colliding with theirs) are distinguishable.
	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 1, func() {
		their := parseStoredCA(t, fv, "secret/ca")
		if their == nil {
			return
		}
		for range 2 {
			s, err := their.Secret(false)
			if err != nil {
				t.Errorf("concurrent CRL publish: %v", err)
				return
			}
			fv.setV2("secret/ca", secretToKV(s))
		}
	})

	c := batchIssueCLI(t)
	if err := c.cmdX509Issue("x509 issue", "secret/x/a"); err != nil {
		t.Fatalf("issue: %v", err)
	}

	if got := latestCRLV2(t, fv, "secret/ca").Number; got.Cmp(big.NewInt(4)) != 0 {
		t.Errorf("persisted CRL number = %s, want 4 (the concurrent writer's 3, bumped once)", got)
	}
}

// A batch whose CA write conflicts retries whole: fresh serials with no
// overlap against the concurrent writer's state, and a revocation entry
// that writer added survives into the batch's persisted CRL.
func TestX509IssueBatchRetryKeepsRevocationAndFreshSerials(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	ca := newCA(t, "authority")
	victim := newLeaf(t, ca, "victim") //draws serial 2; counter rests there
	storeCertV2(t, fv, "secret/ca", ca)
	storeCertV2(t, fv, "secret/victim", victim)

	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 1,
		injectConcurrentRevocation(t, fv, "secret/ca", victim))

	c := batchIssueCLI(t)
	if err := c.cmdX509Issue("x509 issue", "secret/x/a", "secret/x/b"); err != nil {
		t.Fatalf("batch issue: %v", err)
	}

	serialA := latestLeafCertV2(t, fv, "secret/x/a").SerialNumber
	serialB := latestLeafCertV2(t, fv, "secret/x/b").SerialNumber
	counter := latestCASerialV2(t, fv, "secret/ca")
	if serialA.Cmp(serialB) == 0 {
		t.Errorf("both certificates carry serial %s", serialA)
	}
	for name, serial := range map[string]*big.Int{"a": serialA, "b": serialB} {
		if serial.Cmp(big.NewInt(2)) <= 0 {
			t.Errorf("cert %s carries serial %s, which the pre-conflict counter already accounted for", name, serial)
		}
		if serial.Cmp(counter) > 0 {
			t.Errorf("cert %s carries serial %s beyond the persisted counter %s", name, serial, counter)
		}
	}

	revoked := latestCRLV2(t, fv, "secret/ca").RevokedCertificateEntries
	found := false
	for _, entry := range revoked {
		if entry.SerialNumber.Cmp(victim.Certificate.SerialNumber) == 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("the concurrent revocation was lost from the persisted CRL (entries: %v)", revoked)
	}
	if gets, puts := v2DataTraffic(fv, "ca"); gets != 2 || puts != 2 {
		t.Errorf("CA traffic = %d GETs, %d PUTs; want exactly 2 and 2", gets, puts)
	}
}

// Sustained conflict on the CA gives up after five attempts, names the CA
// path, and leaves every leaf unwritten -- no certificate may carry a
// serial no persisted counter accounts for.
func TestX509IssueConflictExhaustionLeavesLeafUnwritten(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	storeCertV2(t, fv, "secret/ca", newCA(t, "authority"))

	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 0,
		injectConcurrentIssuance(t, fv, "secret/ca"))

	c := batchIssueCLI(t)
	err := c.cmdX509Issue("x509 issue", "secret/x/a")
	if err == nil {
		t.Fatal("issue under sustained CA conflict = nil, want an error")
	}
	if !strings.Contains(err.Error(), "secret/ca") {
		t.Errorf("error = %q, want it to name secret/ca", err)
	}
	fv.mu.Lock()
	_, leafWritten := fv.versions["secret/x/a"]
	fv.mu.Unlock()
	if leafWritten {
		t.Error("a certificate was written although no CA write ever landed")
	}
	if gets, puts := v2DataTraffic(fv, "ca"); gets != 5 || puts != 5 {
		t.Errorf("CA traffic = %d GETs, %d PUTs; want 5 refused rounds", gets, puts)
	}
}

// Two processes revoking different certificates under one CA: the loser's
// retry re-reads the winner's CRL and adds its own entry, so both
// revocations survive -- the exact lost-revocation hazard, closed.
func TestX509RevokeInterleavedRevocationsBothSurvive(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	ca := newCA(t, "authority")
	leafA := newLeaf(t, ca, "a")
	leafB := newLeaf(t, ca, "b")
	storeCertV2(t, fv, "secret/ca", ca)
	storeCertV2(t, fv, "secret/a", leafA)
	storeCertV2(t, fv, "secret/b", leafB)

	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 1,
		injectConcurrentRevocation(t, fv, "secret/ca", leafB))

	c := newX509CLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/ca"
	if err := c.cmdX509Revoke("x509 revoke", "secret/a"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	revoked := map[string]bool{}
	for _, entry := range latestCRLV2(t, fv, "secret/ca").RevokedCertificateEntries {
		revoked[entry.SerialNumber.String()] = true
	}
	for name, leaf := range map[string]*vault.X509{"a": leafA, "b": leafB} {
		if !revoked[leaf.Certificate.SerialNumber.String()] {
			t.Errorf("the revocation of %s is missing from the final CRL (revoked: %v)", name, revoked)
		}
	}
	if gets, puts := v2DataTraffic(fv, "ca"); gets != 2 || puts != 2 {
		t.Errorf("CA traffic = %d GETs, %d PUTs; want exactly 2 and 2", gets, puts)
	}
}

// Both processes revoking the same certificate: the loser's retry finds
// the serial already on the fresh CRL and writes nothing -- the winner's
// version stands untouched.
func TestX509RevokeOfConcurrentlyRevokedCertWritesNothing(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	ca := newCA(t, "authority")
	leafA := newLeaf(t, ca, "a")
	storeCertV2(t, fv, "secret/ca", ca)
	storeCertV2(t, fv, "secret/a", leafA)

	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 1,
		injectConcurrentRevocation(t, fv, "secret/ca", leafA))

	c := newX509CLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/ca"
	if err := c.cmdX509Revoke("x509 revoke", "secret/a"); err != nil {
		t.Fatalf("revoke of an already-revoked certificate: %v", err)
	}

	//Version 1 seeded, version 2 the concurrent revocation; a third
	// version would be a pointless CRL churn recording nothing new.
	if states := fv.versionStates("secret/ca"); len(states) != 2 {
		t.Errorf("CA versions = %d, want 2 (the retry had nothing to write)", len(states))
	}
	count := 0
	for _, entry := range latestCRLV2(t, fv, "secret/ca").RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(leafA.Certificate.SerialNumber) == 0 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("the serial appears %d times on the CRL, want exactly once", count)
	}
}

// A plain sequential re-revoke of a certificate already revoked in an
// earlier, unrelated run is not the concurrent case: the plan's own
// "Rejected and deferred" list declines to skip CRL churn for an
// unchanged entry list, so this must still publish a fresh CRL -- one
// new CA version, CRL Number advanced -- exactly as it did before
// check-and-set landed.
func TestX509RevokeOfAlreadyRevokedCertStillPublishesFreshCRL(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	ca := newCA(t, "authority")
	leafA := newLeaf(t, ca, "a")
	ca.Revoke(leafA)
	storeCertV2(t, fv, "secret/ca", ca)
	storeCertV2(t, fv, "secret/a", leafA)

	beforeNumber := latestCRLV2(t, fv, "secret/ca").Number

	c := newX509CLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/ca"
	if err := c.cmdX509Revoke("x509 revoke", "secret/a"); err != nil {
		t.Fatalf("revoke of an already-revoked certificate: %v", err)
	}

	if states := fv.versionStates("secret/ca"); len(states) != 2 {
		t.Errorf("CA versions = %d, want 2 (the seed, then the fresh CRL publish)", len(states))
	}
	afterNumber := latestCRLV2(t, fv, "secret/ca").Number
	if afterNumber.Cmp(beforeNumber) <= 0 {
		t.Errorf("CRL number = %s, want it to have advanced past %s", afterNumber, beforeNumber)
	}
	count := 0
	for _, entry := range latestCRLV2(t, fv, "secret/ca").RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(leafA.Certificate.SerialNumber) == 0 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("the serial appears %d times on the CRL, want exactly once", count)
	}
}

// A CA swapped for a different authority between read and write must not
// credit the foreign CA with the revocation: the retry re-checks the
// signature against the fresh CA and refuses.
func TestX509RevokeAgainstSwappedAuthorityRefuses(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	ca := newCA(t, "authority")
	leafA := newLeaf(t, ca, "a")
	storeCertV2(t, fv, "secret/ca", ca)
	storeCertV2(t, fv, "secret/a", leafA)

	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 1, func() {
		stranger := newCA(t, "stranger")
		s, err := stranger.Secret(false)
		if err != nil {
			t.Errorf("build the stranger CA: %v", err)
			return
		}
		fv.setV2("secret/ca", secretToKV(s))
	})

	c := newX509CLI(t)
	c.opt.X509.Revoke.SignedBy = "secret/ca"
	err := c.cmdX509Revoke("x509 revoke", "secret/a")
	if err == nil {
		t.Fatal("revoke against a swapped authority = nil, want an error")
	}
	if !strings.Contains(err.Error(), "was not signed by") {
		t.Errorf("error = %q, want the was-not-signed-by refusal", err)
	}
	//The stranger's CA stands unmodified: nothing was revoked onto it.
	if got := latestCRLV2(t, fv, "secret/ca").RevokedCertificateEntries; len(got) != 0 {
		t.Errorf("the stranger's CRL gained %d entries, want none", len(got))
	}
	if states := fv.versionStates("secret/ca"); len(states) != 2 {
		t.Errorf("CA versions = %d, want 2 (seed and swap, no write of ours)", len(states))
	}
}

// renew's CA write retries the same way: fresh CA, fresh serial for the
// renewed certificate, the concurrent writer's counter respected.
func TestX509RenewRetriesAgainstFreshCA(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	ca := newCA(t, "authority")
	leafA := newLeaf(t, ca, "a") //serial 2
	storeCertV2(t, fv, "secret/ca", ca)
	storeCertV2(t, fv, "secret/a", leafA)

	//The first CA read is FindSigningCA's discovery; the second is the
	// read-modify-write's own. The competing issuance lands after the
	// second, so the CA write conflicts once.
	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 2,
		injectConcurrentIssuance(t, fv, "secret/ca"))

	c := newX509CLI(t)
	c.opt.X509.Renew.SignedBy = "secret/ca"
	captureStdout(t, func() {
		if err := c.cmdX509Renew("x509 renew", "secret/a"); err != nil {
			t.Fatalf("renew: %v", err)
		}
	})

	renewed := latestLeafCertV2(t, fv, "secret/a").SerialNumber
	counter := latestCASerialV2(t, fv, "secret/ca")
	if renewed.Cmp(counter) != 0 {
		t.Errorf("renewed serial %s != persisted counter %s: the retry did not re-draw against fresh state", renewed, counter)
	}
	//Counter path: seeded at 2, concurrent issuance takes 3, the renewed
	// certificate must carry 4.
	if renewed.Cmp(big.NewInt(4)) != 0 {
		t.Errorf("renewed serial = %s, want 4 (past the concurrent writer's 3)", renewed)
	}
	if gets, puts := v2DataTraffic(fv, "ca"); gets != 3 || puts != 2 {
		t.Errorf("CA traffic = %d GETs, %d PUTs; want 3 (discovery + two attempts) and 2", gets, puts)
	}
}

// reissue -- new key, then the same guarded CA write -- retries against
// the fresh CA too, and the regenerated key is not drawn again for it.
func TestX509ReissueRetriesAgainstFreshCA(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	ca := newCA(t, "authority")
	leafA := newLeaf(t, ca, "a")
	storeCertV2(t, fv, "secret/ca", ca)
	storeCertV2(t, fv, "secret/a", leafA)

	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 2,
		injectConcurrentIssuance(t, fv, "secret/ca"))

	c := newX509CLI(t)
	c.opt.X509.Reissue.SignedBy = "secret/ca"
	//An EC key keeps the regeneration cheap; reissue would otherwise
	// preserve the fixture's RSA parameters.
	c.opt.X509.Reissue.Type = "ec"
	captureStdout(t, func() {
		if err := c.cmdX509Reissue("x509 reissue", "secret/a"); err != nil {
			t.Fatalf("reissue: %v", err)
		}
	})

	reissued := latestLeafCertV2(t, fv, "secret/a")
	counter := latestCASerialV2(t, fv, "secret/ca")
	if reissued.SerialNumber.Cmp(counter) != 0 {
		t.Errorf("reissued serial %s != persisted counter %s", reissued.SerialNumber, counter)
	}
	if reissued.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("reissued certificate carries %s, want the regenerated ECDSA key", reissued.PublicKeyAlgorithm)
	}
	if gets, puts := v2DataTraffic(fv, "ca"); gets != 3 || puts != 2 {
		t.Errorf("CA traffic = %d GETs, %d PUTs; want 3 and 2", gets, puts)
	}
}

// A CA swapped for a different key type mid-retry must not carry the
// first attempt's signature-algorithm choice into the second: reissue
// resets it to Unknown before every attempt's Sign call, so the retry
// re-derives from the fresh (here, EC) CA's key instead of validating a
// now-incompatible RSA-derived choice against it.
func TestX509ReissueAdaptsSignatureAlgorithmToCAKeySwap(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	ca := newCA(t, "authority")
	leafA := newLeaf(t, ca, "a")
	storeCertV2(t, fv, "secret/ca", ca)
	storeCertV2(t, fv, "secret/a", leafA)

	ecCA := newECCA(t, "authority-ec")
	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 2,
		injectConcurrentCAKeySwap(t, fv, "secret/ca", ecCA))

	c := newX509CLI(t)
	c.opt.X509.Reissue.SignedBy = "secret/ca"
	captureStdout(t, func() {
		if err := c.cmdX509Reissue("x509 reissue", "secret/a"); err != nil {
			t.Fatalf("reissue after a CA key swap: %v", err)
		}
	})

	reissued := latestLeafCertV2(t, fv, "secret/a")
	if reissued.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("reissued signature algorithm = %s, want ECDSA-with-SHA256 derived from the swapped CA's key", reissued.SignatureAlgorithm)
	}
}

// renew resets the same way, matching reissue: the identical mid-retry
// CA-key-swap hazard gets the identical answer in both commands.
func TestX509RenewAdaptsSignatureAlgorithmToCAKeySwap(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	ca := newCA(t, "authority")
	leafA := newLeaf(t, ca, "a")
	storeCertV2(t, fv, "secret/ca", ca)
	storeCertV2(t, fv, "secret/a", leafA)

	ecCA := newECCA(t, "authority-ec")
	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 2,
		injectConcurrentCAKeySwap(t, fv, "secret/ca", ecCA))

	c := newX509CLI(t)
	c.opt.X509.Renew.SignedBy = "secret/ca"
	captureStdout(t, func() {
		if err := c.cmdX509Renew("x509 renew", "secret/a"); err != nil {
			t.Fatalf("renew after a CA key swap: %v", err)
		}
	})

	renewed := latestLeafCertV2(t, fv, "secret/a")
	if renewed.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("renewed signature algorithm = %s, want ECDSA-with-SHA256 derived from the swapped CA's key", renewed.SignatureAlgorithm)
	}
}

// crl --renew is the smallest CA read-modify-write; a concurrent
// revocation landing mid-flight survives into the regenerated list.
func TestX509CrlRenewKeepsConcurrentRevocation(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	ca := newCA(t, "authority")
	victim := newLeaf(t, ca, "victim")
	storeCertV2(t, fv, "secret/ca", ca)

	fv.afterRequest(`^GET /v1/secret/data/ca(\?.*)?$`, 1,
		injectConcurrentRevocation(t, fv, "secret/ca", victim))

	c := newX509CLI(t)
	c.opt.X509.CRL.Renew = true
	if err := c.cmdX509Crl("x509 crl", "secret/ca"); err != nil {
		t.Fatalf("crl --renew: %v", err)
	}

	crl := latestCRLV2(t, fv, "secret/ca")
	found := false
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(victim.Certificate.SerialNumber) == 0 {
			found = true
		}
	}
	if !found {
		t.Error("the concurrent revocation was dropped by the regenerated CRL")
	}
	if gets, puts := v2DataTraffic(fv, "ca"); gets != 2 || puts != 2 {
		t.Errorf("CA traffic = %d GETs, %d PUTs; want exactly 2 and 2", gets, puts)
	}
}
