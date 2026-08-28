package cli

// The keygen-family commands -- gen, ssh, rsa, dhparam, uuid, fmt, and
// set/ask/paste -- write under check-and-set on KV v2 mounts: a key some
// other process writes between a command's read and its write now
// survives, where it used to be silently overwritten. Each test here
// plays that concurrent writer through the fake's afterRequest hook and
// asserts three things: the concurrent key is in the final secret, the
// exchange cost exactly one extra read and one refused write, and the
// non-repeatable work -- key generation, operator prompting -- happened
// once, pinned by comparing what the refused write carried against what
// the retry carried. Generation seams live in pkg/vault and are not
// reachable from this package, so on-the-wire material equality is the
// proof used here; the seam-counted versions of these cases live in
// pkg/vault/update_gen_once_test.go.

import (
	"strings"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/prompt"
)

// injectConcurrentV2Write returns a hook fn that appends a new version at
// path holding the current latest data plus extra -- what a concurrent
// safe process's own read-modify-write would leave.
func injectConcurrentV2Write(fv *cliFakeVault, path string, extra map[string]string) func() {
	return func() {
		fv.mu.Lock()
		merged := map[string]string{}
		if history := fv.versions[path]; len(history) > 0 {
			for k, v := range history[len(history)-1].data {
				merged[k] = v
			}
		}
		for k, v := range extra {
			merged[k] = v
		}
		fv.appendVersionLocked(path, merged)
		fv.mu.Unlock()
	}
}

// v2DataTraffic counts data reads and writes for one secret name under
// the fake's v2 mount.
func v2DataTraffic(fv *cliFakeVault, name string) (gets, puts int) {
	for _, r := range fv.requests() {
		switch {
		case strings.HasPrefix(r, "GET /v1/secret/data/"+name):
			gets++
		case strings.HasPrefix(r, "PUT /v1/secret/data/"+name),
			strings.HasPrefix(r, "POST /v1/secret/data/"+name):
			puts++
		}
	}
	return gets, puts
}

// latestV2 returns the newest version's data at a literal path.
func latestV2(t *testing.T, fv *cliFakeVault, path string) map[string]string {
	t.Helper()
	fv.mu.Lock()
	defer fv.mu.Unlock()
	history := fv.versions[path]
	if len(history) == 0 {
		t.Fatalf("no versions at %s", path)
	}
	cp := map[string]string{}
	for k, v := range history[len(history)-1].data {
		cp[k] = v
	}
	return cp
}

// A conflict in the middle of a gen group's write chain retries just the
// unpersisted tail: all four generated keys land, the concurrent writer's
// key survives, and the history counts five versions -- four of ours, one
// of theirs -- with no version wasted re-writing what already persisted.
func TestCmdGenChainRetriesAfterConflict(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)

	fv.afterRequest(`^PUT /v1/secret/data/x$`, 2,
		injectConcurrentV2Write(fv, "secret/x", map[string]string{"theirs": "y"}))

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy

	if err := c.cmdGen("gen", "16",
		"secret/x", "a", "secret/x", "b", "secret/x", "c", "secret/x", "d"); err != nil {
		t.Fatalf("cmdGen: %v", err)
	}

	if states := fv.versionStates("secret/x"); len(states) != 5 {
		t.Fatalf("version count = %d, want 5 (four generated keys plus the concurrent write)", len(states))
	}
	got := latestV2(t, fv, "secret/x")
	if got["theirs"] != "y" {
		t.Errorf("concurrent key lost: final secret = %v", got)
	}
	for _, k := range []string{"a", "b", "c", "d"} {
		if len(got[k]) != 16 {
			t.Errorf("generated key %s = %q, want a 16-character password", k, got[k])
		}
	}
	if gets, puts := v2DataTraffic(fv, "x"); gets != 2 || puts != 5 {
		t.Errorf("data traffic = %d GETs, %d PUTs; want 2 and 5 (four landed, one refused)", gets, puts)
	}
}

// --no-clobber re-decides on the retry: a key the conflict revealed to
// have been written concurrently is refused, its notice emitted once, and
// the concurrent value stands.
func TestCmdGenNoClobberRefusesKeyWrittenConcurrently(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)

	//The path does not exist yet, so the create consults the metadata;
	// the concurrent create lands right after that consultation, which
	// makes our cas=0 write conflict.
	fv.afterRequest(`^GET /v1/secret/metadata/x$`, 1,
		injectConcurrentV2Write(fv, "secret/x", map[string]string{"a": "keepme"}))

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	c.opt.SkipIfExists = true

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdGen("gen", "16", "secret/x", "a")
	})
	if err != nil {
		t.Fatalf("cmdGen: %v", err)
	}
	if got := latestV2(t, fv, "secret/x"); got["a"] != "keepme" {
		t.Errorf("secret/x[a] = %q, want the concurrent writer's value to stand", got["a"])
	}
	if states := fv.versionStates("secret/x"); len(states) != 1 {
		t.Errorf("version count = %d, want 1 (only the concurrent create)", len(states))
	}
	if n := strings.Count(stderr, "secret/x:a"); n != 1 {
		t.Errorf("refusal notice for secret/x:a appeared %d times, want exactly once\n---\n%s", n, stderr)
	}
}

// A --no-clobber skip notice from before a conflict is neither erased nor
// duplicated by the retry: it appears exactly once.
func TestCmdGenSkipNoticeSurvivesLaterConflict(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/x", map[string]string{"a": "existing"})

	fv.afterRequest(`^GET /v1/secret/data/x(\?.*)?$`, 1,
		injectConcurrentV2Write(fv, "secret/x", map[string]string{"theirs": "y"}))

	c := newKeygenCLI(t)
	c.opt.Gen.Policy = defaultGenPolicy
	c.opt.SkipIfExists = true

	var err error
	stderr := captureStderr(t, func() {
		err = c.cmdGen("gen", "16", "secret/x", "a", "secret/x", "b")
	})
	if err != nil {
		t.Fatalf("cmdGen: %v", err)
	}
	if n := strings.Count(stderr, "secret/x:a"); n != 1 {
		t.Errorf("skip notice for secret/x:a appeared %d times, want exactly once\n---\n%s", n, stderr)
	}
	got := latestV2(t, fv, "secret/x")
	if got["a"] != "existing" || got["theirs"] != "y" || len(got["b"]) != 16 {
		t.Errorf("final secret = %v, want the skipped value, the concurrent key, and the generated key", got)
	}
}

// An SSH keypair is generated exactly once across a conflict retry: the
// refused write and the landed one carry the identical private key, and
// the concurrent writer's key survives.
func TestCmdSshRetryKeepsConcurrentKeyAndGeneratesOnce(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/x", map[string]string{"other": "x"})

	fv.afterRequest(`^GET /v1/secret/data/x(\?.*)?$`, 1,
		injectConcurrentV2Write(fv, "secret/x", map[string]string{"theirs": "y"}))

	c := newKeygenCLI(t)
	if err := c.cmdSsh("ssh", "1024", "secret/x"); err != nil {
		t.Fatalf("cmdSsh: %v", err)
	}

	got := latestV2(t, fv, "secret/x")
	for _, k := range []string{"private", "public", "fingerprint"} {
		if got[k] == "" {
			t.Errorf("final secret is missing %s", k)
		}
	}
	if got["theirs"] != "y" || got["other"] != "x" {
		t.Errorf("concurrent keys lost: final secret keys = %v", keysOf(got))
	}
	if gets, puts := v2DataTraffic(fv, "x"); gets != 2 || puts != 2 {
		t.Errorf("data traffic = %d GETs, %d PUTs; want 2 and 2", gets, puts)
	}
	bodies := fv.putDataBodies("secret/x")
	if len(bodies) != 2 || bodies[0]["private"] == "" || bodies[0]["private"] != bodies[1]["private"] {
		t.Errorf("the refused and retried writes carried different private keys: the keypair was generated more than once")
	}
}

// Same for RSA keypairs.
func TestCmdRsaRetryKeepsConcurrentKeyAndGeneratesOnce(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/x", map[string]string{"other": "x"})

	fv.afterRequest(`^GET /v1/secret/data/x(\?.*)?$`, 1,
		injectConcurrentV2Write(fv, "secret/x", map[string]string{"theirs": "y"}))

	c := newKeygenCLI(t)
	if err := c.cmdRsa("rsa", "1024", "secret/x"); err != nil {
		t.Fatalf("cmdRsa: %v", err)
	}

	got := latestV2(t, fv, "secret/x")
	if got["private"] == "" || got["public"] == "" || got["theirs"] != "y" {
		t.Errorf("final secret keys = %v, want the keypair beside the concurrent key", keysOf(got))
	}
	bodies := fv.putDataBodies("secret/x")
	if len(bodies) != 2 || bodies[0]["private"] == "" || bodies[0]["private"] != bodies[1]["private"] {
		t.Errorf("the refused and retried writes carried different private keys: the keypair was generated more than once")
	}
}

// Diffie-Hellman parameters -- minutes of openssl at real sizes -- are
// generated exactly once across a conflict retry. This pays for a real
// 1024-bit openssl run, same as the other dhparam tests: the generator
// seam lives in pkg/vault and is not reachable from here.
func TestCmdDhparamRetryKeepsConcurrentKeyAndGeneratesOnce(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/x", map[string]string{"other": "x"})

	fv.afterRequest(`^GET /v1/secret/data/x(\?.*)?$`, 1,
		injectConcurrentV2Write(fv, "secret/x", map[string]string{"theirs": "y"}))

	c := newKeygenCLI(t)
	if err := c.cmdDhparam("dhparam", "1024", "secret/x"); err != nil {
		t.Fatalf("cmdDhparam: %v", err)
	}

	got := latestV2(t, fv, "secret/x")
	if !strings.Contains(got["dhparam-pem"], "BEGIN DH PARAMETERS") || got["theirs"] != "y" {
		t.Errorf("final secret keys = %v, want the parameter set beside the concurrent key", keysOf(got))
	}
	bodies := fv.putDataBodies("secret/x")
	if len(bodies) != 2 || bodies[0]["dhparam-pem"] == "" || bodies[0]["dhparam-pem"] != bodies[1]["dhparam-pem"] {
		t.Errorf("the refused and retried writes carried different parameter sets: dhparam ran more than once")
	}
}

// The uuid is drawn before the write loop, so the retry re-installs the
// same one.
func TestCmdUuidRetryKeepsConcurrentKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/x", map[string]string{"other": "x"})

	fv.afterRequest(`^GET /v1/secret/data/x(\?.*)?$`, 1,
		injectConcurrentV2Write(fv, "secret/x", map[string]string{"theirs": "y"}))

	c := newKeygenCLI(t)
	if err := c.cmdUuid("uuid", "secret/x"); err != nil {
		t.Fatalf("cmdUuid: %v", err)
	}

	got := latestV2(t, fv, "secret/x")
	if len(got["uuid"]) != 36 || got["theirs"] != "y" {
		t.Errorf("final secret = %v, want a uuid beside the concurrent key", got)
	}
	bodies := fv.putDataBodies("secret/x")
	if len(bodies) != 2 || bodies[0]["uuid"] != bodies[1]["uuid"] {
		t.Errorf("the refused and retried writes carried different uuids, want the same one re-installed")
	}
}

// fmt re-derives its encoding against the retry's fresh state and the
// concurrent key survives.
func TestCmdFmtRetryKeepsConcurrentKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/x", map[string]string{"password": "hunter2"})

	fv.afterRequest(`^GET /v1/secret/data/x(\?.*)?$`, 1,
		injectConcurrentV2Write(fv, "secret/x", map[string]string{"theirs": "y"}))

	c := newTestCLI(t)
	if err := c.cmdFmt("fmt", "base64", "secret/x", "password", "password-b64"); err != nil {
		t.Fatalf("cmdFmt: %v", err)
	}

	got := latestV2(t, fv, "secret/x")
	if got["password-b64"] != "aHVudGVyMg==" || got["theirs"] != "y" {
		t.Errorf("final secret = %v, want the encoded copy beside the concurrent key", got)
	}
	if gets, puts := v2DataTraffic(fv, "x"); gets != 2 || puts != 2 {
		t.Errorf("data traffic = %d GETs, %d PUTs; want 2 and 2", gets, puts)
	}
}

// set's values are collected once; the retry re-applies them against
// fresh state.
func TestCmdSetRetryKeepsConcurrentKey(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/x", map[string]string{"other": "x"})

	fv.afterRequest(`^GET /v1/secret/data/x(\?.*)?$`, 1,
		injectConcurrentV2Write(fv, "secret/x", map[string]string{"theirs": "y"}))

	c := newTestCLI(t)
	captureStderr(t, func() {
		if err := c.cmdSet("set", "secret/x", "k=v"); err != nil {
			t.Fatalf("cmdSet: %v", err)
		}
	})

	got := latestV2(t, fv, "secret/x")
	if got["k"] != "v" || got["theirs"] != "y" || got["other"] != "x" {
		t.Errorf("final secret = %v, want the set key beside both concurrent keys", got)
	}
	if gets, puts := v2DataTraffic(fv, "x"); gets != 2 || puts != 2 {
		t.Errorf("data traffic = %d GETs, %d PUTs; want 2 and 2", gets, puts)
	}
}

// ask prompts the operator exactly once: the reader feeds one value, and
// a second prompt would fail on the exhausted reader. The retried write
// carries the same collected value.
func TestCmdAskUnderConflictPromptsOnce(t *testing.T) {
	isolateHome(t)
	fv := newCLIFakeV2(t)
	fv.setV2("secret/x", map[string]string{"other": "x"})

	fv.afterRequest(`^GET /v1/secret/data/x(\?.*)?$`, 1,
		injectConcurrentV2Write(fv, "secret/x", map[string]string{"theirs": "y"}))

	prompt.SetReader(strings.NewReader("s3cr3t\n"))
	t.Cleanup(func() { prompt.SetReader(nil) })

	c := newTestCLI(t)
	captureStderr(t, func() {
		if err := c.cmdAsk("ask", "secret/x", "newkey"); err != nil {
			t.Fatalf("cmdAsk: %v", err)
		}
	})

	got := latestV2(t, fv, "secret/x")
	if got["newkey"] != "s3cr3t" || got["theirs"] != "y" {
		t.Errorf("final secret = %v, want the prompted value beside the concurrent key", got)
	}
	bodies := fv.putDataBodies("secret/x")
	if len(bodies) != 2 || bodies[0]["newkey"] != "s3cr3t" || bodies[1]["newkey"] != "s3cr3t" {
		t.Errorf("write bodies = %v, want the once-prompted value in both attempts", bodies)
	}
}

// keysOf returns just the key names, for failure messages that must not
// leak generated key material into test logs.
func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
