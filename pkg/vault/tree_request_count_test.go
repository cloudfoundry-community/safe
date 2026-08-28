package vault_test

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cloudfoundry-community/safe/pkg/vault"
)

// A latest-only keyed walk (what `safe export` without --all runs) must
// cost one data GET per alive secret and zero leaf metadata GETs. The
// fixture deliberately has two sub-directories so directory LISTs cannot
// mask a stray metadata GET. kv2/app/creds is written twice so the test
// also pins that the fast path reports the newest version's number and
// values, not a hardcoded version 1 or the wrong write.
func TestLatestOnlyKeyedWalkSkipsMetadataReads(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/app/creds",
		map[string]string{"user": "old", "pass": "old"},
		map[string]string{"user": "u", "pass": "p"})
	fv.setV2("kv2/app/tls", map[string]string{"cert": "c"})
	fv.setV2("kv2/svc/token", map[string]string{"x": "y"})
	fv.setV2("kv2/empty", map[string]string{})

	fv.resetRequestLog()
	secrets, err := v.ConstructSecrets("kv2", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}
	if len(secrets) != 4 {
		t.Fatalf("walked %d secrets, want 4 (empty secret must survive)", len(secrets))
	}
	var creds *vault.SecretEntry
	for i := range secrets {
		s := &secrets[i]
		if len(s.Versions) != 1 {
			t.Errorf("secret %s: %d versions, want 1", s.Path, len(s.Versions))
		}
		if s.Path == "kv2/app/creds" {
			creds = s
		}
	}
	if creds == nil {
		t.Fatal("kv2/app/creds missing from walk")
	}
	if got := creds.Versions[0].Number; got != 2 {
		t.Errorf("kv2/app/creds version = %d, want 2 (the newest write)", got)
	}
	if got := creds.Versions[0].Data.Get("user"); got != "u" {
		t.Errorf("kv2/app/creds user = %q, want %q (the newest write)", got, "u")
	}
	if got := creds.Versions[0].Data.Get("pass"); got != "p" {
		t.Errorf("kv2/app/creds pass = %q, want %q (the newest write)", got, "p")
	}

	// Non-list metadata GETs (`GET /v1/kv2/metadata/<leaf>`, no query).
	// LISTs carry ?list=true and the root probe logs as /v1/kv2/metadata
	// with no trailing segment; neither matches this pattern.
	if got := fv.requestCount(`^GET /v1/kv2/metadata/[^?]+$`); got != 0 {
		t.Errorf("leaf metadata GETs = %d, want 0", got)
	}
	// kv2/app/creds has two versions on the backend, but the fast path
	// still costs exactly one data GET for it: one per alive secret, four
	// total, regardless of how many versions any one of them has.
	if got := fv.requestCount(`^GET /v1/kv2/data/`); got != 4 {
		t.Errorf("data GETs = %d, want 4", got)
	}
}

// A secret living at a mount's own root, not merely under it, must also
// take the one-request fast path. Mounts() reports mount names with a
// trailing slash, and workMounts carries that name verbatim onto the
// secret node it builds for a mount-root secret, so readLatestWithMeta
// has to canonicalize its path the same way every other Vault path-taking
// method here does, or a mount-root secret's fast-path read is built from
// an uncanonicalized path.
func TestLatestOnlyKeyedWalkReadsAV2MountRootSecretInOneRequest(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2", map[string]string{"k": "v"})
	fv.setV2("kv2/below", map[string]string{"k": "v"})

	fv.resetRequestLog()
	secrets, err := v.ConstructSecrets("/", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}

	var root *vault.SecretEntry
	for i := range secrets {
		if secrets[i].Path == "kv2" {
			root = &secrets[i]
		}
	}
	if root == nil {
		t.Fatalf("mount-root secret kv2 missing from walk: %v", secrets.Paths())
	}
	if len(root.Versions) != 1 || root.Versions[0].Data.Get("k") != "v" {
		t.Errorf("kv2 versions = %+v, want one version with k=v", root.Versions)
	}

	// Same exclusion as the sibling test above: a directory LIST logs as
	// /v1/kv2/metadata?list=true, which this pattern does not match.
	if got := fv.requestCount(`^GET /v1/kv2/metadata/[^?]+$`); got != 0 {
		t.Errorf("mount-root metadata GETs = %d, want 0", got)
	}
	// Anchored to exactly the mount-root data path, with nothing after it,
	// so a listing of kv2/below cannot be mistaken for it.
	if got := fv.requestCount(`^GET /v1/kv2/data$`); got != 1 {
		t.Errorf("mount-root data GETs = %d, want 1 (a single clean read, "+
			"not a malformed one that fell back):\n%s",
			got, strings.Join(fv.reqLog, "\n"))
	}
}

// A deleted latest version must be handled exactly as before: the fast
// path 404s, falls back to the metadata flow, and the secret is purged
// (default) or retained without keys (AllowDeletedSecrets).
func TestLatestOnlyKeyedWalkDeletedLatestFallback(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/alive", map[string]string{"k": "v"})
	fv.setV2("kv2/gone", map[string]string{"k": "v"})
	fv.deleteV2("kv2/gone", 1)

	secrets, err := v.ConstructSecrets("kv2", vault.TreeOpts{FetchKeys: true})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Path != "kv2/alive" {
		t.Fatalf("got %v, want just kv2/alive", secrets.Paths())
	}

	allowed, err := v.ConstructSecrets("kv2", vault.TreeOpts{
		FetchKeys:           true,
		AllowDeletedSecrets: true,
	})
	if err != nil {
		t.Fatalf("ConstructSecrets (allow deleted): %v", err)
	}
	if len(allowed) != 2 {
		t.Fatalf("allow-deleted walk found %d secrets, want 2", len(allowed))
	}
}

// A token that can list and read metadata but not read data must leave the
// secret visible with an empty version and count one forbidden skip,
// exactly as the two-request flow does today.
func TestLatestOnlyKeyedWalkForbiddenDataFallback(t *testing.T) {
	v, fv := newTestVault(t)
	fv.mountV2("kv2")
	fv.setV2("kv2/open", map[string]string{"k": "v"})
	fv.setV2("kv2/sealed", map[string]string{"k": "v"})
	fv.forbid("kv2/sealed")

	var skipped atomic.Uint64
	secrets, err := v.ConstructSecrets("kv2", vault.TreeOpts{
		FetchKeys:        true,
		SkippedForbidden: &skipped,
	})
	if err != nil {
		t.Fatalf("ConstructSecrets: %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("walked %d secrets, want 2 (forbidden-data secret must survive)", len(secrets))
	}
	if skipped.Load() != 1 {
		t.Errorf("forbidden skips = %d, want 1", skipped.Load())
	}
}
