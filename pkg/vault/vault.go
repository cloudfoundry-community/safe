package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudfoundry-community/safe/internal/parallel"
	"github.com/cloudfoundry-community/vaultkv"
	"github.com/jhunt/go-ansi"
)

type Vault struct {
	client *vaultkv.KV
	debug  bool

	// versionsMu guards versionsCache, which memoizes Versions per literal
	// Vault path for the life of the process. The tree walk runs NumCPU
	// workers concurrently calling Versions, so this must be race-safe.
	versionsMu    sync.RWMutex
	versionsCache map[string][]vaultkv.KVVersion
	// versionsGen counts invalidations per path, and versionsEpoch counts
	// whole-cache flushes (Curl's non-GET/HEAD case, which cannot be
	// resolved to one path). Versions snapshots both before its network
	// fetch and only stores the result if neither moved while the fetch was
	// in flight: a fetch that straddles an invalidation -- a slow reader
	// racing a concurrent write -- would otherwise be free to store its
	// pre-mutation snapshot into the cache AFTER the mutation's own
	// invalidation already ran, and nothing would ever clear it again. A
	// plain "was there a cache entry at path X" check at store time cannot
	// catch this: an over-called invalidateVersions may have already run
	// and left no entry to compare against, or an unrelated Curl flush may
	// have moved the epoch without ever touching this path's gen. -race
	// cannot see this: it is a logical race between requests, not a data
	// race on memory, since every access here is already lock-guarded.
	versionsGen   map[string]uint64
	versionsEpoch uint64

	// casSleep waits out the backoff between Update/UpdateSteps retry
	// passes; a seam so tests assert requested waits instead of serving
	// them. See sleepBeforeRetry.
	casSleep func(ctx context.Context, d time.Duration) error
}

type VaultConfig struct {
	URL        string
	Token      string
	Namespace  string
	CACerts    *x509.CertPool
	SkipVerify bool
}

// CanonicalURL applies the scheme-default-port normalization NewVault uses
// when building a client's VaultURL, so callers can compare a client's live
// URL against a raw address without duplicating that logic.
func CanonicalURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil {
		return "", fmt.Errorf("could not parse Vault URL: %w", err)
	}

	//The default port for Vault is typically 8200 (which is the VaultKV default),
	// but safe has historically ignored that and used the default http or https
	// port, depending on which was specified as the scheme
	if u.Port() == "" {
		port := ":80"
		if strings.ToLower(u.Scheme) == "https" {
			port = ":443"
		}
		u.Host = u.Host + port
	}
	return u.String(), nil
}

// NewVault creates a new Vault object.  If an empty token is specified,
// the current user's token is read from ~/.vault-token.
func NewVault(conf VaultConfig) (*Vault, error) {
	var err error
	if conf.CACerts == nil {
		// x509.SystemCertPool is not implemented for windows currently.
		// If nil is supplied for RootCAs, the system will verify the certs as per
		// https://golang.org/src/crypto/x509/verify.go (Line 741)
		conf.CACerts, err = x509.SystemCertPool()
		if err != nil && runtime.GOOS != "windows" {
			return nil, fmt.Errorf("unable to retrieve system root certificate authorities: %w", err)
		}
	}
	canonical, err := CanonicalURL(conf.URL)
	if err != nil {
		return nil, err
	}
	vaultURL, err := url.Parse(canonical)
	if err != nil {
		return nil, fmt.Errorf("could not parse Vault URL: %w", err)
	}

	proxyRouter, err := NewProxyRouter()
	if err != nil {
		return nil, fmt.Errorf("error setting up proxy: %w", err)
	}

	if conf.SkipVerify {
		_, _ = ansi.Fprintf(os.Stderr, "@Y{WARNING: TLS certificate verification disabled — connections to Vault are not authenticated}\n")
	}

	return &Vault{
		client: (&vaultkv.Client{
			VaultURL:  vaultURL,
			AuthToken: conf.Token,
			Namespace: conf.Namespace,
			Client: &http.Client{
				Timeout: 30 * time.Second,
				Transport: newRetryTransport(&http.Transport{
					Proxy: proxyRouter.Proxy,
					DialContext: (&net.Dialer{
						Timeout:   10 * time.Second,
						KeepAlive: 30 * time.Second,
					}).DialContext,
					ForceAttemptHTTP2:     true,
					TLSHandshakeTimeout:   10 * time.Second,
					IdleConnTimeout:       90 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
					MaxIdleConnsPerHost:   100,
					TLSClientConfig: &tls.Config{
						RootCAs:            conf.CACerts,
						InsecureSkipVerify: conf.SkipVerify, // #nosec G402 - User-controlled via config for development/testing
						ClientSessionCache: tls.NewLRUClientSessionCache(32),
					},
				}),
			},
			Trace: func() (ret io.Writer) {
				if shouldDebug() {
					ret = os.Stderr
				}
				return ret
			}(),
		}).NewKV(),
		debug:         shouldDebug(),
		versionsCache: map[string][]vaultkv.KVVersion{},
		versionsGen:   map[string]uint64{},
		casSleep:      sleepBackoff,
	}, nil
}

func (v *Vault) Client() *vaultkv.KV {
	return v.client
}

func (v *Vault) MountVersion(path string) (uint, error) {
	path = Canonicalize(path)
	return v.client.MountVersion(path)
}

// Versions returns the version history of the secret at path, caching the
// result per literal Vault path for the life of the process. Every caller
// gets its own clone, since the tree walk re-slices the result across
// NumCPU concurrent workers. Errors are never cached: a not-found is often
// immediately followed by a create, and caching that miss would hide it.
func (v *Vault) Versions(path string) ([]vaultkv.KVVersion, error) {
	path = Canonicalize(path)

	v.versionsMu.RLock()
	cached, ok := v.versionsCache[path]
	gen := v.versionsGen[path]
	epoch := v.versionsEpoch
	v.versionsMu.RUnlock()
	if ok {
		return slices.Clone(cached), nil
	}

	ret, err := v.client.Versions(path)
	if vaultkv.IsNotFound(err) {
		return nil, NewSecretNotFoundError(path)
	}
	if err != nil {
		return ret, err
	}

	v.versionsMu.Lock()
	// Store only if nothing invalidated this path (or flushed the whole
	// cache) while the fetch above was in flight. Either would mean this
	// result was read before a concurrent mutation and must not be allowed
	// to resurrect as the cached value after that mutation's own
	// invalidation already ran.
	if v.versionsGen[path] == gen && v.versionsEpoch == epoch {
		v.versionsCache[path] = ret
	}
	v.versionsMu.Unlock()

	return slices.Clone(ret), nil
}

// invalidateVersions drops the cached history for a literal Vault path and
// bumps its generation, so a fetch already in flight for it will not store
// a stale result once it completes. Canonicalize only: ParsePath would
// truncate a literal ':' in a name. Cheap to over-call; correctness only
// requires that every mutation path calls it.
func (v *Vault) invalidateVersions(path string) {
	path = Canonicalize(path)
	v.versionsMu.Lock()
	delete(v.versionsCache, path)
	v.versionsGen[path]++
	v.versionsMu.Unlock()
}

// UndeleteVersions undeletes the named versions of a secret at a literal
// Vault path, invalidating any cached version history for it.
func (v *Vault) UndeleteVersions(path string, versions []uint) error {
	defer v.invalidateVersions(path)
	return v.client.Undelete(Canonicalize(path), versions)
}

func shouldDebug() bool {
	d := strings.ToLower(os.Getenv("DEBUG"))
	return d != "" && d != "false" && d != "0" && d != "no" && d != "off"
}

// Curl sends one request to the Vault API. Only the path of the URI is
// canonicalized: the rules for a secret path -- collapse repeated slashes,
// drop a trailing one -- were run over the whole string, query and all, so a
// query carrying a URL was sent with its slashes collapsed, ?u=http://a/b
// arriving as ?u=http:/a/b, and a value ending in a slash arrived without it.
//
// Curl's path is an arbitrary API URI, not necessarily a secret path (it can
// address sys/, auth/, anything), so it cannot be resolved to a single cache
// key the way every other mutating method here is. A non-GET/HEAD method is
// assumed capable of mutating some secret's version history, and flushes the
// whole cache rather than guessing which key. The flush runs regardless of
// the call's outcome: a PUT that fails partway through Vault's own request
// handling can still have applied.
func (v *Vault) Curl(method string, path string, body []byte) (*http.Response, error) {
	u, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("could not parse input path: %w", err)
	}

	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("could not parse query: %w", err)
	}

	if !strings.EqualFold(method, "GET") && !strings.EqualFold(method, "HEAD") {
		defer func() {
			v.versionsMu.Lock()
			clear(v.versionsCache)
			// Bumped alongside the clear, not just the clear alone: a path
			// this Curl call touched but that was never previously
			// invalidated has no versionsGen entry yet, so its gen would
			// still read as the same zero value before and after a bare
			// clear -- indistinguishable from "nothing happened" to a
			// fetch racing this call. The epoch has no such default-value
			// collision, since every Versions call reads it fresh under
			// the same lock this increment holds.
			v.versionsEpoch++
			v.versionsMu.Unlock()
		}()
	}

	return v.client.Client.Curl(method, Canonicalize(u.Path), query, bytes.NewBuffer(body))
}

// Read checks the Vault for a Secret at the specified path, and returns it.
// The returned *Secret is never nil. A missing secret and a missing key are
// both reported through err, as SecretNotFound and KeyNotFound respectively,
// alongside an empty Secret; every Secret method dereferences its receiver,
// so a caller that tolerates a not-found error can still use the value.
func (v *Vault) Read(path string) (secret *Secret, err error) {
	path, key, version := ParsePath(path)

	secret = NewSecret()

	raw := map[string]any{}
	_, err = v.client.Get(path, &raw, &vaultkv.KVGetOpts{Version: uint(version)})
	if err != nil {
		if vaultkv.IsNotFound(err) {
			err = v.notFoundReading(path, version)
		}
		return
	}

	err = fillSecretFromRaw(secret, raw, path, key)
	return
}

// fillSecretFromRaw copies a raw data map into secret, re-marshalling any
// non-string values back to JSON. A non-empty key keeps only that key, and
// reports a KeyNotFoundError when the map does not hold it.
func fillSecretFromRaw(secret *Secret, raw map[string]any, path, key string) error {
	if key != "" {
		val, found := raw[key]
		if !found {
			return NewKeyNotFoundError(path, key)
		}
		raw = map[string]any{key: val}
	}

	for k, v := range raw {
		if s, ok := v.(string); ok {
			secret.data[k] = s
		} else {
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			secret.data[k] = string(b)
		}
	}

	return nil
}

// readWithVersion is Read for a read-modify-write: the same path parsing,
// the same not-found translation, but it also returns the KV version the
// data endpoint reported alongside the data -- which is what a
// check-and-set write needs to name. On a v1 mount the version is
// meaningless (vaultkv reports 1) and callers must not send it anywhere.
func (v *Vault) readWithVersion(path string) (secret *Secret, version uint, err error) {
	path, key, ver := ParsePath(path)

	secret = NewSecret()

	raw := map[string]any{}
	meta, err := v.client.Get(path, &raw, &vaultkv.KVGetOpts{Version: uint(ver)})
	if err != nil {
		if vaultkv.IsNotFound(err) {
			err = v.notFoundReading(path, ver)
		}
		return secret, 0, err
	}

	if err := fillSecretFromRaw(secret, raw, path, key); err != nil {
		return secret, 0, err
	}
	return secret, meta.Version, nil
}

// readLatestWithMeta reads the newest live version of a secret in one
// request, also returning the KVVersion metadata the data endpoint
// carries. Unlike Read it takes a LITERAL Vault path: no key or version
// syntax, no unescaping -- but it still canonicalizes slashes, same as
// every other path-taking method here, so a mount-root secret name (which
// Mounts returns with a trailing slash) reads correctly. On a v1 mount the
// returned metadata carries only Version==1 and its Deleted/Destroyed
// fields are meaningless; callers must gate on mount version first.
func (v *Vault) readLatestWithMeta(path string) (*Secret, vaultkv.KVVersion, error) {
	path = Canonicalize(path)
	secret := NewSecret()
	raw := map[string]any{}
	meta, err := v.client.Get(path, &raw, nil)
	if err != nil {
		return secret, meta, err
	}
	for k, val := range raw {
		if s, ok := val.(string); ok {
			secret.data[k] = s
			continue
		}
		b, merr := json.Marshal(val)
		if merr != nil {
			return secret, meta, merr
		}
		secret.data[k] = string(b)
	}
	return secret, meta, nil
}

// notFoundReading turns a 404 from a read into the most specific not-found
// error it can. A versioned read fails either because the secret is not there
// or because that one version is not, and the two send a reader looking in
// different places: one to create the secret, the other to `safe versions`.
//
// Telling them apart costs a metadata request, so it is only paid when a
// version was actually named. A plain read of a missing secret — what every
// `safe gen` does on a path it is about to create — still costs the single
// request it always did.
func (v *Vault) notFoundReading(path string, version uint64) error {
	if version == 0 {
		return NewSecretNotFoundError(path)
	}

	versions, err := v.Versions(path)
	if err != nil || len(versions) == 0 {
		//No history to consult, so the secret itself is the better answer.
		return NewSecretNotFoundError(path)
	}

	for _, v := range versions {
		if uint64(v.Version) != version {
			continue
		}
		switch {
		case v.Destroyed:
			return NewVersionNotFoundError(path, version, "destroyed")
		case v.Deleted:
			return NewVersionNotFoundError(path, version, "deleted")
		}
		//The version is there and alive, so the 404 was about something
		// other than the version; do not claim otherwise.
		return NewSecretNotFoundError(path)
	}

	return NewVersionNotFoundError(path, version, "")
}

// ExplainNotFound narrows a not-found error from Read the way notFoundReading
// narrows a versioned one: when the secret does exist and it is only its newest
// version that cannot be read, it says which version and what became of it.
// Anything else is returned untouched, including a missing key and a version
// the caller named, which is already as specific as it gets.
//
// Read does not do this for itself. A read with no version named is what gen,
// uuid, ssh, rsa and dhparam all do to a path they are about to create, and
// they expect the miss; the metadata request this costs would land on every one
// of those. Here it is paid only by a command that has already failed and is
// about to put the message in front of somebody.
//
// Vault does say which version it was in the body of the 404, but vaultkv
// discards the body of any non-2xx response, so the history has to be asked for
// separately.
func (v *Vault) ExplainNotFound(path string, err error) error {
	if !IsSecretNotFound(err) {
		return err
	}

	secret, _, version := ParsePath(path)
	if version != 0 {
		return err
	}

	versions, verr := v.Versions(secret)
	if verr != nil || len(versions) == 0 {
		//Nothing to consult, so the secret really is the best answer.
		return err
	}

	//A read with no version named asks for the newest one, so that is the
	// only version whose state can explain this particular miss.
	latest := versions[len(versions)-1]
	switch {
	case latest.Destroyed:
		return NewVersionNotFoundError(secret, uint64(latest.Version), "destroyed")
	case latest.Deleted:
		return NewVersionNotFoundError(secret, uint64(latest.Version), "deleted")
	}
	return err
}

// List returns the set of (relative) paths that are directly underneath
// the given path.  Intermediate path nodes are suffixed with a single "/",
// whereas leaf nodes (the secrets themselves) are not.
func (v *Vault) List(path string) (paths []string, err error) {
	path = Canonicalize(path)

	paths, err = v.client.List(path)
	if vaultkv.IsNotFound(err) {
		err = NewSecretNotFoundError(path)
	}

	return paths, err
}

// Write takes a Secret and writes it to the Vault at the specified path.
func (v *Vault) Write(path string, s *Secret) error {
	path, key, version := ParsePath(path)
	if key != "" {
		return fmt.Errorf("cannot write to paths in /path:key notation")
	}

	if version != 0 {
		return fmt.Errorf("cannot write to paths in /path^version notation")
	}

	defer v.invalidateVersions(path)

	if s.Empty() {
		return v.deleteIfPresent(EncodePath(path, "", 0), DeleteOpts{})
	}

	_, err := v.client.Set(path, s.data, nil)
	if vaultkv.IsNotFound(err) {
		err = NewSecretNotFoundError(path)
	}

	return err
}

// casAttempts is how many read-apply-write rounds Update makes against
// check-and-set conflicts before giving up: enough that a retry always
// converges against a bounded burst of concurrent writers, small enough
// that a genuinely contended path fails loudly instead of spinning.
const casAttempts = 5

// casBackoffBase is the first wait Update/UpdateSteps request between
// retry passes; casBackoffCap bounds how large it grows. Small and bounded
// on purpose: this runs synchronously inside a CLI command, not a daemon,
// with only casAttempts passes to spend -- there is no room for the
// GET-retry transport's coarser schedule (3.2's 100ms-per-doubling scale,
// sized for a single throttled read, not a bounded burst of writers all
// waiting on one path).
const (
	casBackoffBase = 10 * time.Millisecond
	casBackoffCap  = 200 * time.Millisecond
)

// casBackoff returns the wait Update/UpdateSteps request before retry pass
// number attempt (1-based): full jitter over [0, ceiling], where ceiling
// doubles with each attempt and saturates at casBackoffCap. Full jitter,
// rather than a fixed base plus jitter, spreads concurrent losers of the
// same conflict across the whole window instead of clustering them near
// its start.
func casBackoff(attempt int) time.Duration {
	return rand.N(casBackoffCeiling(attempt) + 1)
}

// casBackoffCeiling returns the upper bound (inclusive) casBackoff draws
// under for retry pass number attempt (1-based).
func casBackoffCeiling(attempt int) time.Duration {
	d := casBackoffBase << (attempt - 1)
	if d <= 0 || d > casBackoffCap {
		return casBackoffCap
	}
	return d
}

// sleepBeforeRetry waits out a jittered backoff before Update or
// UpdateSteps' next attempt, unless attempt -- its zero-based index --
// was the last one: giving up is immediate, never delayed by a wait
// nobody benefits from. The uncontended path never reaches this call at
// all, since it returns before the loop's bottom.
func (v *Vault) sleepBeforeRetry(attempt int) error {
	if attempt >= casAttempts-1 {
		return nil
	}
	return v.casSleep(context.Background(), casBackoff(attempt+1))
}

// writeCAS writes s at path with the given check-and-set version and
// returns the version Vault assigned. A nil cas sends no check-and-set at
// all -- the unconditional write, and the only kind a KV v1 mount
// understands (v1 ignores the option entirely). cas 0 writes only if the
// path has no version history; cas n writes only if the current version
// is n, and a mismatch comes back as an error vaultkv.IsCASConflict
// recognizes. Deletes are not this function's business: the empty-secret
// degrade-to-delete lives in Write, and deletes take no CAS.
func (v *Vault) writeCAS(path string, s *Secret, cas *uint) (uint, error) {
	path, key, version := ParsePath(path)
	if key != "" {
		return 0, fmt.Errorf("cannot write to paths in /path:key notation")
	}

	if version != 0 {
		return 0, fmt.Errorf("cannot write to paths in /path^version notation")
	}

	defer v.invalidateVersions(path)

	meta, err := v.client.Set(path, s.data, &vaultkv.KVSetOpts{CAS: cas})
	if vaultkv.IsNotFound(err) {
		err = NewSecretNotFoundError(path)
	}
	if err != nil {
		return 0, err
	}
	return meta.Version, nil
}

// errStale404 says a data read answered 404 while the version metadata
// showed a live current version: the read raced a concurrent create, and
// the right response is a fresh read, never a write over a value that was
// not seen.
var errStale404 = errors.New("the secret appeared between its read and its metadata")

// resolveAbsentCAS resolves the check-and-set version for a write to a
// path whose data read answered 404. That answer alone does not mean the
// path is free: a soft-deleted or destroyed-latest secret 404s its data
// read while its metadata keeps current_version, and Vault rejects cas=0
// whenever any metadata survives -- assuming "create only" would wedge
// every write to a previously-deleted path. Verified against a live
// Vault. So: no metadata means cas=0 (create only); metadata whose
// current version is dead means CAS against that version; metadata whose
// current version is alive means the 404 itself was stale (a concurrent
// create landed) and the caller must re-read, reported as errStale404. A
// metadata read the token is not allowed (or otherwise fails) degrades to
// nil -- the unconditional write every one of these paths made before
// check-and-set existed.
func (v *Vault) resolveAbsentCAS(path string) (*uint, error) {
	versions, err := v.Versions(path)
	if err != nil || len(versions) == 0 {
		if err != nil && !IsNotFound(err) {
			return nil, nil
		}
		zero := uint(0)
		return &zero, nil
	}
	current := versions[len(versions)-1]
	if current.Alive() {
		//The consulted history may itself have been cached before the
		// concurrent create; drop it so the retry consults fresh state.
		v.invalidateVersions(path)
		return nil, errStale404
	}
	cas := current.Version
	return &cas, nil
}

// Update runs one read-modify-write against path under check-and-set: it
// reads the live version, hands the fresh state to fn, and writes fn's
// result back naming the version the read observed, so a write landing in
// between conflicts instead of being overwritten; on a conflict it
// re-reads and re-applies fn, up to casAttempts times, then gives up
// naming the path. fn hears exists == false for a path with no live data
// (missing, soft-deleted, or destroyed-latest -- the write still lands in
// every one of those cases), may mutate s in place and return a nil out,
// or return a replacement secret; write == false skips the write, and fn
// must be safe to re-run against fresh state, keeping non-repeatable work
// (generation, prompting) outside. Returns the version the successful
// write assigned. On a KV v1 mount this degrades to a plain
// read-then-write -- no cas is ever sent, because no versioning exists to
// check against; v1 stays last-writer-wins.
//
// A not-found read tries an optimistic cas=0 write first, never consulting
// metadata: a path with no history at all -- the common case for every
// fresh gen/ssh/rsa/set target -- has nothing there to consult, and the
// guess lands. Only when that guess conflicts does Update ask why: the
// very next attempt's own data read already tells apart a concurrent
// create (data now present, handled by the ordinary observed-version
// branch) from surviving metadata on a soft-deleted or destroyed-latest
// path (data still absent, resolveAbsentCAS's dead-version case). The
// metadata GET this pays is one request, charged only on that conflict,
// never on the fast path.
func (v *Vault) Update(path string, fn func(s *Secret, exists bool) (out *Secret, write bool, err error)) (uint, error) {
	literal, key, version := ParsePath(path)
	if key != "" {
		return 0, fmt.Errorf("cannot write to paths in /path:key notation")
	}

	if version != 0 {
		return 0, fmt.Errorf("cannot write to paths in /path^version notation")
	}

	//The mount table is fetched once per process and cached in the
	// client, so this costs no request beyond the one every command
	// already pays.
	mount, err := v.MountVersion(literal)
	if err != nil {
		return 0, err
	}

	var lastConflict error
	for attempt := 0; attempt < casAttempts; attempt++ {
		//The caller's path goes down unre-parsed: readWithVersion and
		// writeCAS run the same ParsePath themselves, and handing them
		// the already-unescaped literal would split any escaped colon or
		// caret in the secret's own name a second time.
		s, ver, err := v.readWithVersion(path)
		exists := err == nil
		if err != nil && !IsNotFound(err) {
			return 0, err
		}

		out, write, err := fn(s, exists)
		if err != nil {
			return 0, err
		}
		if !write {
			return 0, nil
		}
		if out == nil {
			out = s
		}

		//Resolved only once fn has asked for a write, so declining fns
		// and error paths never pay any request the absent branch can
		// cost. A not-found path guesses cas=0 optimistically rather than
		// consulting metadata up front -- see the doc comment above.
		var cas *uint
		optimistic := false
		if mount == 2 {
			if exists {
				observed := ver
				cas = &observed
			} else {
				zero := uint(0)
				cas = &zero
				optimistic = true
			}
		}

		assigned, werr := v.writeCAS(path, out, cas)
		if werr == nil {
			return assigned, nil
		}
		if !vaultkv.IsCASConflict(werr) {
			return 0, werr
		}
		lastConflict = werr

		if optimistic {
			//The blind guess was wrong: metadata survives at this path.
			// Consult it once, in this same pass, rather than paying a
			// second full read whose answer -- still absent -- this
			// conflict already told us.
			resolved, rerr := v.resolveAbsentCAS(literal)
			if errors.Is(rerr, errStale404) {
				lastConflict = rerr
				if serr := v.sleepBeforeRetry(attempt); serr != nil {
					return 0, serr
				}
				continue
			}
			if rerr != nil {
				return 0, rerr
			}
			assigned, werr = v.writeCAS(path, out, resolved)
			if werr == nil {
				return assigned, nil
			}
			if !vaultkv.IsCASConflict(werr) {
				return 0, werr
			}
			lastConflict = werr
		}

		if serr := v.sleepBeforeRetry(attempt); serr != nil {
			return 0, serr
		}
	}
	return 0, fmt.Errorf("gave up writing %s after %d attempts against concurrent writers: %w", literal, casAttempts, lastConflict)
}

// UpdateSteps is Update's chained form, for a group of writes that build
// on one read: fn runs once per step against the accumulated secret,
// mutating it in place, and every step that asks for a write persists the
// whole accumulated state as its own version, check-and-set against the
// version the previous write assigned (the first, against what the read
// observed). N steps cost one read plus one write per step. On a conflict
// the chain re-reads and re-applies only the steps whose writes have not
// landed -- a persisted step never runs again, its keys already riding
// along in the fresh read -- while a step that declined its write
// re-evaluates every pass, which is what lets a skip predicate re-decide
// against a concurrent writer's state. The whole chain shares one budget
// of casAttempts read passes, then gives up naming the path. exists
// reports whether the path held live data as of the current pass's read,
// flipping to true once any write lands. On a KV v1 mount this degrades
// to one read and plain writes; v1 stays last-writer-wins.
func (v *Vault) UpdateSteps(path string, steps int, fn func(step int, s *Secret, exists bool) (write bool, err error)) error {
	literal, key, version := ParsePath(path)
	if key != "" {
		return fmt.Errorf("cannot write to paths in /path:key notation")
	}

	if version != 0 {
		return fmt.Errorf("cannot write to paths in /path^version notation")
	}

	//Cached in the client after the first fetch, same as in Update.
	mount, err := v.MountVersion(literal)
	if err != nil {
		return err
	}

	persisted := make([]bool, steps)
	var lastConflict error
	for attempt := 0; attempt < casAttempts; attempt++ {
		//Same as in Update: the caller's path goes down unre-parsed.
		s, ver, err := v.readWithVersion(path)
		exists := err == nil
		if err != nil && !IsNotFound(err) {
			return err
		}

		var cas *uint
		casResolved := false
		if mount == 2 && exists {
			observed := ver
			cas = &observed
			casResolved = true
		}

		conflicted := false
		for i := 0; i < steps; i++ {
			if persisted[i] {
				continue
			}
			write, err := fn(i, s, exists)
			if err != nil {
				return err
			}
			if !write {
				continue
			}
			//Resolved lazily at the pass's first write, so a chain whose
			// steps all decline (or fail first) never pays any request
			// the absent branch can cost. A not-found path guesses cas=0
			// optimistically first, the same as Update -- see its doc
			// comment for why that skips the metadata GET on the common,
			// no-history case.
			optimistic := false
			if mount == 2 && !casResolved {
				zero := uint(0)
				cas = &zero
				casResolved = true
				optimistic = true
			}
			assigned, werr := v.writeCAS(path, s, cas)
			if werr == nil {
				persisted[i] = true
				exists = true
				if mount == 2 {
					observed := assigned
					cas = &observed
				}
				continue
			}
			if !vaultkv.IsCASConflict(werr) {
				return werr
			}
			lastConflict = werr

			if optimistic {
				//The blind guess was wrong: metadata survives at this
				// path. Consult it once, in this same pass, rather than
				// paying a second full read whose answer -- still
				// absent -- this conflict already told us.
				resolved, rerr := v.resolveAbsentCAS(literal)
				if errors.Is(rerr, errStale404) {
					lastConflict = rerr
					conflicted = true
					break
				}
				if rerr != nil {
					return rerr
				}
				assigned, werr = v.writeCAS(path, s, resolved)
				if werr == nil {
					persisted[i] = true
					exists = true
					cas = &assigned
					continue
				}
				if !vaultkv.IsCASConflict(werr) {
					return werr
				}
				lastConflict = werr
			}
			conflicted = true
			break
		}
		if !conflicted {
			return nil
		}
		if serr := v.sleepBeforeRetry(attempt); serr != nil {
			return serr
		}
	}
	return fmt.Errorf("gave up writing %s after %d attempts against concurrent writers: %w", literal, casAttempts, lastConflict)
}

// errIfFolder returns an error with your provided message if the given path is a folder.
// Can also throw an error if contacting the backend failed, in which case that error
// is returned.
func (v *Vault) errIfFolder(path, message string, args ...any) error {
	path = Canonicalize(path)
	if _, err := v.List(path); err == nil {
		//We don't want the folder error to be ignored because of the -f flag to rm,
		// so we explicitly don't make this a secretNotFound error
		return fmt.Errorf(message, args...)
	} else if !IsNotFound(err) {
		return err
	}
	return nil
}

const (
	verifyStateAlive uint = iota
	verifyStateAliveOrDeleted
)

type verifyOpts struct {
	AnyVersion bool
	State      uint
}

func (v *Vault) verifySecretState(path string, opts verifyOpts) error {
	secret, _, version := ParsePath(path)
	mountV, err := v.MountVersion(secret)
	if err != nil {
		return err
	}

	switch mountV {
	case 1:
		return v.verifySecretExists(path)
	case 2:
		versions, err := v.Versions(secret)
		if err != nil {
			if IsNotFound(err) {
				err = v.errIfFolder(path, "`%s' points to a folder, not a secret", path)
				if err != nil {
					return err
				}

				return NewSecretNotFoundError(secret)
			}

			return err
		}

		if len(versions) == 0 {
			return NewSecretNotFoundError(secret)
		}

		if !opts.AnyVersion {
			var v vaultkv.KVVersion
			if version == 0 {
				v = versions[len(versions)-1]
			} else {
				//Older than anything Vault still lists, which only happens
				// once a version has been destroyed and pruned.
				if uint64(versions[0].Version) > version {
					return NewVersionNotFoundError(secret, version, "destroyed")
				}

				if version > uint64(versions[len(versions)-1].Version) {
					return NewVersionNotFoundError(secret, version, "")
				}

				idx := version - uint64(versions[0].Version)
				v = versions[idx]
			}

			//Named by number even when the caller asked for the latest, since
			// which version that was is the part they do not know.
			if v.Destroyed {
				return NewVersionNotFoundError(secret, uint64(v.Version), "destroyed")
			}
			if opts.State == verifyStateAlive && v.Deleted {
				return NewVersionNotFoundError(secret, uint64(v.Version), "deleted")
			}
		} else {
			for i := range versions {
				if (!versions[i].Deleted && !versions[i].Destroyed) || (opts.State == verifyStateAliveOrDeleted && !versions[i].Destroyed) {
					return nil
				}
			}

			//If we got this far, we couldn't find a version that satisfied our constraints
			if opts.State == verifyStateAlive {
				return secretNotFound{fmt.Sprintf("no living version of secret `%s` exists", secret)}
			}
			return secretNotFound{fmt.Sprintf("no living or deleted version of secret `%s` exists", secret)}
		}

	default:
		return fmt.Errorf("unsupported mount version: %d", mountV)
	}
	return nil
}

func (v *Vault) verifySecretExists(path string) error {
	path = Canonicalize(path)

	_, err := v.Read(path)
	if err != nil && IsNotFound(err) { //if this was not a leaf node (secret)...
		if folderErr := v.errIfFolder(path, "`%s` points to a folder, not a secret", path); folderErr != nil {
			return folderErr
		}
	}
	return err
}

// DeleteTree recursively deletes the leaf nodes beneath the given root until
// the root has no children, and then deletes that.
func (v *Vault) DeleteTree(root string, opts DeleteOpts) error {
	//A root naming a key or a version cannot be honoured by a recursion: the
	// walk drops both and deletes everything beneath the secret. Refuse rather
	// than delete more than was asked for.
	rawRoot, key, version := ParsePath(root)
	if key != "" || version != 0 {
		return fmt.Errorf("cannot recursively delete a specific key or version (%s)", root)
	}
	//ParsePath unescaped the root. The walk and the mount lookup want that
	// literal Vault path; deleteEntireSecret parses its argument again, so it
	// gets the escaped form back.
	root = EncodePath(rawRoot, "", 0)

	secrets, err := v.ConstructSecrets(rawRoot, TreeOpts{FetchKeys: false, SkipVersionInfo: true, AllowDeletedSecrets: true})
	if err != nil {
		return err
	}
	// The context bounds dispatch only: the deletes themselves are vaultkv
	// requests, which carry no context, so a failure stops new paths from
	// starting while in-flight requests run to their client timeout.
	err = parallel.EachLimit(context.Background(), secrets.Paths(), parallel.IOLimit(), func(_ context.Context, _ int, path string) error {
		return v.deleteEntireSecret(path, opts.Destroy, opts.All)
	})
	if err != nil {
		return err
	}

	mount, err := v.Client().MountPath(rawRoot)
	if err != nil {
		return err
	}

	if strings.Trim(rawRoot, "/") != strings.Trim(mount, "/") {
		err = v.deleteEntireSecret(root, opts.Destroy, opts.All)
	}

	return err
}

type DeleteOpts struct {
	Destroy bool
	All     bool
}

// CheckDeletePath reports whether a path and the options it is to be deleted
// under ask for the same thing. It reads the path alone and makes no request,
// so a caller holding several paths can put all of them past it before any one
// of them is deleted.
func CheckDeletePath(path string, opts DeleteOpts) error {
	//All works on every version, so a path that names one version asks for two
	// different things at once. The version used to be dropped and the All
	// taken: deleting every version of a secret when one was named, and, with
	// Destroy, destroying every version and the metadata along with them --
	// which cannot be undone, was reported as success, and happened just the
	// same for a version that had never been written, since All also turns off
	// the check that the named version exists.
	if secretPath, _, version := ParsePath(path); opts.All && version != 0 {
		return fmt.Errorf("cannot delete version %d of `%s' and every version of it at once: drop the version to keep --all, or drop --all to work on the one version", version, secretPath)
	}

	return nil
}

func (v *Vault) canSemanticallyDelete(path string) error {
	justSecret, key, version := ParsePath(path)
	if key == "" || version == 0 {
		return nil
	}

	versions, err := v.Versions(justSecret)
	if err != nil {
		return err
	}

	if len(versions) == 0 {
		return NewSecretNotFoundError(justSecret)
	}

	if versions[len(versions)-1].Version == uint(version) {
		return nil
	}

	//Read the version, not the key: a read of a path that names a key hands
	// back that one key, so asking this way makes every version look as though
	// it held nothing else, and the check below can never find anything to
	// object to. ParsePath unescaped the secret path, and Read parses its
	// argument again, so the escaped form goes back in.
	s, err := v.Read(EncodePath(justSecret, "", version))
	if err != nil {
		return err
	}

	if !s.Has(key) {
		return NewKeyNotFoundError(justSecret, key)
	}

	if len(s.data) != 1 {
		return fmt.Errorf("cannot delete %s from version %d: that version holds other keys, and a version already written cannot be rewritten", key, version)
	}

	return nil
}

// Delete removes the secret or key stored at the specified path.
// If destroy is true and the mount is v2, the latest version is destroyed instead
func (v *Vault) Delete(path string, opts DeleteOpts) error {
	path = Canonicalize(path)

	if err := CheckDeletePath(path, opts); err != nil {
		return err
	}

	reqState := verifyStateAlive
	if opts.Destroy {
		reqState = verifyStateAliveOrDeleted
	}

	err := v.verifySecretState(path, verifyOpts{
		AnyVersion: opts.All,
		State:      reqState,
	})
	if err != nil {
		return err
	}

	err = v.canSemanticallyDelete(path)
	if err != nil {
		return err
	}

	if !PathHasKey(path) {
		return v.deleteEntireSecret(path, opts.Destroy, opts.All)
	}

	return v.deleteSpecificKey(path, opts)
}

func (v *Vault) deleteEntireSecret(path string, destroy bool, all bool) error {
	secret, _, version := ParsePath(path)
	defer v.invalidateVersions(secret)

	if destroy && all {
		return v.client.DestroyAll(secret)
	}

	var versions []uint
	if version != 0 {
		versions = []uint{uint(version)}
	}

	if destroy {
		allVersions, err := v.Versions(secret)
		if err != nil {
			return err
		}
		if len(allVersions) == 0 {
			return NewSecretNotFoundError(secret)
		}
		//Need to populate latest version to a Destroy call if the
		// version is not explicitly given
		if len(versions) == 0 {
			versions = []uint{allVersions[len(allVersions)-1].Version}
		}
		//Check if we should clean up the metadata entirely because there are
		// no more remaining non-destroyed versions
		shouldNuke := true
		verIdx := 0
		for i := range allVersions {
			for verIdx < len(versions) && versions[verIdx] < allVersions[i].Version {
				verIdx++
			}
			if !allVersions[i].Destroyed && (verIdx >= len(versions) || versions[verIdx] != allVersions[i].Version) {
				shouldNuke = false
				break
			}
		}

		if shouldNuke {
			return v.client.DestroyAll(secret)
		}
		return v.client.Destroy(secret, versions)
	}

	if all {
		allVersions, err := v.Versions(secret)
		if err != nil {
			return err
		}

		versions = make([]uint, 0, len(allVersions))
		for i := range allVersions {
			versions = append(versions, allVersions[i].Version)
		}

	}

	return v.client.Delete(secret, &vaultkv.KVDeleteOpts{Versions: versions, V1Destroy: true})
}

func (v *Vault) deleteSpecificKey(path string, opts DeleteOpts) error {
	secretPath, key, version := ParsePath(path)
	//ParsePath unescaped the secret path. Read, Write, and deleteEntireSecret
	// all parse their argument again, so they need the escaped form back or
	// they split a second time at a colon that belongs to the path.
	//
	// The version goes back with it. Dropping it reads and removes the key from
	// the latest version instead of the one that was named — an edit to a
	// secret nobody asked about, leaving the named version as it was.
	versionedPath := EncodePath(secretPath, "", version)
	secret, err := v.Read(versionedPath)
	if err != nil {
		return err
	}
	deleted := secret.Delete(key)
	if !deleted {
		return NewKeyNotFoundError(secretPath, key)
	}
	if secret.Empty() {
		//Gotta avoid call to Write because Write ignores version information (with good reason)
		// We can only be here and not be on the latest version if this was the only key remaining
		// and we're just trying to nuke the secret
		//
		//The key was the whole secret, so removing it removes versions, which
		// is what --destroy and --all are asking about. They used to be dropped
		// here: a destroy reported success and left the value where an undelete
		// would bring it straight back.
		return v.deleteEntireSecret(versionedPath, opts.Destroy, opts.All)
	}
	//Destroying, and deleting every version, both work on whole versions.
	// Neither can be done to one key of a secret that holds others: the key
	// stays in every version already written. Writing a new version without
	// the key and calling that a destroy is what safe used to do.
	if opts.Destroy {
		return fmt.Errorf("cannot destroy the key %s: %s holds other keys, and destroying removes whole versions", key, secretPath)
	}
	if opts.All {
		return fmt.Errorf("cannot delete the key %s from every version: %s holds other keys, and a version already written cannot be rewritten", key, secretPath)
	}
	//What is left goes on as a new version. canSemanticallyDelete has already
	// turned away anything but the latest version by this point, so this never
	// writes an old version forward over a newer one.
	return v.Write(EncodePath(secretPath, "", 0), secret)
}

// DeleteVersions marks the given versions of the given secret as deleted for
// a v2 backend or actually deletes it for a v1 backend.
func (v *Vault) DeleteVersions(path string, versions []uint) error {
	defer v.invalidateVersions(path)
	return v.client.Delete(path, &vaultkv.KVDeleteOpts{Versions: versions, V1Destroy: true})
}

func (v *Vault) Undelete(path string) error {
	secret, key, version := ParsePath(path)
	if key != "" {
		return fmt.Errorf("cannot undelete specific key (%s)", path)
	}
	defer v.invalidateVersions(secret)

	respVersions, err := v.Versions(secret)
	if err != nil {
		return err
	}

	if len(respVersions) == 0 {
		return NewSecretNotFoundError(secret)
	}

	if version == 0 {
		version = uint64(respVersions[len(respVersions)-1].Version)
	}

	//Said the way a read says it, but left a plain error: this one reaches the
	// tree walk, and MoveCopyTree drops walk errors that answer to IsNotFound.
	destroyedErr := errors.New(VersionNotFoundMessage(secret, version, "destroyed"))
	firstVersion := respVersions[0].Version
	if version < uint64(firstVersion) {
		return destroyedErr
	}

	diff := version - uint64(firstVersion)
	const maxInt = int(^uint(0) >> 1)
	if diff > uint64(maxInt) {
		return fmt.Errorf("version difference too large for int conversion")
	}
	idx := int(diff)
	if idx >= len(respVersions) {
		return errors.New(VersionNotFoundMessage(secret, version, ""))
	}

	if respVersions[idx].Destroyed {
		return destroyedErr
	}

	return v.Client().Undelete(secret, []uint{uint(version)})
}

// deleteIfPresent first checks to see if there is a Secret at the given path,
// and if so, it deletes it. Otherwise, no error is thrown
func (v *Vault) deleteIfPresent(path string, opts DeleteOpts) error {
	secretpath, _, _ := ParsePath(path)
	if _, err := v.Read(EncodePath(secretpath, "", 0)); err != nil {
		if IsSecretNotFound(err) {
			return nil
		}
		return err
	}

	err := v.Delete(path, opts)
	if IsKeyNotFound(err) {
		return nil
	}
	return err
}

func (v *Vault) verifyMetadataExists(path string) error {
	versions, err := v.Versions(path)
	if err != nil {
		if vaultkv.IsNotFound(err) {
			return NewSecretNotFoundError(path)
		}
		return err
	}

	if len(versions) == 0 {
		return NewSecretNotFoundError(path)
	}

	return nil
}

type MoveCopyOpts struct {
	SkipIfExists bool
	Quiet        bool
	//Deep copies all versions and overwrites all versions at the target location
	Deep bool
	//DeletedVersions undeletes, reads, and redeletes the deleted keys
	// It also puts in dummy destroyed keys to dest to match destroyed keys from src
	//Makes no sense without Deep
	DeletedVersions bool
}

// Copy copies secrets from one path to another.
// With a secret:key specified: key -> key is good.
// key -> no-key is okay - we assume to keep old key name
// no-key -> key is bad. That makes no sense and the user should feel bad.
// Returns KeyNotFoundError if there is no such specified key in the secret at oldpath
func (v *Vault) Copy(oldpath, newpath string, opts MoveCopyOpts) error {
	oldpath = Canonicalize(oldpath)
	newpath = Canonicalize(newpath)

	if opts.DeletedVersions && !opts.Deep {
		return fmt.Errorf("DeletedVersions requires Deep to be set")
	}
	var err error
	reqState := verifyStateAlive
	if opts.DeletedVersions {
		reqState = verifyStateAliveOrDeleted
	}

	err = v.verifySecretState(oldpath, verifyOpts{
		State:      reqState,
		AnyVersion: opts.Deep,
	})
	if err != nil {
		return err
	}

	if opts.SkipIfExists {
		if _, err := v.Read(newpath); err == nil {
			if !opts.Quiet {
				_, _ = ansi.Fprintf(os.Stderr, "@R{Cowardly refusing to copy/move data into} @C{%s}@R{, as that would clobber existing data}\n", newpath)
			}
			return nil
		} else if !IsNotFound(err) {
			return err
		}
	}

	srcPath, srcKey, srcVersion := ParsePath(oldpath)
	dstPath, dstKey, dstVersion := ParsePath(newpath)
	//ParsePath unescaped both paths. The tree walk and SecretEntry.Copy want
	// those literal Vault paths, but Read and Write parse their argument again,
	// so they get the destination back in the escaped syntax.
	encodedDstPath := EncodePath(dstPath, "", 0)

	if dstVersion != 0 {
		return fmt.Errorf("copying a secret to a specific destination version is not supported")
	}

	if opts.Deep && srcVersion != 0 {
		return fmt.Errorf("performing a deep copy of a specified version is not supported")
	}

	var toWrite []*Secret
	if srcKey != "" { //Just a single key.
		if opts.Deep {
			return fmt.Errorf("cannot take deep copy of a specific key")
		}
		srcSecret, err := v.Read(oldpath)
		if err != nil {
			return err
		}

		if !srcSecret.Has(srcKey) {
			return NewKeyNotFoundError(oldpath, srcKey)
		}

		if dstKey == "" {
			dstKey = srcKey
		}

		dstOrig, err := v.Read(encodedDstPath)
		if err != nil && !IsSecretNotFound(err) {
			return err
		}

		if IsSecretNotFound(err) {
			dstOrig = NewSecret()
		}

		toWrite = append(toWrite, dstOrig)
		_ = toWrite[0].Set(dstKey, srcSecret.Get(srcKey), false)
	} else {
		if dstKey != "" {
			return fmt.Errorf("cannot move full secret `%s` into specific key `%s`", oldpath, newpath)
		}
		t, err := v.ConstructSecrets(srcPath, TreeOpts{
			FetchKeys:           true,
			GetOnly:             true,
			FetchAllVersions:    opts.Deep || srcVersion != 0,
			GetDeletedVersions:  opts.Deep && opts.DeletedVersions,
			AllowDeletedSecrets: opts.Deep || srcVersion != 0,
		})

		if err != nil {
			return err
		}

		if len(t) == 0 {
			// Prevent a panic
			return NewSecretNotFoundError(srcPath)
		}

		if srcVersion != 0 {
			//Filter results to the specific requested secret
			for i := range t[0].Versions {
				if t[0].Versions[i].Number == uint(srcVersion) {
					t[0].Versions = []SecretVersion{t[0].Versions[i]}
					break
				}
			}
		}

		err = t[0].Copy(v, dstPath, TreeCopyOpts{Clear: opts.Deep, Pad: opts.Deep})
		if err != nil {
			return err
		}
	}

	for i := range toWrite {
		err := v.Write(encodedDstPath, toWrite[i])
		if err != nil {
			return err
		}
	}

	return nil
}

// MoveCopyTree will recursively copy all nodes from the root to the new location.
// This function will get confused about 'secret:key' syntax, so don't let those
// get routed here - they don't make sense for a recursion anyway.
func (v *Vault) MoveCopyTree(oldRoot, newRoot string, move bool, opts MoveCopyOpts) error {
	//Neither root can name a key or a version: the recursion drops both and
	// relocates the whole subtree instead of the one thing that was named.
	rawOldRoot, oldKey, oldVersion := ParsePath(oldRoot)
	rawNewRoot, newKey, newVersion := ParsePath(newRoot)
	if oldKey != "" || newKey != "" || oldVersion != 0 || newVersion != 0 {
		return fmt.Errorf("cannot recursively copy or move a specific key or version (%s -> %s)", oldRoot, newRoot)
	}
	//Same guard v.Copy applies: DeletedVersions only makes sense alongside
	// Deep, and the recursive path must refuse it rather than silently
	// falling back to a shallow copy plus a versionless delete.
	if opts.DeletedVersions && !opts.Deep {
		return fmt.Errorf("DeletedVersions requires Deep to be set")
	}
	//The walk wants the literal Vault paths ParsePath returned. The prefix
	// replace below works in the escaped syntax that entry paths encode to,
	// and EscapePathSegment substitutes byte by byte, so escaping a path and
	// escaping its root prefix agree: the replace stays exact. Re-encoding
	// also normalizes the roots the way the walk does.
	oldRoot = EncodePath(rawOldRoot, "", 0)
	newRoot = EncodePath(rawNewRoot, "", 0)

	//The walk skips (rather than aborts on) any node it cannot read due to
	// permissions, counting each skip here. Recursion treats the walk as a
	// complete inventory and does destructive work against it -- for a
	// move, that skip would otherwise let an entry it never actually read
	// reach the source delete/destroy below. So a nonzero skip count
	// refuses the whole operation up front, matching the old per-secret
	// verifySecretState's abort-on-403 behavior.
	var skipped atomic.Uint64
	tree, err := v.ConstructSecrets(rawOldRoot, TreeOpts{
		FetchKeys:           true,
		FetchAllVersions:    opts.Deep,
		GetDeletedVersions:  opts.Deep && opts.DeletedVersions,
		AllowDeletedSecrets: opts.Deep,
		SkippedForbidden:    &skipped,
	})
	if err != nil {
		return err
	}
	if n := skipped.Load(); n > 0 {
		verb := "copy"
		if move {
			verb = "move"
		}
		return fmt.Errorf("cannot recursively %s %s: %d secret(s) or version(s) under it could not be read (permission denied)", verb, oldRoot, n)
	}

	if opts.SkipIfExists {
		//Writing one secret over a deleted secret isn't clobbering. Completely overwriting a set of deleted secrets would be
		newTree, err := v.ConstructSecrets(rawNewRoot, TreeOpts{FetchKeys: false, AllowDeletedSecrets: !opts.Deep, SkipVersionInfo: true})
		if err != nil && !IsNotFound(err) {
			return err
		}
		// The keyed source walk's Paths() emits path:key entries per key, so
		// the clobber comparison is built from entry paths on BOTH sides.
		existing := map[string]bool{}
		for _, entry := range newTree {
			existing[EncodePath(entry.Path, "", 0)] = true
		}
		existingPaths := []string{}
		for _, entry := range tree {
			newPath := strings.Replace(EncodePath(entry.Path, "", 0), oldRoot, newRoot, 1)
			if existing[newPath] {
				existingPaths = append(existingPaths, newPath)
			}
		}
		if len(existingPaths) > 0 {
			if !opts.Quiet {
				_, _ = ansi.Fprintf(os.Stderr, "@R{Cowardly refusing to copy/move data into} @C{%s}@R{, as the following paths would be clobbered:}\n", newRoot)
				for _, path := range existingPaths {
					_, _ = ansi.Fprintf(os.Stderr, "@R{- }@C{%s}\n", path)
				}
			}
			return nil
		}
	}

	// As in DeleteTree, the context bounds dispatch only: entry.Copy and
	// the source deletes are contextless vaultkv requests.
	err = parallel.EachLimit(context.Background(), tree, parallel.IOLimit(), func(_ context.Context, _ int, entry SecretEntry) error {
		newPath := strings.Replace(EncodePath(entry.Path, "", 0), oldRoot, newRoot, 1)
		rawNewPath, _, _ := ParsePath(newPath)
		if err := entry.Copy(v, rawNewPath, TreeCopyOpts{Clear: opts.Deep, Pad: opts.Deep}); err != nil {
			return err
		}
		// An entry the walk could not actually read carries no versions.
		// The skip check above already refuses the whole operation in that
		// case, but guard the destructive branch independently too: never
		// let a zero-version entry -- one entry.Copy just wrote nothing
		// for -- reach the source delete/destroy.
		if !move || len(entry.Versions) == 0 {
			return nil
		}
		if opts.Deep && opts.DeletedVersions {
			err := v.client.DestroyAll(entry.Path)
			v.invalidateVersions(entry.Path)
			return err
		}
		// deleteEntireSecret, not v.Delete: Delete re-runs
		// verifySecretState (a metadata GET per secret) that the walk
		// already answered, and canSemanticallyDelete is a no-op for the
		// key-less, version-less paths recursion guarantees.
		return v.deleteEntireSecret(EncodePath(entry.Path, "", 0), false, false)
	})
	if err != nil {
		return err
	}
	return nil
}

// Move moves secrets from one path to another.
// A move is semantically a copy and then a deletion of the original item. For
// more information on the behavior of Move pertaining to keys, look at Copy.
func (v *Vault) Move(oldpath, newpath string, opts MoveCopyOpts) error {
	oldpath = Canonicalize(oldpath)
	newpath = Canonicalize(newpath)

	err := v.canSemanticallyDelete(oldpath)
	if err != nil {
		return fmt.Errorf("can't move `%s': %w. Did you mean cp?", oldpath, err)
	}

	err = v.Copy(oldpath, newpath, opts)
	if err != nil {
		return err
	}

	if opts.Deep && opts.DeletedVersions {
		//DestroyAll goes straight to Vault, so it takes the literal path rather
		// than the escaped syntax the caller wrote. Copy has already refused a
		// deep move that names a key or a version, so nothing is dropped here.
		rawOldPath, _, _ := ParsePath(oldpath)
		err = v.client.DestroyAll(rawOldPath)
		v.invalidateVersions(rawOldPath)
		if err != nil {
			return err
		}
	} else {
		err = v.Delete(oldpath, DeleteOpts{})
		if err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) Mounts(typ string) ([]string, error) {
	mounts, err := v.client.Client.ListMounts()
	if err != nil {
		return nil, err
	}

	ret := []string{}

	for name, mountInfo := range mounts {
		if mountInfo.Type == typ {
			ret = append(ret, strings.TrimSuffix(name, "/")+"/")
		}
	}

	return ret, nil
}

// KVMounts returns every kv and generic mount in one mount-table request,
// kv mounts first, matching the order the root walk historically used.
func (v *Vault) KVMounts() ([]string, error) {
	mounts, err := v.client.Client.ListMounts()
	if err != nil {
		return nil, err
	}
	var kvs, generics []string
	for name, mountInfo := range mounts {
		switch mountInfo.Type {
		case "kv":
			kvs = append(kvs, strings.TrimSuffix(name, "/")+"/")
		case "generic":
			generics = append(generics, strings.TrimSuffix(name, "/")+"/")
		}
	}
	return append(kvs, generics...), nil
}

func DecodeErrorResponse(body []byte) error {
	var raw map[string]any

	if err := json.Unmarshal(body, &raw); err != nil {
		return fmt.Errorf("received non-200 with non-JSON payload:\n%s", body)
	}

	if rawErrors, ok := raw["errors"]; ok {
		var errors []string
		if elems, ok := rawErrors.([]any); ok {
			for _, elem := range elems {
				if err, ok := elem.(string); ok {
					errors = append(errors, err)
				}
			}
			return fmt.Errorf("%s", strings.Join(errors, "\n"))
		} else {
			return fmt.Errorf("received unexpected format of Vault error messages:\n%v", errors)
		}
	} else {
		return fmt.Errorf("received non-200 with no error messagess:\n%v", raw)
	}
}

// FindSigningCA returns the authority that should sign cert, and the path it
// was read from. A certificate signs itself when it is named as its own
// authority or when it already carries its own signature; otherwise the
// authority is read from the Vault, and has to be one — signing with a plain
// certificate produces something no relying party will accept, and nothing
// further along reports it.
func (v *Vault) FindSigningCA(cert *X509, certPath string, signPath string) (*X509, string, error) {
	/* find the CA */
	if signPath != "" {
		// Compared canonicalized: a leading or trailing slash, or a doubled
		// one, still names the same secret as certPath, and Sign's
		// CA-rotation branch (ca == x) depends on this returning the
		// certificate object itself -- by pointer identity -- for that
		// case, not a second copy read back from the Vault.
		if Canonicalize(certPath) == Canonicalize(signPath) {
			return cert, certPath, nil
		} else {
			s, err := v.Read(signPath)
			if err != nil {
				return nil, "", err
			}
			ca, err := s.X509(true)
			if err != nil {
				return nil, "", err
			}
			if !ca.IsCA() {
				return nil, "", fmt.Errorf("%s is not a certificate authority", signPath)
			}
			return ca, signPath, nil
		}
	} else {
		// Check if this cert is self-signed If so, don't change the value
		// of s, because its already the cert we loaded in. #Hax
		err := cert.Certificate.CheckSignature(
			cert.Certificate.SignatureAlgorithm,
			cert.Certificate.RawTBSCertificate,
			cert.Certificate.Signature,
		)
		if err == nil {
			return cert, certPath, nil
		} else {
			// Lets see if we can guess the CA if none was provided. A path
			// with no '/' at all has no parent directory to guess a sibling
			// under.
			slash := strings.LastIndex(certPath, "/")
			if slash < 0 {
				return nil, "", fmt.Errorf("no signing authority provided and no 'ca' sibling found")
			}
			caPath := certPath[0:slash] + "/ca"
			s, err := v.Read(caPath)
			if err != nil {
				return nil, "", fmt.Errorf("no signing authority provided and no 'ca' sibling found")
			}
			ca, err := s.X509(true)
			if err != nil {
				return nil, "", err
			}
			if !ca.IsCA() {
				return nil, "", fmt.Errorf("%s is not a certificate authority", caPath)
			}
			//The sibling is a guess. Signing under it when it is not the
			// authority that issued the certificate hands back something
			// with a different issuer than the one it went in with, which
			// is not what renewing or reissuing was asked to do. Naming an
			// authority explicitly still moves a certificate to a new one.
			//
			// A cryptographic signature check would also refuse the
			// ordinary case of CA rotation: reissuing the CA itself with a
			// fresh key (the ca == x branch in Sign) replaces its public
			// key, so no certificate signed under the old key verifies
			// against it anymore, even though the sibling is still the
			// right authority. Comparing the sibling's Subject to the
			// certificate's Issuer instead catches an unrelated stranger CA
			// the same way, without being upset by a key rotation: the
			// Subject and Issuer stay equal across one, and differ for a
			// sibling that never issued the certificate at all.
			//
			// --signed-by is taken at its word, so the remedy named here
			// is also the way past this check: say so, rather than let it
			// read as an instruction to run the same thing again naming
			// the sibling that just got refused.
			if !cert.IssuedBy(ca) {
				return nil, "", fmt.Errorf("%s did not sign %s; name its authority with --signed-by (naming one that did not sign it moves the certificate under it)", caPath, certPath)
			}
			return ca, caPath, nil
		}
	}
}

func (v *Vault) SaveSealKeys(keys []string) error {
	path := "secret/vault/seal/keys"
	s := NewSecret()
	for i, key := range keys {
		if err := s.Set(fmt.Sprintf("key%d", i+1), key, false); err != nil {
			return err
		}
	}
	return v.Write(path, s)
}

func (v *Vault) SetURL(u string) error {
	vaultURL, err := url.Parse(strings.TrimSuffix(u, "/"))
	if err != nil {
		return fmt.Errorf("could not parse Vault URL: %w", err)
	}

	//The default port for Vault is typically 8200 (which is the VaultKV default),
	// but safe has historically ignored that and used the default http or https
	// port, depending on which was specified as the scheme
	if vaultURL.Port() == "" {
		port := ":80"
		if strings.ToLower(vaultURL.Scheme) == "https" {
			port = ":443"
		}
		vaultURL.Host = vaultURL.Host + port
	}
	v.client.Client.VaultURL = vaultURL
	return nil
}
