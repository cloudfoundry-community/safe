# Performance

`safe` now makes far fewer Vault API requests for the same work, and issues the requests it still needs concurrently.

* `safe export` of a 300 secret tree drops from 714 requests to 413. A KV v2 secret whose latest version is alive is now read in one request instead of a metadata read followed by a data read. Deleted, destroyed, and v1 secrets fall back to the previous flow, so semantics are unchanged.

* `safe cp -R` of 30 secrets drops from 215 requests to 63, and `safe mv -R` from 275 to 93. A recursive copy used to re-read every source it had already read during the walk; it now writes from the walked data.

* Reading ten paths against a Vault 20 ms away drops from 0.289 s to 0.103 s. Multi-path `get`, and the per-path loops in `cp -R`, `mv -R`, `rm -R`, `gen`, `ssh`, `rsa`, `dhparam`, and `import`, all run with bounded concurrency.

* `safe gen` of several keys on one path now reads the path once and applies the keys cumulatively: N keys cost N+1 requests instead of 2N, and the version history still gains one version per key.

* `safe x509 issue` and `reissue` generate the leaf key while the CA read is in flight, and both commands validate their flags before any request goes out, so a bad flag no longer costs a round trip or a key generation. `x509 validate` and `x509 show` prefetch all of their paths concurrently.

* Password generation draws entropy in one block per password instead of one read per character, preserving uniformity by rejection sampling.

* Chained sub-commands (`safe get a -- get b`) reuse one Vault client and one connection instead of building a new one per command.

* Every walking command asks Vault for its mount table once rather than repeatedly, and the HTTP transport is tuned for connection reuse.

* Network fan-outs are sized independently of the core count: 16 wide by default, overridable with `SAFE_CONCURRENCY` (clamped to 1–64). CPU-bound fan-outs (`ssh`, `rsa` key generation) keep their core-based width.

* `safe tree` and `safe paths` of a 300 secret tree drop from 413 requests to 113. Their old default paid one metadata read per leaf purely to hide secrets whose latest version is deleted, and the Vault API offers no cheaper way to detect that. The quick walk is now the default; see the behavior change below.

# Batch Certificate Issuance

`safe x509 issue` now accepts any number of destination paths and issues one certificate per path in a single invocation. Every certificate carries the `--name` SAN set; each subject defaults to its path's basename when `--subject` is absent. The batch pays for its size once: `--no-clobber` reads run concurrently, every key generates while the CA is read, and one CA write reserves every serial and re-signs the revocation list before any certificate write lands, so a crash mid-batch burns spare serials rather than issuing numbers the counter never recorded.

# Safe Under Concurrency

Two `safe` processes (or `safe` beside any other Vault client) can now work the same paths without silently losing writes.

* The write behind `gen`, `ssh`, `rsa`, `dhparam`, `uuid`, `fmt`, and `set`/`ask`/`paste` runs under KV v2 check-and-set. A key some concurrent process writes between a command's read and its write now survives: the conflicting write is refused and re-applied against fresh state, where it used to be silently overwritten. `--no-clobber` re-decides on each retry, so it refuses a key the conflict revealed.

* The CA read-modify-write behind `x509 issue`, `reissue`, `renew`, `revoke`, and `crl --renew` is guarded the same way. A concurrent issuance moving the serial counter, or a concurrent revocation extending the CRL, now forces a retry against the fresh CA instead of being overwritten. Duplicate serials under one issuer and lost revocation entries were both possible before. If a retry finds the certificate already revoked by someone else's write, the command's own write becomes a no-op; an ordinary re-revoke of something revoked in an earlier run still re-publishes the CRL as before.

* Conflict retries back off with a small jittered wait (10 ms growing toward a 200 ms cap), so a burst of concurrent writers scatters instead of colliding again. An uncontended write pays nothing, and the happy-path request budget is unchanged: one read and one write. KV v1 mounts keep their plain writes; no `cas` is ever sent there.

* Reads retry transient failures: a 429 or a connection reset earns up to two more attempts with jittered backoff, honoring `Retry-After` when Vault sends one, bounded by the request's own deadline. A refused connection fails immediately (nothing is listening; retrying will not change that), a 503 surfaces immediately (a sealed Vault must be visible), and writes are never replayed.

# Behavior Changes

Most commands are byte for byte identical to the previous release, including under a restricted token. These are the exceptions.

* **A recursive `copy` or `move` over a tree you can list but cannot fully read now fails.** It refuses up front, exits non-zero, and reports how many secrets or versions it could not read. Previously `copy -Rf` exited zero while writing empty secrets for every unreadable source, and `move -Rf` exited non-zero only after copying part of the tree and deleting several sources. Scripts that relied on the old exit status will need updating.

* **`safe tree` and `safe paths` no longer hide deleted secrets by default.** A secret whose latest version has been soft-deleted now appears in both listings. The check that hid it cost one metadata read per leaf, which was most of what those commands did. Pass `--exact` to get the old filtering back. `-q` and `--quick` are still accepted on both commands and now name the default, so existing invocations are unaffected. `safe ls` is unchanged and still checks by default.

* `safe fmt` documents its `--cost` flag for bcrypt's work factor. An explicit `--cost 0` is now rejected like any other out-of-range value instead of silently becoming 12, and values above what bcrypt accepts are refused before the Vault read rather than running for hours after it.

* `x509 issue` warns when an explicit `--subject` covers several paths, and when destination basenames collide: both would otherwise produce indistinguishable certificates.

* `safe rekey` aborts as soon as stdin closes on the first unseal-key prompt, rather than posting a partial key set and letting the server reject it. The abort message is now safe's own and no longer varies with the Vault version.

* A KV v2 secret whose metadata read is forbidden but whose data read is permitted is now returned with its keys and values rather than skipped. `safe values` no longer prints its incomplete results warning for that case, and `export`, `find`, and the `--keys` walks return the secret.

* A recursive copy is now a snapshot taken at walk time. A source destroyed after the walk no longer aborts the copy; the destination receives the data as of walk time. A source destroyed during the walk still fails as before.

* When a parallelized command fails, it stops dispatching new work but lets already started items finish, so a few more items may complete than before. When several items fail, every failure is reported rather than the first alone, and `--force` on a recursive delete or move suppresses the run only when every failure is a not-found. One exception: if a `mv -Rf` source vanishes between the walk and the delete, `--force` no longer suppresses the resulting error.

* A secret living at the root of a recursive copy is written to the destination once rather than twice.

* `safe import` processes secrets in sorted path order for both the version 2 and legacy version 1 formats, rather than Go map order, and the v1 loop now writes concurrently like the v2 loop.

* `gen`, `ssh`, `rsa`, and `dhparam` print their per-path notices grouped by path, in the order the paths were given, after the parallel phase completes. The wording is unchanged.

* `safe dhparam` no longer streams OpenSSL's progress output to stderr. The generated parameters and all error reporting are unchanged.

* The warning printed when TLS certificate verification is disabled is now opt-in, off by default, and says connections are insecure rather than merely not authenticated. Set `SAFE_SKIP_VERIFY_WARNING=1` to see it. Nothing that wraps safe gets an unasked-for line on stderr, and whether verification happens is unchanged.

# Upstream Convergence

* Requires `vaultkv` v0.7.2, which adds KV v2 check-and-set support and a whole-table mount cache, and carries v0.7.1's fixes for connection reuse after error responses, a stale token on redirects, and mount lookup concurrency.

* The archived `gopkg.in/yaml.v2` is replaced by its maintained successor, `go.yaml.in/yaml/v2` v2.4.4, and the archived `github.com/pborman/uuid` by `github.com/google/uuid` v1.6.0, which pborman/uuid was already a wrapper around. `golang.org/x/crypto` moves to v0.56.0 and `github.com/gofrs/flock` to v0.13.1. Parsing, rendering, and the UUIDs `safe uuid` writes are unchanged.
