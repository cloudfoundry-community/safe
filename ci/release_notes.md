# Performance

`safe` now makes far fewer Vault API requests for the same work, and issues the requests it still needs concurrently.

* `safe export` of a 300 secret tree drops from 714 requests to 413. A KV v2 secret whose latest version is alive is now read in one request instead of a metadata read followed by a data read. Deleted, destroyed, and v1 secrets fall back to the previous flow, so semantics are unchanged.

* `safe cp -R` of 30 secrets drops from 215 requests to 63, and `safe mv -R` from 275 to 93. A recursive copy used to re-read every source it had already read during the walk; it now writes from the walked data.

* Reading ten paths against a Vault 20 ms away drops from 0.289 s to 0.103 s. Multi-path `get`, and the per-path loops in `cp -R`, `mv -R`, `rm -R`, `gen`, `ssh`, `rsa`, `dhparam`, and `import`, all run with bounded concurrency.

* Chained sub-commands (`safe get a -- get b`) reuse one Vault client and one connection instead of building a new one per command.

* Every walking command asks Vault for its mount table once rather than repeatedly, and the HTTP transport is tuned for connection reuse.

`safe tree` and `safe paths` are unchanged. Their default output pays one metadata read per leaf purely to hide deleted secrets, and the Vault API offers no cheaper way to detect a deleted latest version. Use `-q` to skip that filtering.

# Behavior Changes

Most commands are byte for byte identical to the previous release, including under a restricted token. These are the exceptions.

* **A recursive `copy` or `move` over a tree you can list but cannot fully read now fails.** It refuses up front, exits non-zero, and reports how many secrets or versions it could not read. Previously `copy -Rf` exited zero while writing empty secrets for every unreadable source, and `move -Rf` exited non-zero only after copying part of the tree and deleting several sources. Scripts that relied on the old exit status will need updating.

* A KV v2 secret whose metadata read is forbidden but whose data read is permitted is now returned with its keys and values rather than skipped. `safe values` no longer prints its incomplete results warning for that case, and `export`, `find`, and the `--keys` walks return the secret.

* A recursive copy is now a snapshot taken at walk time. A source destroyed after the walk no longer aborts the copy; the destination receives the data as of walk time. A source destroyed during the walk still fails as before.

* When a parallelized command fails, it stops dispatching new work but lets already started items finish, so a few more items may complete than before. The error returned is the first failure, unwrapped, so `--force` suppression and not-found handling are unchanged. One exception: if a `mv -Rf` source vanishes between the walk and the delete, `--force` no longer suppresses the resulting error.

* A secret living at the root of a recursive copy is written to the destination once rather than twice.

* `safe import` of the version 2 format processes secrets in sorted path order rather than Go map order. The legacy v1 format is unchanged.

* `gen`, `ssh`, `rsa`, and `dhparam` print their per-path notices grouped by path, in the order the paths were given, after the parallel phase completes. The wording is unchanged.

* `safe dhparam` no longer streams OpenSSL's progress output to stderr. The generated parameters and all error reporting are unchanged.

# Upstream Convergence

* Requires `vaultkv` v0.7.1, which fixes connection reuse after error responses, a stale token on redirects, and mount lookup concurrency.

