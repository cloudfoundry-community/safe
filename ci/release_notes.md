# Behavior Changes

* **The warning printed when TLS certificate verification is disabled is now off by default.** v1.22.0 wrote that line to stderr unconditionally whenever a target set `skip_verify`, which broke tooling that wraps `safe` and either parses its stderr or expects it to stay quiet. Targeting a Vault with a self-signed certificate is routine rather than exceptional, so the notice is now opt-in: set `SAFE_SKIP_VERIFY_WARNING=1` to get it back. `safe envvars` documents it. Whether certificates are verified is unchanged either way; only the warning changed.

# Dependencies

* `safe` builds against Go 1.27.1.

* `safe` no longer depends directly on an archived library. `gopkg.in/yaml.v2`, archived in April 2025, gives way to its maintained successor `go.yaml.in/yaml/v2` v2.4.4. `github.com/pborman/uuid` gives way to `github.com/google/uuid` v1.6.0, which it wrapped and which `safe` already carried indirectly. YAML parsing and rendering are unchanged, and `safe uuid` writes the same version 4 UUIDs, though it now reports a failed entropy draw rather than proceeding past it.

* `golang.org/x/crypto` moves to v0.56.0 and `github.com/gofrs/flock` to v0.13.1.
