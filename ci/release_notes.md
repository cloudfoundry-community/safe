# Bug Fixes

* **`safe set`, `ask`, and `paste` no longer fail on Vault CE 1.21.3 and later, and they no longer change the type of values they did not touch.** Those Vault versions return `alias_metadata: {}` on every auth role that uses the shared token fields. These commands update a path by reading it and writing every key back, and that read turned each value that was not a string into its JSON text. Vault refuses the string `"{}"` for `alias_metadata`, so a `set` on any such role failed with `invalid key pair "{}"`, even though `vault write` on the same path worked. The same read also changed fields that Vault does accept as strings, so a `token_policies` list of `["a"]` came back as one policy named `["a"]`.

* **`safe rm path:key`, `cp`, `mv`, and `revert` had the same problem, and they are fixed too.** Removing one key sent the keys it kept back as strings, so `alias_metadata` failed the same way. Copying or moving one key did that to the destination's untouched values, and the copied value itself landed as a string even when it was an object or a list. Copying a whole secret took a different route, through the tree walk, and it now writes the raw JSON on KV v1 and on KV v2. A key that is copied or moved keeps the type it had at its source.

* **KV secrets written by other tools keep their objects, lists, numbers, and booleans.** Before this release, the next `safe set` turned each of those values into a string, and a large integer also lost its low digits on the way through a float. All of these commands now send untouched values back with their JSON type, and a key that you set yourself still goes out as the string you gave. What `get`, `export`, and the formats display does not change, because the secret still holds the same strings.

* **`safe get` now reports a YAML encoding failure instead of printing an empty document.** Before, a failed encode looked the same as a secret with nothing in it, and the command exited cleanly. It now fails with a message that names the path.

* **The unknown-target error now says where the name came from.** A missing target used to read `Current target 'X' not found in ~/.saferc` even when `X` came from `-T` or from `$SAFE_TARGET`, which sent people looking for a problem in their saved selection. The message now reads `Target 'X' (from -T)` or `Target 'X' (from $SAFE_TARGET)` for a name you handed in, and it keeps the old wording for the saved current target. A name that equals `$SAFE_TARGET` is reported as coming from the environment, because the option parser folds the two into one value.

* **`make shipit` now refuses a defaulted or slashed `VERSION`.** The Makefile defaults `VERSION` to `dev/<branch>/<sha>`, so a run without it compiled every binary and only then failed, because the default contains a slash. The release targets now fail at the start unless `VERSION` came from the command line or the environment and contains no slash.

# Known Gaps

* **`safe export` and `safe import` still turn non-string values into strings.** The typed write-back covers the commands above but not these two, so an export and import round trip can still change the type of an object, list, number, or boolean. A later release will address that.

# Dependencies

* `safe` now builds with Go 1.27.3, and we updated `golang.org/x/crypto`, `golang.org/x/net`, and `golang.org/x/term` to their current releases.

# Internal

* We made a flaky `safe local` raft test deterministic and recorded our keep decisions for six modules that modrot flags as stale, and neither change affects the product.
