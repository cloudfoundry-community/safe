# New Features

* **`safe export` and `safe import` now keep the type of every value.** Secrets written by the vault CLI, by Terraform, or by Vault itself can hold objects, lists, numbers, booleans, and null. Until this release an export turned each of those values into a string. A backup and restore therefore changed their types without any warning and v1.25.1 listed this as a known gap. When any exported value is not a string, export now writes a version 3 file. It has the same shape as the version 2 file, history included. It carries each value as the JSON that Vault returned, so a large integer keeps all of its digits. Import reads version 1, 2, and 3 files and writes each value back with its original type. It decodes every value in a version 3 file before it writes any of them, so a malformed file writes nothing.

* **Exports that hold only strings have not changed.** They come out byte for byte as the version 1 or version 2 file they always did, because Genesis and older safe binaries read those files. A safe older than v1.26.0 refuses a version 3 file as an unknown format and exits before it writes anything, so it can never import those values as strings by mistake. The README and the help for `export` and `import` describe when export picks version 3.

# Bug Fixes

* **`safe import -s` no longer panics on a secret with an empty version list.** It now writes nothing for that secret and moves on to the next one.

* **The `import` help describes `--ignore-destroyed` in full again.** A word was missing from the middle of that description, and we put it back.

# Internal

* The `crypt-md5`, `crypt-sha256`, and `crypt-sha512` formats now have tests that pin their output to vectors from `openssl passwd` and from the SHA-crypt spec. The output of these formats has not changed. The vectors will let us prove that any future replacement of the `tredoe/osutil` module is byte-compatible.

* We made two more flaky tests deterministic. The memory-mode `safe local` tests now pick a free port instead of the default 8219, so overlapping test runs no longer collide, and the x509 batch key generation test no longer depends on how fast the machine can generate keys.
