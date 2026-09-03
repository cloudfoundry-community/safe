# Behavior Changes

* **A hand-edited `~/.saferc` that spells a boolean the YAML 1.1 way (`skip_verify: yes`, `on`, `y`, or their negatives) is now rejected.** `safe` reads its configuration with YAML 1.2 scalar rules, under which those words are strings, and reports the line and column of the offending value. Files written by `safe` are unaffected: it has only ever written `true` or `false`. Change the word to `true` or `false` and the file loads again.

# Dependencies

* `safe` now reads and writes YAML with `github.com/goccy/go-yaml` v1.19.2, the library our other Go tools use, in place of `go.yaml.in/yaml/v2`. `~/.saferc`, `~/.svtoken`, and `safe get -K` output are byte-for-byte unchanged. In `safe get` output, values that need quoting are now double-quoted rather than single-quoted, and long values are no longer folded at 80 columns. Every value reads back identically in any YAML parser. Values that the new library would otherwise write ambiguously, such as a secret beginning with `? ` or spelled like a number, are quoted explicitly so they always parse back as strings.
