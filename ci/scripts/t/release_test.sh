#!/usr/bin/env bash
# Tests for the VERSION guard shared by `make shipit` and `make release-all`.
# The guard runs before any build step, so these runs are fast and offline.
#
#   make test-release-lib
#   bash ci/scripts/t/release_test.sh
set -u

SCRIPT_DIR="$(dirname -- "${BASH_SOURCE[0]}")"
REPO="$SCRIPT_DIR/../../.."

fail_count=0
pass_count=0

report() {
  local label="$1" ok="$2" out="$3"
  if [[ $ok == 1 ]]; then
    pass_count=$((pass_count + 1))
    echo "ok   — $label"
  else
    fail_count=$((fail_count + 1))
    echo "FAIL — $label"
    echo "$out" | sed 's/^/       /'
  fi
}

# check LABEL WANT_FAILURE(1|0) WANT_TEXT make-args...
check() {
  local label="$1" want_fail="$2" want_text="$3"; shift 3
  local out status ok=1
  out="$(env -u VERSION make -C "$REPO" "$@" 2>&1)"
  status=$?
  if [[ $want_fail == 1 && $status -eq 0 ]]; then ok=0; fi
  if [[ $want_fail == 0 && $status -ne 0 ]]; then ok=0; fi
  if [[ -n "$want_text" && "$out" != *"$want_text"* ]]; then ok=0; fi
  report "$label" "$ok" "$out"
}

check "shipit refuses an unset VERSION"       1 "VERSION must be given explicitly" shipit
check "release-all refuses an unset VERSION"  1 "VERSION must be given explicitly" release-all
check "shipit refuses a VERSION with a slash" 1 "not feature/x" shipit VERSION=feature/x
check "release-all refuses a slash VERSION"   1 "not feature/x" release-all VERSION=feature/x
check "the guard accepts an explicit VERSION" 0 "" release-version-check VERSION=1.2.3

# An environment-supplied VERSION counts as explicit.
ok=0
out="$(VERSION=1.2.3 make -C "$REPO" release-version-check 2>&1)" && ok=1
report "the guard accepts VERSION from the environment" "$ok" "$out"

echo
echo "---------------------------------------"
echo "  passed: $pass_count"
echo "  failed: $fail_count"
echo "---------------------------------------"

[[ $fail_count -eq 0 ]]
