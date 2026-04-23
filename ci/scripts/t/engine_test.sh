#!/usr/bin/env bash
# Unit tests for ci/scripts/lib/engine.sh — asserts download URLs,
# archive extensions, binary names, and per-engine os/arch aliases
# for every supported {engine × os × arch} combination.
#
# Plain bash (no bats dependency). Run with:
#   bash ci/scripts/t/engine_test.sh
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
LIB="$SCRIPT_DIR/../lib/engine.sh"

fail_count=0
pass_count=0

assert_eq() {
  local label="$1" want="$2" got="$3"
  if [[ "$want" == "$got" ]]; then
    pass_count=$((pass_count + 1))
    echo "ok   — $label"
  else
    fail_count=$((fail_count + 1))
    echo "FAIL — $label"
    echo "       want: $want"
    echo "       got:  $got"
  fi
}

assert_fails() {
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then
    fail_count=$((fail_count + 1))
    echo "FAIL — $label (expected non-zero exit)"
  else
    pass_count=$((pass_count + 1))
    echo "ok   — $label"
  fi
}

if [[ ! -f "$LIB" ]]; then
  echo "FAIL — $LIB not found"
  echo "       expected functions: engine_url, engine_archive_ext,"
  echo "       engine_binary_name, engine_local_binary, engine_arch_for,"
  echo "       engine_os_for"
  exit 1
fi

# shellcheck source=/dev/null
source "$LIB"

# ----- engine_url -----------------------------------------------------------
assert_eq "engine_url vault linux amd64" \
  "https://releases.hashicorp.com/vault/1.13.2/vault_1.13.2_linux_amd64.zip" \
  "$(engine_url vault 1.13.2 linux amd64)"

assert_eq "engine_url vault darwin arm64" \
  "https://releases.hashicorp.com/vault/1.13.2/vault_1.13.2_darwin_arm64.zip" \
  "$(engine_url vault 1.13.2 darwin arm64)"

assert_eq "engine_url bao linux amd64 (→ Linux / x86_64)" \
  "https://github.com/openbao/openbao/releases/download/v2.5.3/bao_2.5.3_Linux_x86_64.tar.gz" \
  "$(engine_url bao 2.5.3 linux amd64)"

assert_eq "engine_url bao darwin arm64 (→ Darwin / arm64)" \
  "https://github.com/openbao/openbao/releases/download/v2.5.3/bao_2.5.3_Darwin_arm64.tar.gz" \
  "$(engine_url bao 2.5.3 darwin arm64)"

assert_eq "engine_url bao linux arm64" \
  "https://github.com/openbao/openbao/releases/download/v2.5.3/bao_2.5.3_Linux_arm64.tar.gz" \
  "$(engine_url bao 2.5.3 linux arm64)"

# ----- engine_archive_ext ---------------------------------------------------
assert_eq "engine_archive_ext vault" "zip"    "$(engine_archive_ext vault)"
assert_eq "engine_archive_ext bao"   "tar.gz" "$(engine_archive_ext bao)"

# ----- engine_binary_name ---------------------------------------------------
assert_eq "engine_binary_name vault" "vault" "$(engine_binary_name vault)"
assert_eq "engine_binary_name bao"   "bao"   "$(engine_binary_name bao)"

# ----- engine_local_binary --------------------------------------------------
assert_eq "engine_local_binary vault darwin 1.13.2" \
  "vault-darwin-1.13.2" "$(engine_local_binary vault darwin 1.13.2)"
assert_eq "engine_local_binary bao linux 2.5.3" \
  "bao-linux-2.5.3"     "$(engine_local_binary bao linux 2.5.3)"

# ----- engine_arch_for (per-engine alias) -----------------------------------
assert_eq "engine_arch_for vault x86_64" "amd64"  "$(engine_arch_for vault x86_64)"
assert_eq "engine_arch_for vault amd64"  "amd64"  "$(engine_arch_for vault amd64)"
assert_eq "engine_arch_for vault aarch64" "arm64" "$(engine_arch_for vault aarch64)"
assert_eq "engine_arch_for vault arm64"  "arm64"  "$(engine_arch_for vault arm64)"

assert_eq "engine_arch_for bao x86_64"  "x86_64" "$(engine_arch_for bao x86_64)"
assert_eq "engine_arch_for bao amd64"   "x86_64" "$(engine_arch_for bao amd64)"
assert_eq "engine_arch_for bao aarch64" "arm64"  "$(engine_arch_for bao aarch64)"
assert_eq "engine_arch_for bao arm64"   "arm64"  "$(engine_arch_for bao arm64)"

# ----- engine_os_for --------------------------------------------------------
assert_eq "engine_os_for vault linux"  "linux"  "$(engine_os_for vault linux)"
assert_eq "engine_os_for vault darwin" "darwin" "$(engine_os_for vault darwin)"
assert_eq "engine_os_for bao linux"    "Linux"  "$(engine_os_for bao linux)"
assert_eq "engine_os_for bao darwin"   "Darwin" "$(engine_os_for bao darwin)"

# ----- engine_startup_mode --------------------------------------------------
assert_eq "engine_startup_mode vault" "dev"    "$(engine_startup_mode vault)"
assert_eq "engine_startup_mode bao"   "config" "$(engine_startup_mode bao)"

# ----- error paths ----------------------------------------------------------
assert_fails "engine_url rejects unknown engine" \
  engine_url glorp 1.0.0 linux amd64
assert_fails "engine_arch_for rejects unknown arch" \
  engine_arch_for vault riscv64
assert_fails "engine_os_for rejects unknown os" \
  engine_os_for bao plan9
assert_fails "engine_startup_mode rejects unknown engine" \
  engine_startup_mode glorp

# ----- summary --------------------------------------------------------------
echo
echo "---------------------------------------"
echo "  passed: $pass_count"
echo "  failed: $fail_count"
echo "---------------------------------------"

if [[ $fail_count -gt 0 ]]; then
  exit 1
fi
