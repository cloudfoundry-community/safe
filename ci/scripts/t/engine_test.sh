#!/usr/bin/env bash
# Unit tests for ci/scripts/lib/engine.sh -- asserts download URLs, archive
# extensions, binary names, arch/os normalisation, and the OpenBao minimum
# version guard.
#
# Plain bash, no bats dependency and no network. Run with:
#   make test-engine-lib
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
  exit 1
fi

# shellcheck source=/dev/null
source "$LIB"

# ----- engine_url: vault ----------------------------------------------------
assert_eq "engine_url vault linux amd64" \
  "https://releases.hashicorp.com/vault/1.13.13/vault_1.13.13_linux_amd64.zip" \
  "$(engine_url vault 1.13.13 linux amd64)"

assert_eq "engine_url vault darwin arm64" \
  "https://releases.hashicorp.com/vault/1.13.13/vault_1.13.13_darwin_arm64.zip" \
  "$(engine_url vault 1.13.13 darwin arm64)"

# ----- engine_url: bao ------------------------------------------------------
# OpenBao 2.6.0 renamed its assets from bao_2.5.5_Linux_x86_64.tar.gz to
# openbao_2.6.1_linux_amd64.tar.gz. Only the 2.6+ spelling is built.
assert_eq "engine_url bao linux amd64" \
  "https://github.com/openbao/openbao/releases/download/v2.6.1/openbao_2.6.1_linux_amd64.tar.gz" \
  "$(engine_url bao 2.6.1 linux amd64)"

assert_eq "engine_url bao linux arm64" \
  "https://github.com/openbao/openbao/releases/download/v2.6.1/openbao_2.6.1_linux_arm64.tar.gz" \
  "$(engine_url bao 2.6.1 linux arm64)"

assert_eq "engine_url bao darwin arm64" \
  "https://github.com/openbao/openbao/releases/download/v2.6.1/openbao_2.6.1_darwin_arm64.tar.gz" \
  "$(engine_url bao 2.6.1 darwin arm64)"

# uname -m spellings normalise before reaching the URL.
assert_eq "engine_url bao normalises x86_64" \
  "https://github.com/openbao/openbao/releases/download/v2.6.1/openbao_2.6.1_linux_amd64.tar.gz" \
  "$(engine_url bao 2.6.1 linux x86_64)"

assert_eq "engine_url vault normalises aarch64" \
  "https://releases.hashicorp.com/vault/1.13.13/vault_1.13.13_linux_arm64.zip" \
  "$(engine_url vault 1.13.13 linux aarch64)"

# ----- OpenBao minimum version ----------------------------------------------
assert_fails "engine_url rejects OpenBao 2.5.5 (pre-2.6 asset naming)" \
  engine_url bao 2.5.5 linux amd64
assert_fails "engine_url rejects OpenBao 1.9.0" \
  engine_url bao 1.9.0 linux amd64
assert_eq "engine_url accepts the 2.6.0 boundary" \
  "https://github.com/openbao/openbao/releases/download/v2.6.0/openbao_2.6.0_linux_amd64.tar.gz" \
  "$(engine_url bao 2.6.0 linux amd64)"
assert_eq "engine_url accepts a later major" \
  "https://github.com/openbao/openbao/releases/download/v3.0.0/openbao_3.0.0_linux_amd64.tar.gz" \
  "$(engine_url bao 3.0.0 linux amd64)"

# A version given without a patch component, and one carrying a pre-release
# suffix, are both compared against the floor rather than rejected outright.
assert_eq "engine_url accepts a two-component version" \
  "https://github.com/openbao/openbao/releases/download/v2.7/openbao_2.7_linux_amd64.tar.gz" \
  "$(engine_url bao 2.7 linux amd64)"
assert_fails "engine_url rejects a two-component version below the floor" \
  engine_url bao 2.5 linux amd64
assert_eq "engine_url accepts a pre-release above the floor" \
  "https://github.com/openbao/openbao/releases/download/v2.7.0-beta20260622/openbao_2.7.0-beta20260622_linux_amd64.tar.gz" \
  "$(engine_url bao 2.7.0-beta20260622 linux amd64)"

# Zero-padded components must not be read as octal (10#08 vs 08).
assert_eq "engine_url handles a zero-padded component" \
  "https://releases.hashicorp.com/vault/1.08.9/vault_1.08.9_linux_amd64.zip" \
  "$(engine_url vault 1.08.9 linux amd64)"

# ----- version normalisation ------------------------------------------------
# A leading v -- the spelling of the release tags themselves -- is accepted
# and stripped; a version that is not dotted numbers is refused up front
# rather than surfacing as a bash arithmetic error and a bogus
# older-than-the-floor diagnosis.
assert_eq "engine_url strips a leading v (bao)" \
  "https://github.com/openbao/openbao/releases/download/v2.6.1/openbao_2.6.1_linux_amd64.tar.gz" \
  "$(engine_url bao v2.6.1 linux amd64)"
assert_eq "engine_url strips a leading v (vault)" \
  "https://releases.hashicorp.com/vault/1.13.13/vault_1.13.13_linux_amd64.zip" \
  "$(engine_url vault v1.13.13 linux amd64)"
assert_fails "engine_url rejects an empty version"        engine_url bao "" linux amd64
assert_fails "engine_url rejects a non-numeric version"   engine_url bao vlatest linux amd64
assert_fails "engine_url rejects garbage version (vault)" engine_url vault banana linux amd64

# A Vault version is not held to the OpenBao floor.
assert_eq "engine_url does not apply the bao floor to vault" \
  "https://releases.hashicorp.com/vault/1.9.10/vault_1.9.10_linux_amd64.zip" \
  "$(engine_url vault 1.9.10 linux amd64)"

# ----- engine_archive_ext ---------------------------------------------------
assert_eq "engine_archive_ext vault" "zip"    "$(engine_archive_ext vault)"
assert_eq "engine_archive_ext bao"   "tar.gz" "$(engine_archive_ext bao)"

# ----- engine_binary_name ---------------------------------------------------
# The OpenBao archive is named openbao_* but the binary inside it is bao.
assert_eq "engine_binary_name vault" "vault" "$(engine_binary_name vault)"
assert_eq "engine_binary_name bao"   "bao"   "$(engine_binary_name bao)"

# ----- engine_local_binary --------------------------------------------------
assert_eq "engine_local_binary vault darwin 1.13.13" \
  "vault-darwin-1.13.13" "$(engine_local_binary vault darwin 1.13.13)"
assert_eq "engine_local_binary bao linux 2.6.1" \
  "bao-linux-2.6.1"      "$(engine_local_binary bao linux 2.6.1)"

# ----- normalize_arch / normalize_os ----------------------------------------
assert_eq "normalize_arch x86_64"  "amd64" "$(normalize_arch x86_64)"
assert_eq "normalize_arch amd64"   "amd64" "$(normalize_arch amd64)"
assert_eq "normalize_arch aarch64" "arm64" "$(normalize_arch aarch64)"
assert_eq "normalize_arch arm64"   "arm64" "$(normalize_arch arm64)"
assert_eq "normalize_os linux"     "linux"  "$(normalize_os linux)"
assert_eq "normalize_os darwin"    "darwin" "$(normalize_os darwin)"

# ----- engine_startup_mode --------------------------------------------------
# Vault's -dev server is enough; OpenBao needs a written config to re-enable
# the rekey endpoints, so it starts from a config file instead.
assert_eq "engine_startup_mode vault" "dev"    "$(engine_startup_mode vault)"
assert_eq "engine_startup_mode bao"   "config" "$(engine_startup_mode bao)"

# ----- error paths ----------------------------------------------------------
assert_fails "engine_url rejects an unknown engine"          engine_url glorp 1.0.0 linux amd64
assert_fails "engine_archive_ext rejects an unknown engine"  engine_archive_ext glorp
assert_fails "engine_binary_name rejects an unknown engine"  engine_binary_name glorp
assert_fails "engine_local_binary rejects an unknown engine" engine_local_binary glorp linux 1.0.0
assert_fails "engine_startup_mode rejects an unknown engine" engine_startup_mode glorp
assert_fails "normalize_arch rejects an unknown arch"        normalize_arch riscv64
assert_fails "normalize_os rejects an unknown os"            normalize_os plan9
assert_fails "engine_url rejects an unknown arch"            engine_url vault 1.13.13 linux riscv64
assert_fails "engine_url rejects an unknown os"              engine_url bao 2.6.1 plan9 amd64

# ----- summary --------------------------------------------------------------
echo
echo "---------------------------------------"
echo "  passed: $pass_count"
echo "  failed: $fail_count"
echo "---------------------------------------"

if [[ $fail_count -gt 0 ]]; then
  exit 1
fi
