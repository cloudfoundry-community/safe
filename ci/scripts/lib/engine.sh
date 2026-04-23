#!/usr/bin/env bash
# Per-engine URL/format/binary helpers for the safe round-trip test suite.
# Supports the HashiCorp Vault binary (engine=vault) and the OpenBao binary
# (engine=bao). Vault uses lowercase-OS/amd64/zip; OpenBao uses capitalised-OS,
# the x86_64 arch alias, and tar.gz. Callers pass the canonical lowercase
# form (linux|darwin, amd64|arm64) and the helpers translate per engine.
#
# This file defines functions only; source it — do not execute.

_engine_lib_warn() {
  echo >&2 "engine.sh: $*"
}

engine_arch_for() {
  local engine="$1" raw="$2"
  case "$engine" in
    vault)
      case "$raw" in
        x86_64|amd64)  echo amd64 ;;
        aarch64|arm64) echo arm64 ;;
        *) _engine_lib_warn "unsupported arch for vault: $raw"; return 1 ;;
      esac
      ;;
    bao)
      case "$raw" in
        x86_64|amd64)  echo x86_64 ;;
        aarch64|arm64) echo arm64  ;;
        *) _engine_lib_warn "unsupported arch for bao: $raw"; return 1 ;;
      esac
      ;;
    *) _engine_lib_warn "unknown engine: $engine"; return 1 ;;
  esac
}

engine_os_for() {
  local engine="$1" raw="$2"
  case "$engine" in
    vault)
      case "$raw" in
        linux|darwin) echo "$raw" ;;
        *) _engine_lib_warn "unsupported os for vault: $raw"; return 1 ;;
      esac
      ;;
    bao)
      case "$raw" in
        linux)  echo Linux  ;;
        darwin) echo Darwin ;;
        *) _engine_lib_warn "unsupported os for bao: $raw"; return 1 ;;
      esac
      ;;
    *) _engine_lib_warn "unknown engine: $engine"; return 1 ;;
  esac
}

engine_archive_ext() {
  case "$1" in
    vault) echo zip    ;;
    bao)   echo tar.gz ;;
    *) _engine_lib_warn "unknown engine: $1"; return 1 ;;
  esac
}

engine_binary_name() {
  case "$1" in
    vault) echo vault ;;
    bao)   echo bao   ;;
    *) _engine_lib_warn "unknown engine: $1"; return 1 ;;
  esac
}

engine_local_binary() {
  local engine="$1" os="$2" version="$3"
  local bin
  bin="$(engine_binary_name "$engine")" || return 1
  echo "${bin}-${os}-${version}"
}

engine_startup_mode() {
  case "$1" in
    vault) echo dev    ;;
    bao)   echo config ;;
    *) _engine_lib_warn "unknown engine: $1"; return 1 ;;
  esac
}

engine_url() {
  local engine="$1" version="$2" raw_os="$3" raw_arch="$4"
  local os arch ext
  os="$(engine_os_for   "$engine" "$raw_os")"   || return 1
  arch="$(engine_arch_for "$engine" "$raw_arch")" || return 1
  ext="$(engine_archive_ext "$engine")"           || return 1
  case "$engine" in
    vault) echo "https://releases.hashicorp.com/vault/${version}/vault_${version}_${os}_${arch}.${ext}" ;;
    bao)   echo "https://github.com/openbao/openbao/releases/download/v${version}/bao_${version}_${os}_${arch}.${ext}" ;;
    *) _engine_lib_warn "unknown engine: $engine"; return 1 ;;
  esac
}
