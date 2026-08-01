#!/usr/bin/env bash
# Download and startup helpers for the safe round-trip suite, which can run
# against either HashiCorp Vault (engine=vault) or OpenBao (engine=bao).
# OpenBao forked from Vault and kept the same server, secrets, auth, and
# operator command surface, so the suite itself runs unchanged on both.
#
# OpenBao renamed its release assets in 2.6.0:
#
#   2.5.x and earlier   bao_2.5.5_Linux_x86_64.tar.gz
#   2.6.0 and later     openbao_2.6.1_linux_amd64.tar.gz
#
# The 2.6 spelling matches the one Vault already uses, so only 2.6+ is
# supported here and the engines differ in archive name and extension alone.
# Asking for an older OpenBao is an error naming the floor rather than a 404
# from a URL built to the wrong scheme.
#
# This file defines functions only; source it -- do not execute.

# OPENBAO_MIN_VERSION is the oldest OpenBao whose assets follow the current
# naming scheme.
OPENBAO_MIN_VERSION=2.6.0

_engine_lib_warn() {
  echo >&2 "engine.sh: $*"
}

# normalize_arch maps uname -m spellings onto the arch token both engines use
# in their release asset names.
normalize_arch() {
  case "$1" in
    x86_64|amd64)  echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) _engine_lib_warn "unsupported arch: $1"; return 1 ;;
  esac
}

# normalize_os does the same for the OS token. Both engines publish lowercase
# GOOS names.
normalize_os() {
  case "$1" in
    linux|darwin) echo "$1" ;;
    *) _engine_lib_warn "unsupported os: $1"; return 1 ;;
  esac
}

engine_archive_ext() {
  case "$1" in
    vault) echo zip    ;;
    bao)   echo tar.gz ;;
    *) _engine_lib_warn "unknown engine: $1"; return 1 ;;
  esac
}

# engine_binary_name is the executable's name, which for OpenBao is bao even
# though the archive it ships in is named openbao.
engine_binary_name() {
  case "$1" in
    vault) echo vault ;;
    bao)   echo bao   ;;
    *) _engine_lib_warn "unknown engine: $1"; return 1 ;;
  esac
}

# engine_local_binary is the cache name a downloaded engine is stored under in
# ./vaults, so several engines and versions can coexist across runs.
engine_local_binary() {
  local engine="$1" os="$2" version="$3"
  local bin
  bin="$(engine_binary_name "$engine")" || return 1
  echo "${bin}-${os}-${version}"
}

# engine_startup_mode says how restart_engine_server should bring the server
# up. Vault's -dev server suffices; OpenBao needs a written config to re-enable
# the rekey endpoints it disables by default.
engine_startup_mode() {
  case "$1" in
    vault) echo dev    ;;
    bao)   echo config ;;
    *) _engine_lib_warn "unknown engine: $1"; return 1 ;;
  esac
}

# _version_key collapses a dotted numeric version into a single sortable
# integer, ignoring any pre-release suffix and tolerating a missing minor or
# patch. Parameter expansion only: no arrays, and no shelling out to sort -V,
# which BSD sort has not always had.
_version_key() {
  local v="${1%%-*}" major minor patch rest
  major="${v%%.*}"
  rest="${v#*.}"
  if [[ "$rest" == "$v" ]]; then rest="0"; fi
  minor="${rest%%.*}"
  patch="${rest#*.}"
  if [[ "$patch" == "$rest" ]]; then patch="0"; fi
  patch="${patch%%.*}"
  # 10# forces base ten, so a zero-padded component is not read as octal.
  echo $(( 10#${major:-0} * 1000000 + 10#${minor:-0} * 1000 + 10#${patch:-0} ))
}

# _version_ge returns 0 when version $1 is at least version $2.
_version_ge() {
  [ "$(_version_key "$1")" -ge "$(_version_key "$2")" ]
}

# engine_version normalizes a requested version: a leading v -- the spelling
# of the release tags themselves -- is dropped, and anything that is not
# dotted numbers (with an optional pre-release suffix) is refused up front,
# rather than surfacing later as a bash arithmetic error and a misleading
# older-than-the-floor diagnosis.
engine_version() {
  local v="${1#v}"
  if [[ ! "$v" =~ ^[0-9]+(\.[0-9]+){0,2}(-[0-9A-Za-z.]+)?$ ]]; then
    _engine_lib_warn "invalid version: '${1}'"
    return 1
  fi
  echo "$v"
}

engine_url() {
  local engine="$1" version="$2" raw_os="$3" raw_arch="$4"
  local os arch ext
  version="$(engine_version "$version")" || return 1
  ext="$(engine_archive_ext "$engine")" || return 1
  os="$(normalize_os "$raw_os")"        || return 1
  arch="$(normalize_arch "$raw_arch")"  || return 1

  case "$engine" in
    vault)
      echo "https://releases.hashicorp.com/vault/${version}/vault_${version}_${os}_${arch}.${ext}"
      ;;
    bao)
      if ! _version_ge "$version" "$OPENBAO_MIN_VERSION"; then
        _engine_lib_warn "OpenBao ${version} is older than ${OPENBAO_MIN_VERSION}, whose release assets were renamed; only ${OPENBAO_MIN_VERSION} and later are supported"
        return 1
      fi
      echo "https://github.com/openbao/openbao/releases/download/v${version}/openbao_${version}_${os}_${arch}.${ext}"
      ;;
    *)
      _engine_lib_warn "unknown engine: $engine"
      return 1
      ;;
  esac
}
