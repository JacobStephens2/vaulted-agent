#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# install-remote.sh — bootstrap vaulted-agent from a GitHub release.
#
# Thin installer meant to be hosted at a short URL and piped to bash:
#
#   curl -fsSL https://vaultedagent.com/install.sh | bash
#
# What it does:
#   1. Resolves a version (VAULTED_AGENT_VERSION, or the latest GitHub release)
#   2. Downloads that tagged source tree from GitHub (not from the marketing host).
#      The default tag's archive must match the sha256 recorded below before
#      extraction. A caller-supplied archive URL, a different tag, or another
#      repo is not checked against that digest.
#   3. Extracts the archive into its own directory and runs that install.sh
#      from there, as root
#
# Pin a version (recommended for shared hosts / repeatable deploys):
#
#   VAULTED_AGENT_VERSION=v0.3.0 curl -fsSL https://vaultedagent.com/install.sh | bash
#
# Pass flags through to install.sh after --:
#
#   curl -fsSL https://vaultedagent.com/install.sh | bash -s -- --user agent
#
# Prefer not to pipe to bash? Fetch, read, then run:
#
#   curl -fsSL -o /tmp/vaulted-agent-install.sh https://vaultedagent.com/install.sh
#   less /tmp/vaulted-agent-install.sh
#   bash /tmp/vaulted-agent-install.sh
#
# The vault token is never written by this script. After install you still put
# the service-account token in op.env / bws.env (or your chosen backend) yourself,
# or use auth_mode=prompt and paste it each launch.
# ---------------------------------------------------------------------------
set -euo pipefail

# Current repo name. GitHub redirects the former vaulted-agent-launcher paths,
# but a redirect is a courtesy, not a contract - name the repo as it is today.
# VAULTED_AGENT_REPO selects a different archive and skips the digest below.
DEFAULT_REPO="JacobStephens2/vaulted-agent"
REPO="${VAULTED_AGENT_REPO:-$DEFAULT_REPO}"
# Default pin. Overridden by VAULTED_AGENT_VERSION=... or "latest".
# scripts/release.sh prepare bumps it. Must match a published GitHub release
# tag (and Cargo.toml version).
DEFAULT_VERSION="v0.4.26"
# sha256 of the GitHub tag archive for DEFAULT_VERSION:
#   ${DEFAULT_REPO}/archive/refs/tags/${DEFAULT_VERSION}.tar.gz
# The tag's own copy of this file cannot know its archive's digest, so prepare
# empties it and deploy-site records it once the tag exists. Empty refuses the
# default archive. Caller-supplied versions are not checked against it.
DEFAULT_ARCHIVE_SHA256="51f43756cbb7bbad6f0eb74c74f0f2ea22dea6928e89147fa405a04ff36c4ad7"
VERSION="${VAULTED_AGENT_VERSION:-$DEFAULT_VERSION}"
GITHUB_API="${GITHUB_API:-https://api.github.com}"
GITHUB="${GITHUB:-https://github.com}"

die() { printf 'vaulted-agent install: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "need '$1' on PATH"; }

# Hex sha256 of one file. shasum first: macOS has shasum, Linux has both.
file_sha256() {
  local sum=""
  if command -v shasum >/dev/null 2>&1; then
    sum="$(shasum -a 256 -- "$1" | awk '{print $1}')"
  elif command -v sha256sum >/dev/null 2>&1; then
    sum="$(sha256sum -- "$1" | awk '{print $1}')"
  else
    die "need shasum or sha256sum to verify a checksum"
  fi
  [[ -n "$sum" ]] || die "could not hash $1"
  printf '%s\n' "$sum"
}

need curl
need tar
need mktemp

printf 'vaulted-agent remote install (pin %s; override with VAULTED_AGENT_VERSION=…)\n' \
  "$VERSION"

# Resolve "latest" via the GitHub releases API when asked. A missing release
# is a hard error — floating main is deliberately not a fallback.
resolve_version() {
  local v="$1" json tag
  if [[ "$v" != "latest" ]]; then
    printf '%s\n' "$v"
    return
  fi
  need grep
  need sed
  json="$(curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "$GITHUB_API/repos/$REPO/releases/latest")" \
    || die "could not fetch latest release for $REPO
  Create a GitHub release, or pin with VAULTED_AGENT_VERSION=vX.Y.Z"
  tag="$(printf '%s\n' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  [[ -n "$tag" ]] || die "latest release response had no tag_name"
  printf '%s\n' "$tag"
}

VERSION="$(resolve_version "$VERSION")"
# GitHub archive URLs accept both "v0.1.0" and "0.1.0"; tags in this repo use v*.
ARCHIVE_URL="${VAULTED_AGENT_ARCHIVE_URL:-$GITHUB/$REPO/archive/refs/tags/${VERSION}.tar.gz}"

# Prefer a release binary asset when present (no Rust toolchain on the host).
# One candidate per line, best first. Linux assets are static musl builds: they
# carry no glibc version dependency, so a single artifact runs on every distro.
# Releases through v0.4.0 published -gnu assets built against the CI runner's
# glibc (2.39), which ld.so refuses to load on older hosts; they stay in the
# list so pinned older versions still resolve, and try_asset drops one that
# cannot actually start here.
detect_assets() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os:$arch" in
    Linux:x86_64)
      printf 'vaulted-agent-x86_64-unknown-linux-musl\n'
      printf 'vaulted-agent-x86_64-unknown-linux-gnu\n' ;;
    Linux:aarch64|Linux:arm64)
      printf 'vaulted-agent-aarch64-unknown-linux-musl\n'
      printf 'vaulted-agent-aarch64-unknown-linux-gnu\n' ;;
    Darwin:x86_64) printf 'vaulted-agent-x86_64-apple-darwin\n' ;;
    Darwin:arm64)  printf 'vaulted-agent-aarch64-apple-darwin\n' ;;
    *) return 1 ;;
  esac
}

printf 'vaulted-agent remote install\n'
printf '  repo    : %s\n' "$REPO"
printf '  version : %s\n' "$VERSION"
printf '  source  : %s\n' "$ARCHIVE_URL"
printf '\n'

workdir="$(mktemp -d "${TMPDIR:-/tmp}/vaulted-agent.XXXXXX")"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

# Optional prebuilt binary (Rust runtime). Falls back to source-only install
# which builds with cargo if needed. A downloaded asset with no .sha256 sidecar
# stops the install; do not run an unverified release binary.
# Try one candidate asset. 0 = usable binary exported in VAULTED_AGENT_BIN,
# 1 = not available/not usable here, caller should try the next candidate.
try_asset() {
  local asset_name="$1" asset_url sum_url http_code bin expected got
  asset_url="$GITHUB/$REPO/releases/download/${VERSION}/${asset_name}.tar.gz"
  sum_url="${asset_url}.sha256"
  printf 'trying release binary: %s\n' "$asset_url"
  # Distinguish "no asset for this platform" (404) from rate-limit/403/network.
  http_code="$(curl -sS -o "$workdir/bin.tgz" -w '%{http_code}' -L "$asset_url" || true)"
  case "$http_code" in
    200) ;;
    404)
      printf '  (no %s asset in %s)\n' "$asset_name" "$VERSION"
      return 1
      ;;
    *)
      die "failed to download release binary (HTTP ${http_code:-?}): $asset_url
  Check network/rate limits, or set VAULTED_AGENT_BIN to a local binary."
      ;;
  esac

  # A release asset without its published checksum is not installed.
  # Missing and unreachable are the same outcome: stop, do not try the next
  # asset or a source build of an unverified binary.
  if ! curl -fsSL -o "$workdir/bin.tgz.sha256" "$sum_url"; then
    die "release asset ${asset_name} has no checksum; refusing to install"
  fi
  expected="$(awk 'NF { print $1; exit }' "$workdir/bin.tgz.sha256")"
  got="$(file_sha256 "$workdir/bin.tgz")"
  [[ -n "$expected" && "$got" == "$expected" ]] \
    || die "checksum verification failed for $asset_name"
  printf '  checksum ok\n'

  tar -xzf "$workdir/bin.tgz" -C "$workdir"
  # Accept either member name. release.yml stages the binary under the
  # per-target asset name, but a release cut by hand packages it under the
  # plain program name, and v0.4.3 shipped exactly that: a valid, correctly
  # checksummed musl binary that this function threw away over its name,
  # falling back to a source build and then failing outright on any host
  # without Rust. The name inside the archive is not worth an install failure.
  bin="$workdir/vaulted-agent"
  local staged=""
  for cand in "$workdir/$asset_name" "$bin"; do
    [[ -f "$cand" ]] && { staged="$cand"; break; }
  done
  if [[ -z "$staged" ]]; then
    printf '  (archive contained neither %s nor vaulted-agent)\n' "$asset_name" >&2
    return 1
  fi
  # Stage under the real program name. The launcher dispatches on argv[0]
  # (`vaulted-agent`, `va`, or a `*-conductor` link) and refuses anything else,
  # so running it under the per-target download name would fail on a perfectly
  # good binary. install.sh installs it as `vaulted-agent` regardless.
  [[ "$staged" == "$bin" ]] || mv -f "$staged" "$bin"
  chmod +x "$bin"

  # The asset has to actually start on this host. A glibc-linked asset built on
  # a newer runner dies at load time ("version `GLIBC_2.39' not found") on an
  # older distro, and the failure would otherwise only surface after install,
  # on first launch. Treat it as the wrong asset and fall through to the next
  # candidate or a source build. `version` touches no config and needs no root.
  if ! "$bin" version >/dev/null 2>&1; then
    printf '  warning: %s does not run on this host; skipping it\n' "$asset_name" >&2
    "$bin" version 2>&1 | sed 's/^/    /' >&2 || true
    rm -f "$bin"
    return 1
  fi

  export VAULTED_AGENT_BIN="$bin"
  printf '  using prebuilt binary %s\n' "$VAULTED_AGENT_BIN"
  return 0
}

# A caller who already exported VAULTED_AGENT_BIN has answered the question the
# asset probe asks, so do not ask it again. try_asset's own error text tells
# operators to set this when downloads fail; downloading anyway made that hint
# a lie, and left the offline/air-gapped path with no way through.
if [[ -n "${VAULTED_AGENT_BIN:-}" ]]; then
  printf 'using VAULTED_AGENT_BIN %s (skipping release assets)\n' "$VAULTED_AGENT_BIN"
else
  # Process substitution (not a pipe) so the export lands in this shell.
  while read -r candidate; do
    [[ -n "$candidate" ]] || continue
    try_asset "$candidate" && break
  done < <(detect_assets || true)

  if [[ -z "${VAULTED_AGENT_BIN:-}" ]]; then
    printf '  (no usable binary asset; will build from source if cargo is available)\n'
  fi
fi

tarball="$workdir/src.tar.gz"
printf 'downloading source…\n'
curl -fsSL -o "$tarball" "$ARCHIVE_URL" \
  || die "download failed: $ARCHIVE_URL
  Check that tag $VERSION exists on $REPO."

# The recorded digest applies only to the default tagged source archive.
# VAULTED_AGENT_ARCHIVE_URL and any other tag skip it: those overrides keep
# downloading whatever URL the caller named.
default_archive_url="${GITHUB}/${DEFAULT_REPO}/archive/refs/tags/${DEFAULT_VERSION}.tar.gz"
if [[ -z "${VAULTED_AGENT_ARCHIVE_URL:-}" && "$ARCHIVE_URL" == "$default_archive_url" ]]; then
  actual_digest="$(file_sha256 "$tarball")"
  [[ "$actual_digest" == "$DEFAULT_ARCHIVE_SHA256" ]] || die "default source archive does not match the recorded sha256 digest; refusing to extract
  expected ${DEFAULT_ARCHIVE_SHA256}
  got      ${actual_digest}"
  printf '  source digest ok\n'
fi

printf 'extracting…\n'
# Own directory, not $workdir. The release binary is already staged there, and
# a source archive extracted beside it can replace that binary or win the
# install.sh search. mktemp, not a fixed name: try_asset has already extracted
# the release asset into $workdir, so a fixed $workdir/source can already hold
# a directory whose install.sh the glob below would run instead of the
# archive's. GitHub names the top directory after the repo's *current* name
# plus the tag with any leading "v" stripped: archive/refs/tags/v0.1.0 →
# vaulted-agent-0.1.0. Do not match on that name.
# A rename keeps the old URL working by redirect while silently changing the
# directory inside the tarball, and matching a hardcoded
# 'vaulted-agent-launcher-*' is what broke every remote install when this repo
# became vaulted-agent. Identify the tree by what it contains, then run
# install.sh with that tree as the working directory.
src_root="$(mktemp -d "$workdir/src.XXXXXX")"
tar -xzf "$tarball" -C "$src_root"
src=""
for d in "$src_root"/*/; do
  [[ -f "${d}install.sh" ]] || continue
  src="${d%/}"
  break
done
[[ -n "$src" ]] || die "tarball did not contain install.sh (unexpected layout)"

printf 'running install.sh from %s\n\n' "$src"

# install.sh must be root for /usr/local/bin and /etc. Re-exec under sudo when
# we are not, preserving any flags the caller passed after bash -s -- …
# cd in the child so a caller-controlled working directory cannot satisfy
# a relative path inside install.sh.
if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo env \
      "SUDO_USER=${SUDO_USER:-$(id -un)}" \
      "SUDO_UID=${SUDO_UID:-$(id -u)}" \
      "SUDO_GID=${SUDO_GID:-$(id -g)}" \
      ${VAULTED_AGENT_BIN:+VAULTED_AGENT_BIN="$VAULTED_AGENT_BIN"} \
      bash -c 'cd "$1" && shift && exec bash ./install.sh "$@"' _ "$src" "$@"
  fi
  die "need root to install (re-run under sudo, or as root)"
fi

if [[ -n "${VAULTED_AGENT_BIN:-}" ]]; then
  export VAULTED_AGENT_BIN
fi
cd "$src"
bash ./install.sh "$@"
