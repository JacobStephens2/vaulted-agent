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
#   2. Downloads that tagged source tree from GitHub (not from the marketing host)
#   3. Runs the real install.sh from the tarball, as root
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

REPO="${VAULTED_AGENT_REPO:-JacobStephens2/vaulted-agent-launcher}"
# Default pin. Overridden by VAULTED_AGENT_VERSION=... or "latest".
# Bump this when cutting a release so unpinned one-liners stay intentional.
# Must match a published GitHub release tag (and Cargo.toml version).
DEFAULT_VERSION="v0.4.13"
VERSION="${VAULTED_AGENT_VERSION:-$DEFAULT_VERSION}"
GITHUB_API="${GITHUB_API:-https://api.github.com}"
GITHUB="${GITHUB:-https://github.com}"

die() { printf 'vaulted-agent install: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "need '$1' on PATH"; }

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
# which builds with cargo if needed. Verify .tar.gz.sha256 when present.
# Try one candidate asset. 0 = usable binary exported in VAULTED_AGENT_BIN,
# 1 = not available/not usable here, caller should try the next candidate.
try_asset() {
  local asset_name="$1" asset_url sum_url http_code bin
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

  # Prefer verifying the published checksum when available.
  if curl -fsSL -o "$workdir/bin.tgz.sha256" "$sum_url"; then
    (
      cd "$workdir"
      if command -v shasum >/dev/null 2>&1; then
        echo "$(awk '{print $1}' bin.tgz.sha256)  bin.tgz" | shasum -a 256 -c -
      elif command -v sha256sum >/dev/null 2>&1; then
        echo "$(awk '{print $1}' bin.tgz.sha256)  bin.tgz" | sha256sum -c -
      else
        die "need shasum or sha256sum to verify release checksum"
      fi
    ) || die "checksum verification failed for $asset_name"
    printf '  checksum ok\n'
  else
    printf '  warning: no .sha256 asset; installing without checksum verification\n' >&2
  fi

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

# Process substitution (not a pipe) so the export lands in this shell.
while read -r candidate; do
  [[ -n "$candidate" ]] || continue
  try_asset "$candidate" && break
done < <(detect_assets || true)

if [[ -z "${VAULTED_AGENT_BIN:-}" ]]; then
  printf '  (no usable binary asset; will build from source if cargo is available)\n'
fi

tarball="$workdir/src.tar.gz"
printf 'downloading source…\n'
curl -fsSL -o "$tarball" "$ARCHIVE_URL" \
  || die "download failed: $ARCHIVE_URL
  Check that tag $VERSION exists on $REPO."

printf 'extracting…\n'
tar -xzf "$tarball" -C "$workdir"
# archive-refs/tags/v0.1.0 → vaulted-agent-launcher-0.1.0 (GitHub strips a
# leading "v" from the directory name inside the tarball).
src="$(find "$workdir" -mindepth 1 -maxdepth 1 -type d -name 'vaulted-agent-launcher-*' | head -n1)"
[[ -n "$src" && -f "$src/install.sh" ]] \
  || die "tarball did not contain install.sh (unexpected layout)"

printf 'running install.sh from %s\n\n' "$VERSION"

# install.sh must be root for /usr/local/bin and /etc. Re-exec under sudo when
# we are not, preserving any flags the caller passed after bash -s -- …
if [[ "$(id -u)" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo env \
      "SUDO_USER=${SUDO_USER:-$(id -un)}" \
      "SUDO_UID=${SUDO_UID:-$(id -u)}" \
      "SUDO_GID=${SUDO_GID:-$(id -g)}" \
      ${VAULTED_AGENT_BIN:+VAULTED_AGENT_BIN="$VAULTED_AGENT_BIN"} \
      bash "$src/install.sh" "$@"
  fi
  die "need root to install (re-run under sudo, or as root)"
fi

if [[ -n "${VAULTED_AGENT_BIN:-}" ]]; then
  export VAULTED_AGENT_BIN
fi
bash "$src/install.sh" "$@"
