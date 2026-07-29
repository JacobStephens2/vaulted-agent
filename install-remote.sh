#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# install-remote.sh — bootstrap vaulted-agent from a GitHub release.
#
# Thin installer meant to be hosted at a short URL and piped to bash:
#
#   curl -fsSL https://stephens.page/vaulted-agent/install.sh | bash
#
# What it does:
#   1. Resolves a version (VAULTED_AGENT_VERSION, or the latest GitHub release)
#   2. Downloads that tagged source tree from GitHub (not from the marketing host)
#   3. Runs the real install.sh from the tarball, as root
#
# Pin a version (recommended for shared hosts / repeatable deploys):
#
#   VAULTED_AGENT_VERSION=v0.2.0 curl -fsSL https://stephens.page/vaulted-agent/install.sh | bash
#
# Pass flags through to install.sh after --:
#
#   curl -fsSL https://stephens.page/vaulted-agent/install.sh | bash -s -- --user agent
#
# Prefer not to pipe to bash? Fetch, read, then run:
#
#   curl -fsSL -o /tmp/vaulted-agent-install.sh https://stephens.page/vaulted-agent/install.sh
#   less /tmp/vaulted-agent-install.sh
#   bash /tmp/vaulted-agent-install.sh
#
# The vault token is never written by this script. After install you still put
# the service-account token in op.env (or your chosen backend) yourself.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO="${VAULTED_AGENT_REPO:-JacobStephens2/vaulted-agent-launcher}"
# Default pin. Overridden by VAULTED_AGENT_VERSION=... or "latest".
# Bump this when cutting a release so unpinned one-liners stay intentional.
DEFAULT_VERSION="v0.2.0"
VERSION="${VAULTED_AGENT_VERSION:-$DEFAULT_VERSION}"
GITHUB_API="${GITHUB_API:-https://api.github.com}"
GITHUB="${GITHUB:-https://github.com}"

die() { printf 'vaulted-agent install: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "need '$1' on PATH"; }

need curl
need tar
need mktemp

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

printf 'vaulted-agent remote install\n'
printf '  repo    : %s\n' "$REPO"
printf '  version : %s\n' "$VERSION"
printf '  source  : %s\n' "$ARCHIVE_URL"
printf '\n'

workdir="$(mktemp -d "${TMPDIR:-/tmp}/vaulted-agent.XXXXXX")"
cleanup() { rm -rf "$workdir"; }
trap cleanup EXIT

tarball="$workdir/src.tar.gz"
printf 'downloading…\n'
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
      bash "$src/install.sh" "$@"
  fi
  die "need root to install (re-run under sudo, or as root)"
fi

bash "$src/install.sh" "$@"
