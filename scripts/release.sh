#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# release.sh — cut a vaulted-agent GitHub release and refresh vaultedagent.com
#
# Encodes docs/hosting-the-installer.md. The hosted file is piped into bash as
# root on other people's machines; the asset gate exists so an unpinned
# one-liner never points at a tag that 404s.
#
# Order:
#   1. prepare vX.Y.Z     bump crate, bootstrap pin, AGENTS/README pins
#      (merge that commit; do not deploy yet)
#   2. tag vX.Y.Z         annotated tag; release.yml publishes assets
#   3. wait-assets vX.Y.Z poll until musl asset + source tar return 200
#   4. deploy-site vX.Y.Z refresh install.sh, AGENTS.md, product-page pin
#   5. readme-latest      the two Latest: links, only after the tag exists
#
#   cut vX.Y.Z            steps 2–5 (prepare already merged)
#
# Local rehearsal (no SSH):
#   VAULTED_AGENT_DEPLOY_LOCAL=1 VAULTED_AGENT_DEPLOY_PATH=/tmp/va-site \
#     ./scripts/release.sh deploy-site --dry-run v0.4.25
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT="${VAULTED_AGENT_RELEASE_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
REPO="${VAULTED_AGENT_REPO:-JacobStephens2/vaulted-agent}"
GITHUB="${GITHUB:-https://github.com}"
SITE_URL="${VAULTED_AGENT_SITE_URL:-https://vaultedagent.com}"
DEPLOY_HOST="${VAULTED_AGENT_DEPLOY_HOST:-jacob@stephens.page}"
DEPLOY_PATH="${VAULTED_AGENT_DEPLOY_PATH:-/var/www/stephens.page/vaulted-agent}"
WAIT_TIMEOUT="${VAULTED_AGENT_WAIT_ASSETS_TIMEOUT:-900}"
WAIT_INTERVAL="${VAULTED_AGENT_WAIT_ASSETS_INTERVAL:-15}"

die() { printf 'release: %s\n' "$*" >&2; exit 1; }
log() { printf 'release: %s\n' "$*" >&2; }

usage() {
  cat <<'EOF'
Usage: scripts/release.sh <command> [--dry-run] vX.Y.Z

Commands:
  prepare        Bump Cargo.toml, Cargo.lock, install-remote.sh, AGENTS.md,
                 README pin examples, and the MIGRATION.md update-pin line.
                 Does not rewrite README Latest: links (those 404 until tagged).
  check-assets   Exit 0 iff the musl asset and source tarball return 200.
  wait-assets    Poll check-assets until they exist (or timeout).
  deploy-site    After assets exist: verify the local file is the bootstrap,
                 back up the live files, install install.sh + AGENTS.md, and
                 rewrite the product-page pin. Refuses a fat installer or a
                 DEFAULT_VERSION that does not match the tag.
  readme-latest  Rewrite the two README Latest: links.
  tag            Create and push an annotated tag (git signing as configured).
  cut            tag + wait-assets + deploy-site + readme-latest.

Environment:
  VAULTED_AGENT_RELEASE_ROOT     repo root (default: parent of scripts/)
  VAULTED_AGENT_DEPLOY_HOST      default jacob@stephens.page
  VAULTED_AGENT_DEPLOY_PATH      default /var/www/stephens.page/vaulted-agent
  VAULTED_AGENT_DEPLOY_LOCAL=1   write DEPLOY_PATH on this machine (no SSH)
  VAULTED_AGENT_SITE_URL         default https://vaultedagent.com
  GITHUB / VAULTED_AGENT_REPO    asset URL prefix
EOF
}

DRY_RUN=0
CMD=""
VERSION=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    prepare|check-assets|wait-assets|deploy-site|readme-latest|tag|cut)
      [[ -z "$CMD" ]] || die "duplicate command"
      CMD=$arg
      ;;
    v*.*.*)
      VERSION=$arg
      ;;
    *)
      die "unknown argument: $arg"
      ;;
  esac
done

[[ -n "$CMD" ]] || { usage; exit 1; }
[[ -n "$VERSION" ]] || die "need version (vX.Y.Z)"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must look like v0.4.25, got $VERSION"
BARE="${VERSION#v}"

MUSL_ASSET="$GITHUB/$REPO/releases/download/$VERSION/vaulted-agent-x86_64-unknown-linux-musl.tar.gz"
SOURCE_TAR="$GITHUB/$REPO/archive/refs/tags/$VERSION.tar.gz"

http_code() {
  curl -sIL -o /dev/null -w '%{http_code}' "$1"
}

digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

replace_file() {
  local file=$1
  local tmp
  tmp=$(mktemp)
  cat >"$tmp"
  mv "$tmp" "$file"
}

pin_in() {
  local file=$1
  grep -E '^DEFAULT_VERSION=' "$file" | head -n1 | sed -E 's/.*"(v[0-9.]+)".*/\1/'
}

cmd_prepare() {
  local cargo="$ROOT/Cargo.toml"
  local lock="$ROOT/Cargo.lock"
  local remote="$ROOT/install-remote.sh"
  local agents="$ROOT/AGENTS.md"
  local readme="$ROOT/README.md"
  local migration="$ROOT/MIGRATION.md"
  local old_bare old_tag
  old_bare=$(sed -nE 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)"/\1/p' "$cargo" | head -n1)
  [[ -n "$old_bare" ]] || die "could not read version from Cargo.toml"
  old_tag="v${old_bare}"
  [[ "$old_tag" != "$VERSION" ]] || die "Cargo.toml is already $VERSION"

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "would bump $old_tag -> $VERSION in Cargo.toml Cargo.lock install-remote.sh AGENTS.md README (pins) MIGRATION.md (update pin)"
    return 0
  fi

  grep -q "version = \"${old_bare}\"" "$cargo" || die "Cargo.toml missing version = \"$old_bare\""
  sed "s/^version = \"${old_bare}\"/version = \"${BARE}\"/" "$cargo" | replace_file "$cargo"

  awk -v old="$old_bare" -v new="$BARE" '
    $0 == "name = \"vaulted-agent\"" { pending=1 }
    pending && $0 ~ /^version = "/ {
      expected = "version = \"" old "\""
      if ($0 != expected) {
        print "release: Cargo.lock vaulted-agent version is not " old ": " $0 > "/dev/stderr"
        exit 1
      }
      $0 = "version = \"" new "\""
      pending=0
    }
    { print }
  ' "$lock" | replace_file "$lock"

  grep -q "DEFAULT_VERSION=\"${old_tag}\"" "$remote" || die "install-remote.sh pin is not $old_tag"
  sed "s/DEFAULT_VERSION=\"${old_tag}\"/DEFAULT_VERSION=\"${VERSION}\"/" "$remote" | replace_file "$remote"

  python3 - "$agents" "$old_tag" "$old_bare" "$VERSION" "$BARE" <<'PY'
import pathlib, sys
path, old_tag, old_bare, new_tag, new_bare = sys.argv[1:]
text = pathlib.Path(path).read_text()
text = text.replace(old_tag, new_tag).replace(old_bare, new_bare)
pathlib.Path(path).write_text(text)
PY

  python3 - "$readme" "$old_tag" "$old_bare" "$VERSION" "$BARE" <<'PY'
import pathlib, sys
path, old_tag, old_bare, new_tag, new_bare = sys.argv[1:]
out = []
for line in pathlib.Path(path).read_text().splitlines(keepends=True):
    if "Latest:" in line:
        out.append(line)
        continue
    out.append(line.replace(old_tag, new_tag).replace(old_bare, new_bare))
pathlib.Path(path).write_text("".join(out))
PY

  python3 - "$migration" "$old_tag" "$VERSION" <<'PY'
import pathlib, sys
path, old_tag, new_tag = sys.argv[1:]
needle = f"`va update {old_tag}`"
repl = f"`va update {new_tag}`"
text = pathlib.Path(path).read_text()
if needle not in text:
    raise SystemExit(f"MIGRATION.md missing {needle}")
pathlib.Path(path).write_text(text.replace(needle, repl))
PY

  log "prepared $VERSION (Latest: links unchanged until readme-latest)"
}

cmd_check_assets() {
  local musl src
  musl=$(http_code "$MUSL_ASSET")
  src=$(http_code "$SOURCE_TAR")
  if [[ "$musl" != "200" || "$src" != "200" ]]; then
    die "assets not published (musl $musl, source tar $src). Do not deploy. $MUSL_ASSET"
  fi
  log "assets ok: musl $musl, source tar $src"
}

cmd_wait_assets() {
  local deadline now
  deadline=$((SECONDS + WAIT_TIMEOUT))
  while true; do
    if musl=$(http_code "$MUSL_ASSET") && src=$(http_code "$SOURCE_TAR") \
      && [[ "$musl" == "200" && "$src" == "200" ]]; then
      log "assets ok: musl $musl, source tar $src"
      return 0
    fi
    now=$SECONDS
    if (( now >= deadline )); then
      die "timed out waiting for assets (musl ${musl:-?}, source tar ${src:-?})"
    fi
    log "waiting for assets (musl ${musl:-?}, source tar ${src:-?})"
    sleep "$WAIT_INTERVAL"
  done
}

bootstrap_is_safe() {
  local file=$1
  bash -n "$file" || die "$file: bash -n failed"
  local pin
  pin=$(pin_in "$file")
  [[ "$pin" == "$VERSION" ]] || die "$file DEFAULT_VERSION=$pin (want $VERSION)"
  grep -q 'detect_assets' "$file" \
    || die "$file has no detect_assets — refusing to host the fat installer"
}

remote_run() {
  if [[ "${VAULTED_AGENT_DEPLOY_LOCAL:-}" == 1 ]]; then
    bash -c "$1"
  else
    ssh "$DEPLOY_HOST" "$1"
  fi
}

remote_put() {
  local src=$1 dest=$2
  if [[ "${VAULTED_AGENT_DEPLOY_LOCAL:-}" == 1 ]]; then
    install -m 0644 "$src" "$dest"
  else
    scp "$src" "$DEPLOY_HOST:$dest"
  fi
}

rewrite_index() {
  local src=$1 dest=$2 previous=$3
  python3 - "$src" "$dest" "$previous" "$VERSION" <<'PY'
import pathlib, sys
src, dest, previous, version = sys.argv[1:]
text = pathlib.Path(src).read_text()
pathlib.Path(dest).write_text(text.replace(previous, version))
PY
}

cmd_deploy_site() {
  local remote="$ROOT/install-remote.sh"
  local agents="$ROOT/AGENTS.md"
  [[ -f "$remote" ]] || die "missing $remote"
  [[ -f "$agents" ]] || die "missing $agents"
  cmd_check_assets
  bootstrap_is_safe "$remote"

  local previous=""
  if [[ -n "${VAULTED_AGENT_PREVIOUS:-}" ]]; then
    previous=$VAULTED_AGENT_PREVIOUS
  elif [[ "${VAULTED_AGENT_DEPLOY_LOCAL:-}" == 1 && -f "$DEPLOY_PATH/install.sh" ]]; then
    previous=$(pin_in "$DEPLOY_PATH/install.sh" || true)
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "would deploy $remote -> $DEPLOY_PATH/install.sh (pin $VERSION)"
    log "would deploy $agents -> $DEPLOY_PATH/AGENTS.md"
    if [[ -n "$previous" && "$previous" != "$VERSION" ]]; then
      log "would rewrite $DEPLOY_PATH/index.html $previous -> $VERSION"
    fi
    return 0
  fi

  local stage
  stage=$(mktemp -d)
  trap 'rm -rf "$stage"' RETURN
  install -m 0644 "$remote" "$stage/install.sh"
  install -m 0644 "$agents" "$stage/AGENTS.md"
  bootstrap_is_safe "$stage/install.sh"

  local dest_index=""
  if [[ "${VAULTED_AGENT_DEPLOY_LOCAL:-}" == 1 ]]; then
    dest_index="$DEPLOY_PATH/index.html"
    mkdir -p "$DEPLOY_PATH"
    if [[ -f "$DEPLOY_PATH/install.sh" ]]; then
      cp -a "$DEPLOY_PATH/install.sh" "$DEPLOY_PATH/install.sh.bak"
    fi
    if [[ -f "$DEPLOY_PATH/AGENTS.md" ]]; then
      cp -a "$DEPLOY_PATH/AGENTS.md" "$DEPLOY_PATH/AGENTS.md.bak"
    fi
    if [[ -f "$dest_index" ]]; then
      cp -a "$dest_index" "$DEPLOY_PATH/index.html.bak"
      [[ -n "$previous" ]] || previous=$(pin_in "$DEPLOY_PATH/install.sh.bak" || true)
      [[ -n "$previous" ]] || die "cannot rewrite index.html without the previous pin"
      rewrite_index "$dest_index.bak" "$stage/index.html" "$previous"
    fi
    install -m 0644 "$stage/install.sh" "$DEPLOY_PATH/install.sh"
    install -m 0644 "$stage/AGENTS.md" "$DEPLOY_PATH/AGENTS.md"
    if [[ -f "$stage/index.html" ]]; then
      install -m 0644 "$stage/index.html" "$dest_index"
    fi
  else
    remote_run "cp -a '$DEPLOY_PATH/install.sh' '$DEPLOY_PATH/install.sh.bak' && cp -a '$DEPLOY_PATH/AGENTS.md' '$DEPLOY_PATH/AGENTS.md.bak' && if [ -f '$DEPLOY_PATH/index.html' ]; then cp -a '$DEPLOY_PATH/index.html' '$DEPLOY_PATH/index.html.bak'; fi"
    if [[ -z "$previous" ]]; then
      previous=$(remote_run "grep -E '^DEFAULT_VERSION=' '$DEPLOY_PATH/install.sh.bak' | head -n1" | sed -E 's/.*"(v[0-9.]+)".*/\1/')
    fi
    if remote_run "test -f '$DEPLOY_PATH/index.html.bak'"; then
      [[ -n "$previous" ]] || die "cannot rewrite index.html without the previous pin"
      remote_run "cat '$DEPLOY_PATH/index.html.bak'" >"$stage/index.html.src"
      rewrite_index "$stage/index.html.src" "$stage/index.html" "$previous"
    fi
    remote_put "$stage/install.sh" "$DEPLOY_PATH/install.sh.tmp"
    remote_put "$stage/AGENTS.md" "$DEPLOY_PATH/AGENTS.md.tmp"
    remote_run "install -m 0644 '$DEPLOY_PATH/install.sh.tmp' '$DEPLOY_PATH/install.sh' && rm -f '$DEPLOY_PATH/install.sh.tmp'"
    remote_run "install -m 0644 '$DEPLOY_PATH/AGENTS.md.tmp' '$DEPLOY_PATH/AGENTS.md' && rm -f '$DEPLOY_PATH/AGENTS.md.tmp'"
    if [[ -f "$stage/index.html" ]]; then
      remote_put "$stage/index.html" "$DEPLOY_PATH/index.html.tmp"
      remote_run "install -m 0644 '$DEPLOY_PATH/index.html.tmp' '$DEPLOY_PATH/index.html' && rm -f '$DEPLOY_PATH/index.html.tmp'"
    fi
  fi

  local staged_hash dest_hash
  staged_hash=$(digest "$stage/install.sh")
  if [[ "${VAULTED_AGENT_DEPLOY_LOCAL:-}" == 1 ]]; then
    dest_hash=$(digest "$DEPLOY_PATH/install.sh")
  else
    dest_hash=$(curl -fsSL "$SITE_URL/install.sh" | {
      if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi
    } | awk '{print $1}')
  fi
  [[ "$staged_hash" == "$dest_hash" ]] \
    || die "live install.sh hash $dest_hash != staged $staged_hash"
  log "deployed $VERSION to $DEPLOY_PATH (install.sh $staged_hash)"
}

cmd_readme_latest() {
  local readme="$ROOT/README.md"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "would rewrite README Latest: links to $VERSION"
    return 0
  fi
  python3 - "$readme" "$VERSION" <<'PY'
import pathlib, re, sys
path, version = sys.argv[1:]
text = pathlib.Path(path).read_text()
new, n = re.subn(
    r"Latest: \[v[0-9.]+\]\(https://github.com/JacobStephens2/vaulted-agent/releases/tag/v[0-9.]+\)",
    f"Latest: [{version}](https://github.com/JacobStephens2/vaulted-agent/releases/tag/{version})",
    text,
)
if n != 2:
    raise SystemExit(f"expected 2 Latest: links, rewrote {n}")
pathlib.Path(path).write_text(new)
PY
  log "README Latest: links -> $VERSION"
}

cmd_tag() {
  local remote="$ROOT/install-remote.sh"
  local cargo="$ROOT/Cargo.toml"
  local pin cargo_ver
  pin=$(pin_in "$remote")
  [[ "$pin" == "$VERSION" ]] || die "install-remote.sh pin $pin != $VERSION"
  cargo_ver=$(sed -nE 's/^version = "([0-9.]+)"/\1/p' "$cargo" | head -n1)
  [[ "$cargo_ver" == "$BARE" ]] || die "Cargo.toml $cargo_ver != $BARE"
  local msg="${VAULTED_AGENT_TAG_MESSAGE:-$VERSION}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "would git tag -a $VERSION && git push origin $VERSION"
    return 0
  fi
  git -C "$ROOT" diff --quiet && git -C "$ROOT" diff --cached --quiet \
    || die "working tree dirty; merge/commit prepare first"
  git -C "$ROOT" tag -a "$VERSION" -m "$msg"
  git -C "$ROOT" push origin "$VERSION"
  log "tagged $VERSION"
}

cmd_cut() {
  cmd_tag
  cmd_wait_assets
  cmd_deploy_site
  cmd_readme_latest
}

case "$CMD" in
  prepare) cmd_prepare ;;
  check-assets) cmd_check_assets ;;
  wait-assets) cmd_wait_assets ;;
  deploy-site) cmd_deploy_site ;;
  readme-latest) cmd_readme_latest ;;
  tag) cmd_tag ;;
  cut) cmd_cut ;;
  *) die "unknown command $CMD" ;;
esac
