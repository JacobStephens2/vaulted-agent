#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# release.sh — cut a vaulted-agent GitHub release and refresh vaultedagent.com
#
# Encodes docs/hosting-the-installer.md. The hosted file is piped into bash as
# root on other people's machines; the asset gate exists so an unpinned
# one-liner never points at a tag that 404s.
#
# One command, from a clean main:
#
#   ./scripts/release.sh release vX.Y.Z
#
# Order:
#   1. prepare vX.Y.Z     bump crate, bootstrap pin, AGENTS/README pins,
#                         MIGRATION (unreleased) headings; release only:
#                         on release/vX.Y.Z, PR, wait for CI, merge
#   2. tag vX.Y.Z         annotated tag; release.yml publishes assets
#   3. wait-assets vX.Y.Z poll until musl asset + source tar return 200
#   4. deploy-site vX.Y.Z record the archive digest, run the bootstrap
#                         tests, refresh install.sh, AGENTS.md, product-page
#                         pin, and commit the site repo
#   5. readme-latest      the two Latest: links, only after the tag exists
#   6. commit the Latest: links and recorded digest to main and push
#
#   cut vX.Y.Z            steps 2–6 (prepare already merged)
#   release vX.Y.Z        steps 1–6; rerun after a failure to resume
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
# On the web host itself, SSH to the same machine has no key; write in place.
if [[ -z "${VAULTED_AGENT_DEPLOY_LOCAL:-}" && -d "$DEPLOY_PATH" && -w "$DEPLOY_PATH" ]]; then
  VAULTED_AGENT_DEPLOY_LOCAL=1
fi

die() { printf 'release: %s\n' "$*" >&2; exit 1; }
log() { printf 'release: %s\n' "$*" >&2; }

usage() {
  cat <<'EOF'
Usage: scripts/release.sh <command> [--dry-run] vX.Y.Z

Commands:
  release        The whole release from a clean main: prepare on
                 release/vX.Y.Z, open the PR, wait for CI, merge, then cut.
                 Steps already done (merged bump, pushed tag) are skipped,
                 so rerun it to resume.
  prepare        Bump Cargo.toml, Cargo.lock, install-remote.sh, AGENTS.md,
                 README pin examples, the MIGRATION.md update-pin line, and
                 the MIGRATION.md (unreleased) headings. Empties the archive
                 digest in install-remote.sh. Does not rewrite README Latest:
                 links (those 404 until tagged).
  check-assets   Exit 0 iff the musl asset and source tarball return 200.
  wait-assets    Poll check-assets until they exist (or timeout).
  deploy-site    After assets exist: record the source archive's sha256 in
                 install-remote.sh, run tests/install_remote_bootstrap.sh
                 against it, back up the live files, install install.sh +
                 AGENTS.md, rewrite the product-page pin, and commit (and
                 push) the site repo when DEPLOY_PATH is in one. Refuses a fat
                 installer or a DEFAULT_VERSION that does not match the tag.
  readme-latest  Rewrite the two README Latest: links.
  tag            Create and push an annotated tag (git signing as configured).
  cut            tag (unless pushed) + wait-assets + deploy-site +
                 readme-latest, then commit README.md and install-remote.sh
                 to main and push.

Environment:
  VAULTED_AGENT_RELEASE_ROOT     repo root (default: parent of scripts/)
  VAULTED_AGENT_DEPLOY_HOST      default jacob@stephens.page
  VAULTED_AGENT_DEPLOY_PATH      default /var/www/stephens.page/vaulted-agent
  VAULTED_AGENT_DEPLOY_LOCAL=1   write DEPLOY_PATH on this machine (no SSH);
                                 the default when DEPLOY_PATH is a writable
                                 directory here
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
    release|prepare|check-assets|wait-assets|deploy-site|readme-latest|tag|cut)
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
  local tmp mode
  tmp=$(mktemp)
  cat >"$tmp"
  # GNU: stat -c '%a'. BSD: stat -f '%Lp'. GNU's -f is --file-system and
  # succeeds with a filesystem dump, so try -c first.
  mode=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file")
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || die "could not read mode of $file (got $mode)"
  chmod "$mode" "$tmp"
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
    log "would bump $old_tag -> $VERSION in Cargo.toml Cargo.lock install-remote.sh AGENTS.md README (pins) MIGRATION.md (update pin, unreleased headings)"
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
  grep -qE '^DEFAULT_ARCHIVE_SHA256="[0-9a-f]*"$' "$remote" \
    || die "install-remote.sh has no DEFAULT_ARCHIVE_SHA256 line"
  # The digest names the old tag's archive. Empty refuses the default archive
  # until deploy-site records the new one.
  sed -e "s/DEFAULT_VERSION=\"${old_tag}\"/DEFAULT_VERSION=\"${VERSION}\"/" \
    -e 's/^DEFAULT_ARCHIVE_SHA256="[0-9a-f]*"$/DEFAULT_ARCHIVE_SHA256=""/' \
    "$remote" | replace_file "$remote"

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
text = text.replace(needle, repl)
# Sections written since the last release ship in this one.
lines = []
for line in text.splitlines(keepends=True):
    if line.startswith("# ") and line.rstrip("\n").endswith(" (unreleased)"):
        line = line.replace(" (unreleased)", f" ({new_tag})")
    lines.append(line)
pathlib.Path(path).write_text("".join(lines))
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
  if [[ -n "${2:-}" ]]; then
    grep -qx "DEFAULT_ARCHIVE_SHA256=\"$2\"" "$file" \
      || die "$file does not record archive digest $2"
  fi
}

# The tag's archive can only be hashed once the tag exists, so the digest is
# written here rather than by prepare.
record_digest() {
  local file=$1 sum=$2
  grep -qE '^DEFAULT_ARCHIVE_SHA256="[0-9a-f]*"$' "$file" \
    || die "$file has no DEFAULT_ARCHIVE_SHA256 line"
  sed "s/^DEFAULT_ARCHIVE_SHA256=\"[0-9a-f]*\"$/DEFAULT_ARCHIVE_SHA256=\"${sum}\"/" "$file" \
    | replace_file "$file"
}

bootstrap_tests_pass() {
  local file=$1
  local suite="$ROOT/tests/install_remote_bootstrap.sh"
  [[ -f "$suite" ]] || die "missing $suite"
  INSTALL_SH="$file" bash "$suite" >&2 \
    || die "tests/install_remote_bootstrap.sh failed against the staged install.sh"
}

# The site tree is a git checkout on the web host. Record what was deployed
# there, and push when the checkout tracks a remote.
commit_site() {
  local files="install.sh AGENTS.md"
  remote_run "test -f '$DEPLOY_PATH/index.html'" && files="$files index.html"
  if ! remote_run "git -C '$DEPLOY_PATH' rev-parse --is-inside-work-tree" >/dev/null 2>&1; then
    log "$DEPLOY_PATH is not a git checkout; nothing to commit"
    return 0
  fi
  remote_run "cd '$DEPLOY_PATH' && git add -- $files && if git diff --cached --quiet -- $files; then echo 'release: site already records $VERSION' >&2; else git commit -q -m 'Publish Vaulted Agent $VERSION install pin' -- $files; fi"
  if remote_run "git -C '$DEPLOY_PATH' rev-parse --abbrev-ref --symbolic-full-name '@{u}'" >/dev/null 2>&1; then
    remote_run "git -C '$DEPLOY_PATH' push -q" \
      || die "deployed, but pushing the site repo failed; push $DEPLOY_PATH by hand"
  fi
  log "site repo records $VERSION"
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
    log "would record the sha256 of $SOURCE_TAR in $remote"
    log "would run tests/install_remote_bootstrap.sh against it"
    log "would deploy $remote -> $DEPLOY_PATH/install.sh (pin $VERSION)"
    log "would deploy $agents -> $DEPLOY_PATH/AGENTS.md"
    if [[ -n "$previous" && "$previous" != "$VERSION" ]]; then
      log "would rewrite $DEPLOY_PATH/index.html $previous -> $VERSION"
    fi
    return 0
  fi

  local stage
  stage=$(mktemp -d)
  # Clear the trap before returning: RETURN traps are global, and a later
  # function (readme-latest under cut) would expand the unset local.
  trap 'rm -rf "$stage"; trap - RETURN' RETURN
  local archive_sum
  curl -fsSL "$SOURCE_TAR" >"$stage/source.tar.gz" || die "could not download $SOURCE_TAR"
  archive_sum=$(digest "$stage/source.tar.gz")
  record_digest "$remote" "$archive_sum"
  install -m 0644 "$remote" "$stage/install.sh"
  install -m 0644 "$agents" "$stage/AGENTS.md"
  bootstrap_is_safe "$stage/install.sh" "$archive_sum"
  bootstrap_tests_pass "$stage/install.sh"

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
      previous=$(remote_run "cat '$DEPLOY_PATH/install.sh.bak'" | pin_in /dev/stdin || true)
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

  verify_deployed "$stage/install.sh" "$DEPLOY_PATH/install.sh" "$SITE_URL/install.sh"
  verify_deployed "$stage/AGENTS.md" "$DEPLOY_PATH/AGENTS.md" "$SITE_URL/AGENTS.md"
  if [[ -f "$stage/index.html" ]]; then
    local page
    if [[ "${VAULTED_AGENT_DEPLOY_LOCAL:-}" == 1 ]]; then
      page=$(cat "$DEPLOY_PATH/index.html")
    else
      page=$(curl -fsSL "$SITE_URL/")
    fi
    printf '%s' "$page" | grep -q "$VERSION" \
      || die "product page does not mention $VERSION after deploy"
  fi
  log "deployed $VERSION to $DEPLOY_PATH"
  commit_site
}

live_digest() {
  local url=$1
  curl -fsSL "$url" | {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi
  } | awk '{print $1}'
}

verify_deployed() {
  local staged=$1 dest=$2 url=$3
  local staged_hash dest_hash
  staged_hash=$(digest "$staged")
  if [[ "${VAULTED_AGENT_DEPLOY_LOCAL:-}" == 1 ]]; then
    dest_hash=$(digest "$dest")
  else
    dest_hash=$(live_digest "$url")
  fi
  [[ "$staged_hash" == "$dest_hash" ]] \
    || die "live $(basename "$dest") hash $dest_hash != staged $staged_hash"
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

git_() { git -C "$ROOT" "$@"; }
gh_() { gh -R "$REPO" "$@"; }

cargo_version() {
  sed -nE 's/^version = "([0-9.]+)"/\1/p' "$ROOT/Cargo.toml" | head -n1
}

require_clean_main() {
  [[ "$(git_ symbolic-ref --short HEAD)" == main ]] || die "run from main"
  git_ diff --quiet && git_ diff --cached --quiet || die "working tree dirty"
  git_ pull -q --ff-only origin main
}

tag_pushed() {
  git_ ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1
}

# A new PR has no checks for a few seconds, and `gh pr checks --watch` exits
# on "no checks reported" instead of waiting for them.
wait_for_checks() {
  local url=$1 i n
  for ((i = 0; i < 60; i++)); do
    n=$(gh_ pr view "$url" --json statusCheckRollup --jq '.statusCheckRollup | length')
    [[ "$n" -gt 0 ]] && break
    sleep 5
  done
  [[ "$n" -gt 0 ]] || die "no CI checks appeared on $url"
  gh_ pr checks "$url" --watch --fail-fast >&2 \
    || die "CI failed on $url; fix it on release/$VERSION, then rerun release"
}

# prepare on release/vX.Y.Z, then PR, CI, merge. An open PR from an earlier
# run is reused.
merge_release_pr() {
  local branch="release/$VERSION" url prev
  url=$(gh_ pr list --head "$branch" --state open --json url --jq '.[0].url // ""')
  if [[ -z "$url" ]]; then
    prev=$(git_ describe --tags --abbrev=0)
    git_ switch -q -c "$branch"
    cmd_prepare
    git_ commit -q -am "Release $VERSION"
    git_ push -q -u origin "$branch"
    url=$(gh_ pr create --base main --head "$branch" --title "Release $VERSION" \
      --body "$(printf 'Bump the release pins to %s. Changes since %s:\n\n' "$VERSION" "$prev"; \
        git_ log --no-merges --format='- %s' "$prev..main")")
    git_ switch -q main
    log "opened $url"
  fi
  wait_for_checks "$url"
  gh_ pr merge "$url" --merge
  git_ pull -q --ff-only origin main
  git_ branch -q -D "$branch" 2>/dev/null || true
  [[ "$(cargo_version)" == "$BARE" ]] || die "main is not $VERSION after merging $url"
  log "merged $url"
}

# deploy-site recorded the archive digest and readme-latest the links; main
# should match what is hosted.
record_on_main() {
  if git_ diff --quiet -- README.md install-remote.sh; then
    log "main already records $VERSION"
    return 0
  fi
  [[ "$(git_ symbolic-ref --short HEAD)" == main ]] \
    || die "commit README.md and install-remote.sh on main and push"
  git_ commit -q -m "Record $VERSION release links and archive digest" -- README.md install-remote.sh
  git_ push -q origin main
  log "pushed the $VERSION links and archive digest to main"
}

cmd_cut() {
  if tag_pushed; then
    log "tag $VERSION already on origin"
  else
    cmd_tag
  fi
  cmd_wait_assets
  cmd_deploy_site
  cmd_readme_latest
  [[ "$DRY_RUN" -eq 1 ]] || record_on_main
}

cmd_release() {
  local tool
  for tool in git gh curl python3; do
    command -v "$tool" >/dev/null 2>&1 || die "need $tool"
  done
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "would pull main, then (unless main is already $VERSION) prepare on release/$VERSION, open a PR, wait for CI, merge"
    log "would tag $VERSION (unless pushed), wait for assets, deploy-site, readme-latest"
    log "would commit README.md + install-remote.sh to main and push"
    return 0
  fi
  require_clean_main
  if [[ "$(cargo_version)" == "$BARE" ]]; then
    log "main is already $VERSION; skipping the release PR"
  else
    merge_release_pr
  fi
  cmd_cut
  log "released $VERSION"
}

case "$CMD" in
  release) cmd_release ;;
  prepare) cmd_prepare ;;
  check-assets) cmd_check_assets ;;
  wait-assets) cmd_wait_assets ;;
  deploy-site) cmd_deploy_site ;;
  readme-latest) cmd_readme_latest ;;
  tag) cmd_tag ;;
  cut) cmd_cut ;;
  *) die "unknown command $CMD" ;;
esac
