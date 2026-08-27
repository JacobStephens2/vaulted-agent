#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# install.sh — install vaulted-agent, its config directory, and optionally the
# per-harness symlinks and a sudoers rule.
#
# Run as root (or via sudo). Nothing here is clobbered silently: existing
# config files are left alone, and an existing file at a symlink path is a
# hard error unless you pass --force. That last one matters if the box already
# has launchers of its own using the same names.
#
#   sudo ./install.sh                          installs for you, no setup needed
#   sudo ./install.sh --user agent             dedicated account (shared hosts)
#   sudo ./install.sh --no-va                  skip the short `va` alias
#   sudo ./install.sh --backend bitwarden --auth-mode prompt
#   ./install.sh --user conductor --workdir /srv/orchestration --link-user alice \
#                --op-env /etc/orchestration/op.env --allow-user alice
#
# To remove an install, prefer the installed binary (no git tree needed):
#
#   sudo vaulted-agent uninstall [--purge] [--dry-run] [--yes] [--link-user alice]
#   sudo va uninstall …
#
# From this tree before/without an install, the same code path is:
#
#   sudo ./install.sh --uninstall …
#
# Uninstall removes the launcher, any symlinks that point at it, and the
# sudoers rule. It keeps your config unless you add --purge, and it never
# touches a backend credential, which may well be shared with something else.
# ---------------------------------------------------------------------------
set -euo pipefail

# Works on stock macOS (/bin/bash 3.2) and modern Linux bash. Avoid mapfile,
# associative arrays, and Linux-only tools (getent, GNU readlink -f).

SERVICE_USER=""                  # default: whoever invoked this script
WORKDIR=""                       # default: the service account's home
PREFIX="/usr/local/bin"
CONFIG="/etc/vaulted-agent"
OP_ENV=""                        # default: $CONFIG/op.env
LINKS=""                         # e.g. claude,codex,grok -> claude-conductor, ...
ALLOW_USER=""                    # write a sudoers rule for this user
LINK_USER=""                     # symlink into this user's ~/.local/bin
NO_LINK=0                        # skip the default ~/.local/bin symlink
NO_VA=0                          # skip the short `va` alias symlink
NO_AUTO_HARNESS=0                # skip detecting claude/codex/grok/kimi/bash
NO_SETUP=0                       # skip interactive vault backend questions
SHORT_NAME="va"                  # short alias for vaulted-agent
BACKEND_CHOICE=""                # onepassword|bitwarden|pass|sops|plainfile|skip
AUTH_MODE_CHOICE=""              # file|prompt — how vault tokens are supplied at launch
# Set during setup when a vault refs manifest is created/wired; printed in the
# final "Next" summary so the operator knows where to put credential references.
REFS_MANIFEST_PATH=""            # absolute path, e.g. /etc/vaulted-agent/manifests/bitwarden.refs
SETUP_BACKEND=""                 # backend name recorded for the final summary
OP_TOKEN_FILE=""                 # optional path to service-account token (never on argv)
BWS_TOKEN_FILE=""
USER_EXPLICIT=0
FORCE=0
DRY=0
UNINSTALL=0
PURGE=0
ASSUME_YES=0
ALLOW_DEBUG_BINARY=0

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ORIG_ARGS=( ${1+"$@"} )          # kept for the re-run hint; the parse loop below consumes $@
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
run() { if (( DRY )); then printf '  would: %s\n' "$*"; else "$@"; fi; }

# True when a human can answer prompts. Do NOT require -t 0: `curl … | bash`
# makes stdin a pipe even when the user is at a real terminal. Read answers
# from /dev/tty (same pattern as uninstall). -t 1 is enough to know we're not
# running under a fully detached cron/CI sink.
can_prompt_user() {
  (( ! ASSUME_YES )) && (( ! DRY )) && [[ -t 1 && -r /dev/tty ]]
}

# Home directory for a username. Linux: getent. macOS: dscl / python pwd.
# Falls back to ~user expansion when the shell can resolve it.
user_home() {
  local u="$1" h=""
  if command -v getent >/dev/null 2>&1; then
    h="$(getent passwd "$u" 2>/dev/null | cut -d: -f6 || true)"
    if [[ -n "$h" ]]; then printf '%s\n' "$h"; return 0; fi
  fi
  if command -v python3 >/dev/null 2>&1; then
    h="$(python3 -c 'import pwd,sys; print(pwd.getpwnam(sys.argv[1]).pw_dir)' "$u" 2>/dev/null || true)"
    if [[ -n "$h" ]]; then printf '%s\n' "$h"; return 0; fi
  fi
  if command -v dscl >/dev/null 2>&1; then
    h="$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || true)"
    if [[ -n "$h" ]]; then printf '%s\n' "$h"; return 0; fi
  fi
  h="$(eval printf '%s' "~$u" 2>/dev/null || true)"
  if [[ -n "$h" && "$h" != "~$u" ]]; then printf '%s\n' "$h"; return 0; fi
  return 1
}

# Absolute path of a file/symlink, portable across GNU and BSD userland.
resolve_path() {
  local p="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$p" 2>/dev/null || true
    return 0
  fi
  # GNU readlink -f; BSD readlink has no -f (and may error).
  if readlink -f "$p" >/dev/null 2>&1; then
    readlink -f "$p" 2>/dev/null || true
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$p" 2>/dev/null || true
    return 0
  fi
  if [[ -L "$p" ]]; then readlink "$p" 2>/dev/null || true
  else printf '%s\n' "$p"
  fi
}

while (( $# )); do
  case "$1" in
    --user)       SERVICE_USER="${2:?}"; USER_EXPLICIT=1; shift 2 ;;
    --workdir)    WORKDIR="${2:?}"; shift 2 ;;
    --prefix)     PREFIX="${2:?}"; shift 2 ;;
    --config)     CONFIG="${2:?}"; shift 2 ;;
    --op-env)     OP_ENV="${2:?}"; shift 2 ;;
    --links)      LINKS="${2:?}"; shift 2 ;;
    --allow-user) ALLOW_USER="${2:?}"; shift 2 ;;
    --link-user)  LINK_USER="${2:?}"; shift 2 ;;
    --force)      FORCE=1; shift ;;
    --dry-run)    DRY=1; shift ;;
    --uninstall)  UNINSTALL=1; shift ;;
    --purge)      PURGE=1; shift ;;
    -y|--yes)     ASSUME_YES=1; shift ;;
    --no-link)         NO_LINK=1; shift ;;
    --no-va)           NO_VA=1; shift ;;
    --no-auto-harness) NO_AUTO_HARNESS=1; shift ;;
    --no-setup)        NO_SETUP=1; shift ;;
    --backend)         BACKEND_CHOICE="${2:?}"; shift 2 ;;
    --auth-mode)       AUTH_MODE_CHOICE="${2:?}"; shift 2 ;;
    --op-token-file)   OP_TOKEN_FILE="${2:?}"; shift 2 ;;
    --bws-token-file)  BWS_TOKEN_FILE="${2:?}"; shift 2 ;;
    --allow-debug-binary) ALLOW_DEBUG_BINARY=1; shift ;;
    -h|--help)         sed -n "2,25p" "$0"; exit 0 ;;
    *)                 die "unknown option '$1'" ;;
  esac
done

case "${AUTH_MODE_CHOICE}" in
  ''|file|prompt) ;;
  *) die "--auth-mode must be 'file' or 'prompt' (got '$AUTH_MODE_CHOICE')" ;;
esac

# --- uninstall --------------------------------------------------------------
# Removes only what this script installs, and only where it can confirm
# ownership: a symlink goes if it resolves to our launcher, and is left alone
# otherwise. Config is kept unless --purge, because harness files are usually
# hand-written. The backend credential is never touched: with --op-env it
# often predates the install, so removing it could break something unrelated.
if (( UNINSTALL )); then
  launcher="$PREFIX/vaulted-agent"

  # Prompt when a human is plainly present, and never otherwise. --dry-run
  # changes nothing so it needs no consent, and -y is the escape hatch for
  # scripts and cron, which have no terminal to answer with anyway.
  #
  # Note this deliberately does NOT key off "were any flags passed". Tying it
  # to that would mean anyone who installed somewhere other than the default
  # prefix could never reach the menu, since they must pass --prefix to say so.
  interactive=0
  if can_prompt_user; then interactive=1; fi

  # Work out what would go before touching anything. The prompt, --dry-run and
  # the real removal all render from these same two lists.
  # bash 3.2 has no associative arrays; track seen users as a space list.
  targets=(); foreign=(); seen_users=" "

  consider() {
    local p="$1"
    if [[ -L "$p" && "$(resolve_path "$p")" == "$launcher" ]]; then
      targets+=("$p")
    elif [[ -e "$p" || -L "$p" ]]; then
      foreign+=("$p")
    fi
  }

  shopt -s nullglob
  for link in "$PREFIX"/*-conductor; do
    consider "$link"
  done
  shopt -u nullglob

  consider "$PREFIX/$SHORT_NAME"

  for u in ${LINK_USER:+"$LINK_USER"} ${SUDO_USER:+"$SUDO_USER"}; do
    if [[ "$seen_users" == *" $u "* ]]; then continue; fi
    seen_users="$seen_users$u "
    uh="$(user_home "$u" 2>/dev/null || true)"
    if [[ -z "$uh" ]]; then continue; fi
    consider "$uh/.local/bin/vaulted-agent"
    consider "$uh/.local/bin/$SHORT_NAME"
  done

  if [[ -e "$launcher" ]]; then targets+=("$launcher"); fi
  if [[ -e /etc/sudoers.d/vaulted-agent ]]; then targets+=(/etc/sudoers.d/vaulted-agent); fi

  n_conf=0; n_man=0
  if [[ -d "$CONFIG" ]]; then
    shopt -s nullglob
    _c=( "$CONFIG"/harnesses.d/*.conf ); n_conf=${#_c[@]}
    _m=( "$CONFIG"/manifests/*        ); n_man=${#_m[@]}
    shopt -u nullglob
  fi

  printf 'vaulted-agent uninstall\n\n'
  if (( ${#targets[@]} == 0 )) && [[ ! -d "$CONFIG" ]]; then
    printf 'Nothing to remove: no launcher at %s and no config at %s.\n' "$PREFIX" "$CONFIG"
    exit 0
  fi

  printf 'Found:\n'
  for t in ${targets[@]+"${targets[@]}"}; do printf '  %s\n' "$t"; done
  if [[ -d "$CONFIG" ]]; then
    printf '  %s  (%d live harnesses, %d manifests)\n' "$CONFIG" "$n_conf" "$n_man"
  fi
  for f in ${foreign[@]+"${foreign[@]}"}; do printf '  %s  (not ours, will be left alone)\n' "$f"; done

  if (( interactive )) && (( PURGE )); then
    printf '\n--purge given: %s will be removed too.\n' "$CONFIG"
  elif (( interactive )); then
    printf '\n  1) Remove the launcher, its symlinks and the sudoers rule; keep config\n'
    if [[ -d "$CONFIG" ]]; then
      printf '  2) Remove all of that, and %s as well\n' "$CONFIG"
    fi
    printf '  3) Show what would happen, change nothing\n'
    printf '  q) Quit\n\n'
    while :; do
      printf 'choice [1-3, q]: '
      read -r ans < /dev/tty || { printf '\n'; exit 130; }
      case "$ans" in
        1)     break ;;
        2)     if [[ -d "$CONFIG" ]]; then PURGE=1; break; fi; printf '  no config directory to remove\n' ;;
        3)     DRY=1; break ;;
        q|Q)   printf 'Nothing removed.\n'; exit 0 ;;
        *)     printf '  enter 1, 2, 3 or q\n' ;;
      esac
    done
  fi

  if (( PURGE )) && [[ -d "$CONFIG" ]]; then targets+=("$CONFIG"); fi

  # Last look before anything is deleted, showing the exact paths.
  if (( interactive )) && (( ! DRY )); then
    printf '\nAbout to remove:\n'
    for t in ${targets[@]+"${targets[@]}"}; do printf '  %s\n' "$t"; done
    printf '\nProceed? [y/N]: '
    read -r yn < /dev/tty || { printf '\n'; exit 130; }
    case "$yn" in
      y|Y|yes|YES) ;;
      *) printf 'Nothing removed.\n'; exit 0 ;;
    esac
  fi

  printf '\n'
  for t in ${targets[@]+"${targets[@]}"}; do
    if (( DRY )); then printf 'would remove %s\n' "$t"
    else rm -rf "$t"; printf 'removed %s\n' "$t"; fi
  done
  for f in ${foreign[@]+"${foreign[@]}"}; do printf 'left alone %s (not ours)\n' "$f"; done

  if (( ! PURGE )) && [[ -d "$CONFIG" ]]; then
    printf '\nkept %s. Add --purge, or choose 2 interactively, to remove it too.\n' "$CONFIG"
  fi
  printf '\nNot touched: any backend credential (op.env / bws.env / age.key).\n'
  printf '  Those are often shared with other tooling; remove by hand if you want them gone.\n'
  exit 0
fi

# Default the service account to whoever invoked this. On a personal machine
# that is what you want, and it means `sudo ./install.sh` works with no setup.
# On a shared host prefer a dedicated account: everything running as the agent
# user can read the agent's environment through /proc/<pid>/environ, so the
# fewer other things run as that user, the narrower that exposure is.
if [[ -z "$SERVICE_USER" ]]; then
  SERVICE_USER="${SUDO_USER:-$(id -un)}"
  if [[ "$SERVICE_USER" == "root" ]]; then
    die "refusing to default the service account to root: agents would run with
  full privilege and could read every credential on the box. Either run this
  with sudo from your normal login, or name an account with --user <name>."
  fi
fi

id -u "$SERVICE_USER" >/dev/null 2>&1 || \
  die "service account '$SERVICE_USER' does not exist. Create it first, e.g.
  # Linux:
  useradd --system --home-dir /srv/$SERVICE_USER --create-home --shell /bin/bash $SERVICE_USER
  # macOS: System Settings → Users, or dscl(1)"

# Put the command on the invoking user's PATH by default: /usr/local/bin is
# absent from it more often than people expect, and a launcher you cannot type
# the name of is not installed in any useful sense.
if [[ -z "$LINK_USER" ]] && (( ! NO_LINK )) && [[ -n "${SUDO_USER:-}" ]]; then
  LINK_USER="$SUDO_USER"
fi

if [[ -z "$WORKDIR" ]]; then
  WORKDIR="$(user_home "$SERVICE_USER")" \
    || die "cannot find home directory for '$SERVICE_USER'"
fi
[[ -n "$OP_ENV" ]]  || OP_ENV="${CONFIG}/op.env"

# Create install targets when missing (fresh macOS often lacks /usr/local/bin).
if (( DRY )); then
  printf '  would ensure directories: %s  %s\n' "$PREFIX" "$(dirname "$CONFIG")"
else
  install -d -m 0755 "$PREFIX" "$(dirname "$CONFIG")" 2>/dev/null \
    || die "cannot create $PREFIX or $(dirname "$CONFIG"); re-run with sudo"
  for d in "$PREFIX" "$(dirname "$CONFIG")" ${ALLOW_USER:+/etc/sudoers.d}; do
    [[ -z "$d" ]] && continue
    [[ -d "$d" ]] || die "$d does not exist; re-run with sudo"
    [[ -w "$d" ]] || die "$d is not writable; re-run with sudo"
  done
fi

printf 'vaulted-agent install\n'
# Map --backend to the on-disk token path we talk about in the summary, and to
# DEFAULT_BACKEND patched into the launcher (harnesses without backend= use it).
BACKEND_TOKEN_PATH="$OP_ENV"
DEFAULT_BACKEND_VALUE="onepassword"
case "${BACKEND_CHOICE:-}" in
  bitwarden|bws)
    BACKEND_TOKEN_PATH="$CONFIG/bws.env"
    DEFAULT_BACKEND_VALUE="bitwarden"
    ;;
  onepassword|op|1password)
    BACKEND_TOKEN_PATH="$OP_ENV"
    DEFAULT_BACKEND_VALUE="onepassword"
    ;;
  pass)
    BACKEND_TOKEN_PATH="(pass: service-account GPG key; no token file)"
    DEFAULT_BACKEND_VALUE="pass"
    ;;
  sops)
    BACKEND_TOKEN_PATH="$CONFIG/age.key"
    DEFAULT_BACKEND_VALUE="sops"
    ;;
  plainfile)
    BACKEND_TOKEN_PATH="(plainfile: secrets live in the manifest)"
    DEFAULT_BACKEND_VALUE="plainfile"
    ;;
  skip|'')
    ;;
esac

printf '  service account : %s (workdir %s)%s\n' "$SERVICE_USER" "$WORKDIR" \
  "$( (( USER_EXPLICIT )) || printf '   <- you; --user <name> for a dedicated account' )"
printf '  launcher        : %s/vaulted-agent\n' "$PREFIX"
printf '  config          : %s\n' "$CONFIG"
printf '  default backend : %s\n' "$DEFAULT_BACKEND_VALUE"
printf '  backend token   : %s\n' "$BACKEND_TOKEN_PATH"
(( DRY )) && printf '  (dry run)\n'
printf '\n'

# --- the launcher (Rust binary; machine defaults go in defaults.conf) ------
# Prefer: VAULTED_AGENT_BIN → release binary in tree → cargo build --release.
# Debug binaries are never installed unless --allow-debug-binary (stale debug
# builds from another branch must not land in /usr/local/bin).
resolve_rust_binary() {
  local cand
  for cand in \
    "${VAULTED_AGENT_BIN:-}" \
    "$REPO/target/release/vaulted-agent"
  do
    [[ -n "$cand" && -x "$cand" ]] || continue
    printf '%s\n' "$cand"
    return 0
  done
  if (( ALLOW_DEBUG_BINARY )) && [[ -x "$REPO/target/debug/vaulted-agent" ]]; then
    printf 'warning: installing target/debug/vaulted-agent (--allow-debug-binary)\n' >&2
    printf '%s\n' "$REPO/target/debug/vaulted-agent"
    return 0
  fi
  if command -v cargo >/dev/null 2>&1; then
    printf 'building vaulted-agent (cargo --release --locked)…\n' >&2
    # Drop privileges for the build when we are root (Cargo build scripts are
    # arbitrary code; the Bash runtime never needed root for this step).
    local build_user="${SUDO_USER:-}"
    if [[ "$(id -u)" -eq 0 && -n "$build_user" && "$build_user" != "root" ]]; then
      (cd "$REPO" && sudo -u "$build_user" cargo build --release --locked) >&2 \
        || die "cargo build --release --locked failed"
    else
      (cd "$REPO" && cargo build --release --locked) >&2 \
        || die "cargo build --release --locked failed"
    fi
    [[ -x "$REPO/target/release/vaulted-agent" ]] \
      || die "cargo build succeeded but binary missing"
    printf '%s\n' "$REPO/target/release/vaulted-agent"
    return 0
  fi
  die "no vaulted-agent binary found and cargo not on PATH.
  Build on a machine with Rust: cargo build --release --locked
  Or set VAULTED_AGENT_BIN=/path/to/vaulted-agent
  Or use install-remote.sh which downloads a release asset."
}
RUST_BIN="$(resolve_rust_binary)"
run install -m 0755 "$RUST_BIN" "$PREFIX/vaulted-agent"
printf 'installed %s/vaulted-agent (Rust runtime from %s)\n' "$PREFIX" "$RUST_BIN"

# Short alias `va` -> vaulted-agent (collision-safe unless --force).
link_alias() {
  local dest="$1" label="${2:-}"
  if [[ -e "$dest" || -L "$dest" ]]; then
    target="$(resolve_path "$dest")"
    if [[ "$target" == "$PREFIX/vaulted-agent" ]]; then
      printf 'link already correct: %s\n' "$dest"
      return 0
    fi
    (( FORCE )) || die "$dest already exists and is not ours (-> ${target:-?}).
  Refusing to overwrite. Pass --force to replace, or --no-va to skip the short alias."
    printf 'REPLACING pre-existing %s\n' "$dest"
  fi
  run ln -sfn "$PREFIX/vaulted-agent" "$dest"
  if [[ -n "$label" ]]; then
    printf 'linked %s -> %s/vaulted-agent\n' "$dest" "$PREFIX"
  else
    printf 'linked %s\n' "$dest"
  fi
}

if (( ! NO_VA )); then
  link_alias "$PREFIX/$SHORT_NAME"
else
  printf 'skipped short alias %s (--no-va)\n' "$SHORT_NAME"
fi

# --- config directories and sample config, never overwriting ---------------
run install -d -m 0755 "$CONFIG" "$CONFIG/harnesses.d" "$CONFIG/manifests"
# Samples land with a .example suffix. They reference a vault that does not
# exist on your machine, so installing them as live config would leave a fresh
# install listing several harnesses that all fail at injection. Copy one and
# drop the suffix to activate it.
# Exception: empty.env is installed live - auto-harnesses need a zero-secret
# day-one manifest so `va claude` can launch before vault wiring.
for src in "$REPO"/etc/harnesses.d/* "$REPO"/etc/manifests/*; do
  base="${src#"$REPO"/etc/}"
  case "$base" in
    */README)            dst="$CONFIG/$base" ;;
    manifests/empty.env) dst="$CONFIG/$base" ;;
    *)                   dst="$CONFIG/${base}.example" ;;
  esac
  if [[ -e "$dst" ]]; then
    printf 'kept existing %s\n' "$dst"
  else
    run install -m 0644 "$src" "$dst"
    printf 'installed %s\n' "$dst"
  fi
done

# --- auto-detect agent CLIs and activate harnesses ------------------------
# Prefer the invoking user's PATH (not root's) when install runs under sudo.
find_user_bin() {
  local name="$1" p home
  if [[ -n "${SUDO_USER:-}" ]] && command -v sudo >/dev/null 2>&1; then
    p="$(sudo -nu "$SUDO_USER" -- command -v "$name" 2>/dev/null || true)"
    if [[ -n "$p" ]]; then printf '%s\n' "$p"; return 0; fi
    home="$(user_home "$SUDO_USER" 2>/dev/null || true)"
  else
    p="$(command -v "$name" 2>/dev/null || true)"
    if [[ -n "$p" ]]; then printf '%s\n' "$p"; return 0; fi
    home="${HOME:-}"
  fi
  for d in \
    ${home:+"$home/.local/bin"} \
    ${home:+"$home/.grok/bin"} \
    /opt/homebrew/bin \
    /usr/local/bin
  do
    if [[ -x "$d/$name" ]]; then printf '%s\n' "$d/$name"; return 0; fi
  done
  return 1
}

write_auto_harness() {
  local name="$1" path="$2" cmd="$3" bindir conf
  conf="$CONFIG/harnesses.d/${name}.conf"
  bindir="$(dirname -- "$path")"
  if [[ -e "$conf" ]]; then
    printf '  %-8s kept existing %s\n' "$name" "$conf"
    return 0
  fi
  if (( DRY )); then
    printf '  %-8s would write %s  (bin=%s command=%s)\n' "$name" "$conf" "$bindir" "$cmd"
    return 0
  fi
  cat > "$conf" <<EOF
# Auto-configured by install.sh — detected $path
# Day-one: plainfile + empty.env so the agent launches with no vault secrets.
# workdir=caller keeps the shell's cwd so agent --resume / sessions match.
# To inject secrets: set backend + manifest (see README), or run:
#   vaulted-agent setup
backend  = plainfile
manifest = empty.env
workdir  = caller
bin      = $bindir
command  = $cmd
EOF
  chmod 0644 "$conf"
  printf '  %-8s wrote %s  (%s)\n' "$name" "$conf" "$path"
}

if (( ! NO_AUTO_HARNESS )); then
  printf '\nDetecting agent CLIs and bash on PATH…\n'
  found_any=0
  found_agent=0
  if p="$(find_user_bin claude)"; then
    write_auto_harness claude "$p" "claude --permission-mode auto"
    found_any=1
    found_agent=1
  else
    printf '  %-8s not found (skipped)\n' claude
  fi
  if p="$(find_user_bin codex)"; then
    write_auto_harness codex "$p" "codex"
    found_any=1
    found_agent=1
  else
    printf '  %-8s not found (skipped)\n' codex
  fi
  if p="$(find_user_bin grok)"; then
    write_auto_harness grok "$p" "grok"
    found_any=1
    found_agent=1
  else
    printf '  %-8s not found (skipped)\n' grok
  fi
  # Kimi Code CLI (https://www.kimi.com/code/en) — binary name is `kimi`.
  # --auto matches unattended default. Vault inject works for OpenAI-compatible
  # providers (OPENAI_API_KEY by type); see issue #70 / kimi-code#2745 for the
  # 0.33–0.34 gate regression and the launcher LEGACY_FLAG workaround.
  if p="$(find_user_bin kimi)"; then
    write_auto_harness kimi "$p" "kimi --auto"
    found_any=1
    found_agent=1
  else
    printf '  %-8s not found (skipped)\n' kimi
  fi
  # bash is almost always on PATH; do not treat it as an agent CLI being found.
  if p="$(find_user_bin bash)"; then
    write_auto_harness bash "$p" "bash"
    found_any=1
  else
    printf '  %-8s not found (skipped)\n' bash
  fi
  if (( found_any )); then
    printf '\nAuto-harnesses use plainfile + empty.env (no vault secrets yet).\n'
    if (( found_agent )); then
      printf '  Try:  va claude   /   va codex   /   va grok   /   va kimi   /   va bash\n'
    else
      printf '  Try:  va bash   (secrets-injected shell; extra argv is appended)\n'
    fi
  fi
  if (( ! found_agent )); then
    printf '  No claude/codex/grok/kimi found. Install an agent CLI, then re-run install\n'
    printf '  or copy a harnesses.d/*.conf.example and drop the .example suffix.\n'
  fi
  unset found_any found_agent p
else
  printf '\nskipped auto-harness detect (--no-auto-harness)\n'
fi

# --- optional interactive vault backend + auth-mode setup -----------------
write_token_file() {
  # $1=path $2=varname $3=token-value  → 0640 root:SERVICE_USER
  local path="$1" var="$2" token="$3" grp
  grp="$(id -gn "$SERVICE_USER" 2>/dev/null || echo "$SERVICE_USER")"
  if (( DRY )); then
    printf '  would write %s (%s=…)\n' "$path" "$var"
    return 0
  fi
  printf '%s=%s\n' "$var" "$token" > "$path"
  chown "root:$grp" "$path" 2>/dev/null || chown "root:$SERVICE_USER" "$path" 2>/dev/null || true
  chmod 0640 "$path"
  printf '  wrote %s (0640)\n' "$path"
}

write_defaults_conf() {
  # $1 = auth_mode (file|prompt)
  local mode="$1" path="$CONFIG/defaults.conf" svc_line="" be_line=""
  case "$mode" in file|prompt) ;; *) die "internal: bad auth_mode '$mode'" ;; esac
  be_line="default_backend = $DEFAULT_BACKEND_VALUE"
  # Only set service_user when operator asked for a dedicated account; otherwise
  # the Rust binary runs as the invoker (no sudo hop).
  if (( USER_EXPLICIT )); then
    svc_line="service_user = $SERVICE_USER"
  fi
  if (( DRY )); then
    printf '  would write %s (auth_mode=%s, %s)\n' "$path" "$mode" "$be_line"
    return 0
  fi
  # Keys this function does not manage belong to the operator, and rewriting
  # the file with `>` used to drop them. `service_user` is the one that hurts:
  # re-running the installer without --user silently moved agents back to
  # running as the caller. The Rust runtime's auth-mode writer already
  # preserves unmanaged keys; match it here.
  local carried=""
  if [[ -f "$path" ]]; then
    carried="$(awk -v have_svc="${svc_line:+1}" '
      { line = $0
        sub(/[[:space:]]*#.*/, "", line)
        if (line ~ /^[[:space:]]*$/) next
        split(line, kv, "=")
        key = kv[1]; gsub(/[[:space:]]/, "", key)
        if (key == "auth_mode" || key == "default_backend") next
        if (key == "service_user" && have_svc == "1") next
        print $0 }' "$path")"
    # Keep a copy before rewriting, so a bad guess here is recoverable.
    cp -p "$path" "$path.bak-$(date +%Y%m%d-%H%M%S)"
  fi
  {
    printf '%s\n' \
      '# Machine-wide launcher defaults (Rust runtime).' \
      '# Change later: vaulted-agent auth-mode  |  va auth-mode prompt|file' \
      "auth_mode = $mode" \
      "$be_line"
    [[ -n "$svc_line" ]] && printf '%s\n' "$svc_line"
    [[ -n "$carried" ]] && printf '%s\n' "$carried"
  } > "$path"
  chmod 0644 "$path"
  printf '  wrote %s (auth_mode=%s, backend=%s)\n' "$path" "$mode" "$DEFAULT_BACKEND_VALUE"
  if [[ -n "$carried" ]]; then
    printf '    kept %s operator-set line(s)\n' "$(printf '%s\n' "$carried" | wc -l | tr -d ' ')"
  fi
  # Explicit: under `set -e` a trailing false test would abort the install.
  return 0
}

# Create a live reference manifest (no secret values) if missing.
# Records REFS_MANIFEST_PATH for the final install summary.
ensure_ref_manifest() {
  # $1=basename  remaining args = comment/header lines
  local base="$1" path="$CONFIG/manifests/$1"
  shift
  REFS_MANIFEST_PATH="$path"
  if [[ -e "$path" ]]; then
    printf '  kept existing manifest %s\n' "$path"
    return 0
  fi
  if (( DRY )); then
    printf '  would write %s\n' "$path"
    return 0
  fi
  {
    printf '%s\n' "$@"
    printf '\n'
  } > "$path"
  chmod 0644 "$path"
  printf '  wrote %s  (add VAR=reference lines when ready)\n' "$path"
}

# Personal installs: agent sessions (claude/codex/grok/kimi) are cwd-scoped.
# Ensure live harnesses use workdir=caller so `va grok --resume …` / `va kimi
# --continue` match a normal launch from the same directory.
ensure_workdir_caller() {
  local conf tmp
  shopt -s nullglob
  for conf in "$CONFIG"/harnesses.d/*.conf; do
    if grep -q '^[[:space:]]*workdir[[:space:]]*=' "$conf" 2>/dev/null; then
      continue
    fi
    if (( DRY )); then
      printf '  would add workdir=caller to %s\n' "${conf##*/}"
      continue
    fi
    tmp="$(mktemp)" || die "mktemp failed"
    cat "$conf" > "$tmp"
    printf 'workdir  = caller\n' >> "$tmp"
    install -m 0644 "$tmp" "$conf"
    rm -f "$tmp"
    printf '  added workdir=caller to %s\n' "${conf##*/}"
  done
  shopt -u nullglob
}

# Env-blind agent basenames (etc/env-blind-agents). Same file the Rust binary
# embeds for doctor — do not hardcode names here. The list may be empty; kimi
# was wrongly listed in v0.4.16 and removed in #70 (upstream kimi-code#2745).
is_env_blind_agent() {
  local name="$1" list="$REPO/etc/env-blind-agents" line
  [[ -n "$name" && -f "$list" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" ]] && continue
    [[ "$line" == "$name" ]] && return 0
  done < "$list"
  return 1
}

# Day-one auto-harnesses are plainfile + empty.env. Choosing a vault backend
# at install must rewire those, or auth_mode=prompt / -p never runs (plainfile
# has no vault token). Never touch harnesses that already have a real backend.
#
# Exception: names listed in etc/env-blind-agents (may be empty). Those tools
# do not consume vault inject for the usual provider path; leave them on
# empty.env. Do not re-add kimi without re-checking issue #70.
wire_day_one_harnesses() {
  local backend="$1" manifest_name="$2" conf tmp n=0 be man cmd base stem
  case "$backend" in
    onepassword|bitwarden|pass) ;;
    *) return 0 ;;
  esac
  [[ -n "$manifest_name" ]] || return 0
  shopt -s nullglob
  for conf in "$CONFIG"/harnesses.d/*.conf; do
    be="$(sed -n 's/^[[:space:]]*backend[[:space:]]*=[[:space:]]*//p' "$conf" 2>/dev/null | head -1)"
    man="$(sed -n 's/^[[:space:]]*manifest[[:space:]]*=[[:space:]]*//p' "$conf" 2>/dev/null | head -1)"
    cmd="$(sed -n 's/^[[:space:]]*command[[:space:]]*=[[:space:]]*//p' "$conf" 2>/dev/null | head -1)"
    be="$(printf '%s' "$be" | sed 's/[[:space:]]*$//')"
    man="$(printf '%s' "$man" | sed 's/[[:space:]]*$//')"
    cmd="$(printf '%s' "$cmd" | sed 's/[[:space:]]*$//')"
    base="${cmd%% *}"
    base="${base##*/}"
    stem="${conf##*/}"
    stem="${stem%.conf}"
    # Registry skip: only when etc/env-blind-agents lists this name.
    if is_env_blind_agent "$base" || is_env_blind_agent "$stem"; then
      printf '  left %s  (listed in etc/env-blind-agents as %s — not rewired to vault; see that file)\n' \
        "${conf##*/}" "${base:-$stem}"
      continue
    fi
    # Only rewrite the installer's zero-secret starter config.
    if [[ "$be" != "plainfile" || "$man" != "empty.env" ]]; then
      printf '  left %s  (backend=%s manifest=%s — not day-one)\n' \
        "${conf##*/}" "${be:-?}" "${man:-?}"
      continue
    fi
    if (( DRY )); then
      printf '  would set %s → backend=%s manifest=%s\n' \
        "${conf##*/}" "$backend" "$manifest_name"
      n=$(( n + 1 ))
      continue
    fi
    tmp="$(mktemp)" || die "mktemp failed"
    sed -e "s|^[[:space:]]*backend[[:space:]]*=.*|backend  = $backend|" \
        -e "s|^[[:space:]]*manifest[[:space:]]*=.*|manifest = $manifest_name|" \
        "$conf" > "$tmp"
    # Ensure workdir=caller so agent --resume uses the shell's cwd (sessions are
    # often scoped by directory). Add the key if the day-one file lacks it.
    if ! grep -q '^[[:space:]]*workdir[[:space:]]*=' "$tmp"; then
      # Insert after manifest line when present; otherwise append.
      if grep -q '^[[:space:]]*manifest[[:space:]]*=' "$tmp"; then
        awk '
          /^[[:space:]]*manifest[[:space:]]*=/ && !done {
            print; print "workdir  = caller"; done=1; next
          }
          { print }
        ' "$tmp" > "${tmp}.w" && mv "${tmp}.w" "$tmp"
      else
        printf 'workdir  = caller\n' >> "$tmp"
      fi
    fi
    install -m 0644 "$tmp" "$conf"
    rm -f "$tmp"
    printf '  wired %s → backend=%s manifest=%s workdir=caller\n' \
      "${conf##*/}" "$backend" "$manifest_name"
    n=$(( n + 1 ))
  done
  shopt -u nullglob
  if (( n == 0 )); then
    printf '  no day-one (plainfile+empty.env) harnesses to wire\n'
  else
    printf '  %d harness(es) now use %s — token prompt applies when auth_mode=prompt\n' \
      "$n" "$backend"
  fi
}

# Resolve AUTH_MODE_CHOICE interactively when unset. Defaults to file.
prompt_auth_mode_setup() {
  local choice
  if [[ -n "$AUTH_MODE_CHOICE" ]]; then
    return 0
  fi
  if (( ! NO_SETUP )) && can_prompt_user; then
    printf '\nHow should vault tokens be supplied at launch?\n'
    printf '  1) file    — store once in op.env / bws.env (no prompt each run)\n'
    printf '  2) prompt  — paste token each launch; nothing stored on disk\n'
    printf '     (same as always running with -p / --prompt-auth)\n'
    printf 'choice [1-2, default 1]: '
    read -r choice < /dev/tty || choice=1
    case "$choice" in
      1|file|''|disk) AUTH_MODE_CHOICE=file ;;
      2|prompt|p)     AUTH_MODE_CHOICE=prompt ;;
      *)
        printf '  unknown choice; defaulting to file\n'
        AUTH_MODE_CHOICE=file
        ;;
    esac
  else
    AUTH_MODE_CHOICE=file
  fi
}

prompt_backend_setup() {
  local choice token path
  choice="$BACKEND_CHOICE"
  if [[ -z "$choice" ]] && (( ! NO_SETUP )) && can_prompt_user; then
    printf '\nDefault secret backend for this machine?\n'
    printf '  1) 1Password service account  (op inject)\n'
    printf '  2) Bitwarden Secrets Manager  (bws)\n'
    printf '  3) pass (passwordstore.org)\n'
    printf '  4) sops + age\n'
    printf '  5) Skip — keep plainfile/empty (agents launch with no vault secrets)\n'
    printf 'choice [1-5, default 5]: '
    read -r choice < /dev/tty || choice=5
    case "$choice" in
      1|onepassword|op) choice=onepassword ;;
      2|bitwarden|bws)  choice=bitwarden ;;
      3|pass)           choice=pass ;;
      4|sops)           choice=sops ;;
      5|''|skip|plainfile|none) choice=skip ;;
      *) printf '  unknown choice; skipping vault setup\n'; choice=skip ;;
    esac
  elif [[ -z "$choice" ]]; then
    choice=skip
    if (( ! NO_SETUP )) && ! can_prompt_user; then
      printf '\nNo interactive terminal for setup questions (common with curl|bash in CI).\n'
      printf '  Defaults: backend skipped, auth_mode=file.\n'
      printf '  Later: vaulted-agent setup   and/or   vaulted-agent auth-mode\n'
      printf '  Or re-run with flags, e.g.:\n'
      printf '    curl -fsSL …/install.sh | bash -s -- --backend bitwarden --auth-mode prompt\n'
    fi
  fi

  # Auth mode applies machine-wide; always record it (even on skip).
  prompt_auth_mode_setup
  write_defaults_conf "$AUTH_MODE_CHOICE"
  # Always keep project-scoped resume working for existing harnesses.
  ensure_workdir_caller

  case "$choice" in
    onepassword|op)
      SETUP_BACKEND=onepassword
      path="${OP_ENV:-$CONFIG/op.env}"
      ensure_ref_manifest onepassword.refs \
        '# 1Password references — one per line, no secret values:' \
        '#   VAR=op://Vault/Item/field' \
        '# Fill these in, then launch; with auth_mode=prompt you paste OP_SERVICE_ACCOUNT_TOKEN.'
      printf '  Wiring day-one harnesses to onepassword…\n'
      wire_day_one_harnesses onepassword onepassword.refs
      if [[ "$AUTH_MODE_CHOICE" == prompt ]]; then
        printf '  auth_mode=prompt: not writing %s\n' "$path"
        printf '  backend ready: onepassword — launch prompts for OP_SERVICE_ACCOUNT_TOKEN\n'
        printf '  change later: vaulted-agent auth-mode file|prompt\n'
      else
        if [[ -n "$OP_TOKEN_FILE" && -r "$OP_TOKEN_FILE" ]]; then
          token="$(tr -d '\n' < "$OP_TOKEN_FILE")"
        elif [[ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]]; then
          token="$OP_SERVICE_ACCOUNT_TOKEN"
        elif can_prompt_user; then
          printf 'OP_SERVICE_ACCOUNT_TOKEN (input hidden, empty to skip): '
          read -rs token < /dev/tty || token=""
          printf '\n'
        else
          token=""
        fi
        if [[ -n "$token" ]]; then
          write_token_file "$path" OP_SERVICE_ACCOUNT_TOKEN "$token"
          printf '  backend ready: onepassword\n'
        else
          printf '  no token provided; write %s later or: vaulted-agent auth-mode prompt\n' "$path"
        fi
      fi
      ;;
    bitwarden|bws)
      SETUP_BACKEND=bitwarden
      path="${CONFIG}/bws.env"
      ensure_ref_manifest bitwarden.refs \
        '# Bitwarden Secrets Manager — one per line, no secret values:' \
        '#   VAR=<secret-uuid>' \
        '# List ids: bws secret list' \
        '# With auth_mode=prompt, launch asks for BWS_ACCESS_TOKEN (not written to disk).'
      printf '  Wiring day-one harnesses to bitwarden…\n'
      wire_day_one_harnesses bitwarden bitwarden.refs
      if [[ "$AUTH_MODE_CHOICE" == prompt ]]; then
        printf '  auth_mode=prompt: not writing %s\n' "$path"
        printf '  backend ready: bitwarden — launch prompts for BWS_ACCESS_TOKEN\n'
        printf '  change later: vaulted-agent auth-mode file|prompt\n'
      else
        if [[ -n "$BWS_TOKEN_FILE" && -r "$BWS_TOKEN_FILE" ]]; then
          token="$(tr -d '\n' < "$BWS_TOKEN_FILE")"
        elif [[ -n "${BWS_ACCESS_TOKEN:-}" ]]; then
          token="$BWS_ACCESS_TOKEN"
        elif can_prompt_user; then
          printf 'BWS_ACCESS_TOKEN (input hidden, empty to skip): '
          read -rs token < /dev/tty || token=""
          printf '\n'
        else
          token=""
        fi
        if [[ -n "$token" ]]; then
          write_token_file "$path" BWS_ACCESS_TOKEN "$token"
          printf '  backend ready: bitwarden\n'
        else
          printf '  no token provided; write %s later or: vaulted-agent auth-mode prompt\n' "$path"
        fi
      fi
      ;;
    pass)
      SETUP_BACKEND=pass
      ensure_ref_manifest pass.refs \
        '# pass (passwordstore.org) — one per line:' \
        '#   VAR=store/entry/path' \
        '# Service account needs GPG + `pass show`.'
      printf '  Wiring day-one harnesses to pass…\n'
      wire_day_one_harnesses pass pass.refs
      printf '  pass: ensure the service account can run `pass show` (GPG key).\n'
      printf '  auth_mode=%s is recorded; pass uses GPG, not a pasteable vault token file.\n' \
        "$AUTH_MODE_CHOICE"
      ;;
    sops)
      printf '  sops: place an age identity at %s/age.key (0600) and set backend=sops.\n' "$CONFIG"
      printf '  auth_mode=%s is recorded; sops uses age.key, not a pasteable vault token.\n' \
        "$AUTH_MODE_CHOICE"
      printf '  (day-one harnesses left as plainfile — sops needs an encrypted manifest per harness)\n'
      ;;
    skip|plainfile|none|'')
      printf '\nVault setup skipped. Agents launch with empty.env until you configure a backend.\n'
      printf '  auth_mode=%s  (change later: vaulted-agent auth-mode)\n' "$AUTH_MODE_CHOICE"
      printf '  Interactive later:  vaulted-agent setup\n'
      ;;
    *)
      printf '  unknown --backend %s; skipping\n' "$choice"
      ;;
  esac
}

if (( ! NO_SETUP )); then
  prompt_backend_setup
else
  printf '\nskipped vault setup prompts (--no-setup)\n'
  # Still record auth_mode when the operator passed it explicitly.
  if [[ -n "$AUTH_MODE_CHOICE" ]]; then
    write_defaults_conf "$AUTH_MODE_CHOICE"
  elif [[ ! -e "$CONFIG/defaults.conf" ]]; then
    write_defaults_conf file
  fi
  ensure_workdir_caller
  # --backend without interactive setup should still rewire day-one harnesses.
  case "${BACKEND_CHOICE}" in
    onepassword|op)
      SETUP_BACKEND=onepassword
      ensure_ref_manifest onepassword.refs \
        '# VAR=op://Vault/Item/field'
      wire_day_one_harnesses onepassword onepassword.refs
      ;;
    bitwarden|bws)
      SETUP_BACKEND=bitwarden
      ensure_ref_manifest bitwarden.refs \
        '# VAR=<secret-uuid>  # bws secret list'
      wire_day_one_harnesses bitwarden bitwarden.refs
      ;;
    pass)
      SETUP_BACKEND=pass
      ensure_ref_manifest pass.refs \
        '# VAR=store/entry/path'
      wire_day_one_harnesses pass pass.refs
      ;;
  esac
fi

# --- optional per-harness symlinks -----------------------------------------
if [[ -n "$LINKS" ]]; then
  # bash 3.2: read -a from a here-string is fine; avoid mapfile.
  IFS=',' read -r -a wanted <<< "$LINKS"
  for name in "${wanted[@]}"; do
    name="$(printf '%s' "$name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -n "$name" ]] || continue
    link="$PREFIX/${name}-conductor"
    if [[ -e "$link" || -L "$link" ]]; then
      target="$(resolve_path "$link")"
      if [[ "$target" == "$PREFIX/vaulted-agent" ]]; then
        printf 'link already correct: %s\n' "$link"; continue
      fi
      (( FORCE )) || die "$link already exists and is not ours (-> ${target:-?}).
  Refusing to overwrite. Pass --force if you really mean to replace it."
      printf 'REPLACING pre-existing %s\n' "$link"
    fi
    run ln -sfn "$PREFIX/vaulted-agent" "$link"
    printf 'linked %s\n' "$link"
  done
fi

# --- optional sudoers rule --------------------------------------------------
if [[ -n "$ALLOW_USER" ]]; then
  sudoers="/etc/sudoers.d/vaulted-agent"
  # Grant both the long name and the short alias when the alias is installed.
  lines=(
    "$ALLOW_USER ALL=($SERVICE_USER) NOPASSWD: $PREFIX/vaulted-agent"
  )
  (( ! NO_VA )) && lines+=(
    "$ALLOW_USER ALL=($SERVICE_USER) NOPASSWD: $PREFIX/$SHORT_NAME"
  )
  if (( DRY )); then
    printf '  would write %s:\n' "$sudoers"
    for line in "${lines[@]}"; do printf '    %s\n' "$line"; done
  else
    : > "$sudoers"
    for line in "${lines[@]}"; do printf '%s\n' "$line" >> "$sudoers"; done
    chmod 0440 "$sudoers"
    visudo -cf "$sudoers" >/dev/null || { rm -f "$sudoers"; die "sudoers rule rejected"; }
    printf 'wrote %s\n' "$sudoers"
  fi
  printf '  note: this grants %s EVERY harness, including ones added later.\n' "$ALLOW_USER"
  printf '  For per-harness control use --links and one sudoers line per link.\n'
fi

# --- is the launcher reachable by the person who will type the command? ----
# `~/.local/bin` is the target because it is conventionally on the PATH and is
# the user's own directory, so this needs no change to system PATH config. The
# link may live anywhere: the sudo re-exec always rebuilds the path as
# $PREFIX/vaulted-agent, so the sudoers rule still matches either way.
link_into_home() {
  local u="$1" home grp dest
  home="$(user_home "$u")" || die "cannot find a home directory for '$u'"
  grp="$(id -gn "$u")"
  [[ -n "$home" && -d "$home" ]] || die "cannot find a home directory for '$u'"
  [[ -d "$home/.local/bin" ]] || run install -d -o "$u" -g "$grp" -m 0755 "$home/.local/bin"
  for dest in "$home/.local/bin/vaulted-agent" \
              $( (( ! NO_VA )) && printf '%s' "$home/.local/bin/$SHORT_NAME" ); do
    [[ -n "$dest" ]] || continue
    run ln -sfn "$PREFIX/vaulted-agent" "$dest"
    # -h: change symlink ownership, not the target (GNU and BSD chown).
    run chown -h "$u:$grp" "$dest" 2>/dev/null || run chown "$u:$grp" "$dest"
    printf 'linked %s -> %s/vaulted-agent\n' "$dest" "$PREFIX"
  done
}

# Can this user resolve vaulted-agent on a login-ish PATH? Prefer sudo -iu
# (works on both Linux and macOS); fall back to su -l.
user_can_run_vaulted_agent() {
  local u="$1"
  if command -v sudo >/dev/null 2>&1; then
    sudo -niu "$u" -- command -v vaulted-agent >/dev/null 2>&1 && return 0
  fi
  if command -v su >/dev/null 2>&1; then
    su -l "$u" -c 'command -v vaulted-agent' >/dev/null 2>&1 && return 0
  fi
  return 1
}

if [[ -n "$LINK_USER" ]]; then
  id -u "$LINK_USER" >/dev/null 2>&1 || die "no such user '$LINK_USER'"
  link_into_home "$LINK_USER"
else
  # The check below is deliberately one-sided. A login shell FAILING to
  # resolve the command is conclusive: it is definitely not reachable. A login
  # shell finding it proves little, because root's PATH and a synthetic login
  # PATH often contain /usr/local/bin when the user's interactive shell does
  # not. Shout on a definite failure; otherwise offer a check in their shell.
  who="${ALLOW_USER:-${SUDO_USER:-}}"
  fixcmd="mkdir -p ~/.local/bin && ln -s $PREFIX/vaulted-agent ~/.local/bin/vaulted-agent"
  (( ! NO_VA )) && fixcmd="$fixcmd && ln -s $PREFIX/vaulted-agent ~/.local/bin/$SHORT_NAME"
  rerun="sudo $0 ${ORIG_ARGS[*]-} --link-user ${who:-YOU}"
  if [[ -n "$who" && "$(id -u)" -eq 0 ]] \
     && ! user_can_run_vaulted_agent "$who"; then
    printf '\nNOT REACHABLE: %s cannot run `vaulted-agent`; %s is not on their PATH.\n' \
      "$who" "$PREFIX"
    printf '  Fix it for them:   %s\n' "$rerun"
    printf '  Or, as %s:   %s\n' "$who" "$fixcmd"
    printf '  On macOS, also ensure ~/.local/bin is on your PATH (e.g. in ~/.zprofile).\n'
  else
    printf '\nConfirm it is reachable from your own shell (this is the authoritative test,\n'
    printf 'since an installer cannot see your interactive PATH):\n'
    printf '    command -v vaulted-agent\n'
    (( ! NO_VA )) && printf '    command -v %s\n' "$SHORT_NAME"
    printf '  Finding nothing means %s is not on your PATH. Then either:\n' "$PREFIX"
    printf '    %s\n' "$fixcmd"
    printf '  or re-run with:  --link-user %s\n' "${who:-<you>}"
  fi
  unset who fixcmd rerun
fi

printf '\nNext:\n'
if [[ -n "$REFS_MANIFEST_PATH" ]]; then
  case "${SETUP_BACKEND}" in
    bitwarden)
      printf '  Put Bitwarden credential references (VAR=<secret-uuid>) in:\n'
      printf '    %s\n' "$REFS_MANIFEST_PATH"
      printf '  List secret ids with:  bws secret list\n'
      ;;
    onepassword)
      printf '  Put 1Password credential references (VAR=op://Vault/Item/field) in:\n'
      printf '    %s\n' "$REFS_MANIFEST_PATH"
      ;;
    pass)
      printf '  Put pass store paths (VAR=store/entry/path) in:\n'
      printf '    %s\n' "$REFS_MANIFEST_PATH"
      ;;
    *)
      printf '  Put credential references in:\n'
      printf '    %s\n' "$REFS_MANIFEST_PATH"
      ;;
  esac
  printf '  (references only — never secret values; safe to edit as root)\n'
fi
if [[ "${AUTH_MODE_CHOICE:-file}" == prompt ]]; then
  printf '  auth_mode is prompt — paste the vault token when launching (nothing on disk).\n'
  printf '  Change later:  vaulted-agent auth-mode file|prompt\n'
else
  case "${SETUP_BACKEND}" in
    bitwarden)
      printf '  Vault token file (if using file auth): %s/bws.env  (0640 root:%s)\n' \
        "$CONFIG" "$SERVICE_USER"
      ;;
    onepassword)
      printf '  Vault token file (if using file auth): %s  (0640 root:%s)\n' \
        "$OP_ENV" "$SERVICE_USER"
      ;;
    *)
      printf '  put a backend credential at %s (0640 root:%s) if you use file auth,\n' \
        "$OP_ENV" "$SERVICE_USER"
      ;;
  esac
  printf '  or switch to paste-each-launch:  vaulted-agent auth-mode prompt\n'
fi
if [[ -z "$REFS_MANIFEST_PATH" ]]; then
  printf '  copy a harness into place if needed:\n'
  printf '    cp %s/harnesses.d/claude.conf.example %s/harnesses.d/claude.conf\n' "$CONFIG" "$CONFIG"
fi
printf '  then run:  vaulted-agent   (or the short alias:  %s)\n' "$SHORT_NAME"
printf '    e.g.  %s claude   /   %s grok   /   %s kimi   /   %s bash\n' \
  "$SHORT_NAME" "$SHORT_NAME" "$SHORT_NAME" "$SHORT_NAME"
printf '    (or: sudo -u %s %s/vaulted-agent)\n' "$SERVICE_USER" "$PREFIX"
printf '\nTo remove this install later:\n'
printf '  sudo vaulted-agent uninstall\n'
printf '  sudo vaulted-agent uninstall --purge   # also remove config\n'
