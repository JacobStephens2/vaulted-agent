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
#   sudo ./install.sh --backend bitwarden --bws-token-file /root/bws-token
#   ./install.sh --user conductor --workdir /srv/orchestration --link-user alice \
#                --backend onepassword --op-env /etc/orchestration/op.env --allow-user alice
#
# Vault setup is done by the installed launcher: this script asks, then runs
# `vaulted-agent auth-mode`, `vaulted-agent setup <backend> --wire-only` and,
# with auth_mode=file, pipes the Manager token to `setup <backend> --set-token`,
# which verifies it against the vault before writing it. A rejected token does
# not stop the install. Token sources: a paste, --bws-token-file,
# --op-token-file, the exported BWS_ACCESS_TOKEN / OP_SERVICE_ACCOUNT_TOKEN,
# or --op-env PATH: an existing env file whose OP_SERVICE_ACCOUNT_TOKEN is
# stored in <config>/op.env, the only file the launcher reads. Skipping the
# backend (or no --backend without a terminal) leaves default_backend alone.
#
# Agent CLI detection is the launcher's too: `vaulted-agent update
# --sync-harnesses` (Harness discovery), with --user as the launch account.
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
OP_ENV=""                        # token source: OP_SERVICE_ACCOUNT_TOKEN read from here
LINKS=""                         # e.g. claude,codex,grok -> claude-conductor, ...
ALLOW_USER=""                    # write a sudoers rule for this user
LINK_USER=""                     # symlink into this user's ~/.local/bin
NO_LINK=0                        # skip the default ~/.local/bin symlink
NO_VA=0                          # skip the short `va` alias symlink
NO_AUTO_HARNESS=0                # skip Harness discovery (update --sync-harnesses)
NO_SETUP=0                       # skip interactive vault backend questions
SHORT_NAME="va"                  # short alias for vaulted-agent
BACKEND_CHOICE=""                # onepassword|bitwarden|pass|sops|skip
AUTH_MODE_CHOICE=""              # file|prompt — how vault tokens are supplied at launch
SETUP_BACKEND=""                 # backend wired this run, for the final summary
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
# from /dev/tty. -t 1 is enough to know we're not running under a fully
# detached cron/CI sink.
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
    -h|--help)         awk 'NR > 2 && /^# ---/ { exit } NR >= 2' "$0"; exit 0 ;;
    *)                 die "unknown option '$1'" ;;
  esac
done

case "${AUTH_MODE_CHOICE}" in
  ''|file|prompt) ;;
  *) die "--auth-mode must be 'file' or 'prompt' (got '$AUTH_MODE_CHOICE')" ;;
esac

case "${BACKEND_CHOICE}" in
  '')                     ;;
  bitwarden|bws)          BACKEND_CHOICE=bitwarden ;;
  onepassword|op|1password) BACKEND_CHOICE=onepassword ;;
  pass|sops)              ;;
  skip|plainfile|none)    BACKEND_CHOICE=skip ;;
  *) die "--backend must be onepassword, bitwarden, pass, sops or skip (got '$BACKEND_CHOICE')" ;;
esac

# --- the launcher binary ------------------------------------------------------
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

# --- uninstall --------------------------------------------------------------
# One implementation: the launcher's `uninstall` (the Uninstall plan). It
# removes a symlink only when it resolves to the launcher, keeps config unless
# --purge, and never removes a backend credential. The installed launcher runs
# it when there is one; otherwise the binary an install would use.
if (( UNINSTALL )); then
  if [[ -x "$PREFIX/vaulted-agent" ]]; then
    uninstaller="$PREFIX/vaulted-agent"
  else
    uninstaller="$(resolve_rust_binary)"
  fi
  uninstall_args=()
  if (( PURGE )); then uninstall_args+=(--purge); fi
  if (( DRY )); then uninstall_args+=(--dry-run); fi
  if (( ASSUME_YES )); then uninstall_args+=(--yes); fi
  if [[ -n "$LINK_USER" ]]; then uninstall_args+=(--link-user "$LINK_USER"); fi
  exec env VAULTED_AGENT_BIN_DIR="$PREFIX" VAULTED_AGENT_CONFIG_DIR="$CONFIG" \
    "$uninstaller" uninstall ${uninstall_args[@]+"${uninstall_args[@]}"}
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
printf '  service account : %s (workdir %s)%s\n' "$SERVICE_USER" "$WORKDIR" \
  "$( (( USER_EXPLICIT )) || printf '   <- you; --user <name> for a dedicated account' )"
printf '  launcher        : %s/vaulted-agent\n' "$PREFIX"
printf '  config          : %s\n' "$CONFIG"
case "$BACKEND_CHOICE" in
  '')   printf '  backend         : asked below (skipping leaves it as it is)\n' ;;
  skip) printf '  backend         : skipped (left as it is)\n' ;;
  *)    printf '  backend         : %s\n' "$BACKEND_CHOICE" ;;
esac
(( DRY )) && printf '  (dry run)\n'
printf '\n'

# --- the launcher (Rust binary; machine defaults go in defaults.conf) ------
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

# --- Harness discovery: the launcher's `update --sync-harnesses` -----------
# The launcher owns detection (src/harness_sync.rs): it searches for each
# auto-harness binary as the launch account, which is the service account
# passed here, writes a Harness conf for each one found without an entry, and
# reports added, kept, found only for the invoking account, and not found. A
# dry run asks the binary it would install, which writes nothing.
if (( ! NO_AUTO_HARNESS )); then
  printf '\n'
  if (( DRY )); then
    discoverer="$RUST_BIN"
    sync_args=(--dry-run)
  else
    discoverer="$PREFIX/vaulted-agent"
    sync_args=()
  fi
  VAULTED_AGENT_CONFIG_DIR="$CONFIG" VAULTED_AGENT_SERVICE_USER="$SERVICE_USER" \
    "$discoverer" update --sync-harnesses ${sync_args[@]+"${sync_args[@]}"} \
    || die "Harness discovery failed (message above). Retry: sudo VAULTED_AGENT_CONFIG_DIR=$CONFIG vaulted-agent update --sync-harnesses"
  unset discoverer sync_args
else
  printf '\nskipped auto-harness detect (--no-auto-harness)\n'
fi

# --- vault setup: questions here, every vault-config write by the launcher --
# Under `curl | bash` stdin is a pipe, so the launcher's own menus cannot run.
# This script asks the questions and turns the answers into launcher calls;
# Vault wiring, auth_mode and the Manager-token file all belong to the
# launcher, which verifies a token live before it is stored (issue #148).
LAUNCHER="$PREFIX/vaulted-agent"

# Run the installed launcher against --config. Dry run: print, run nothing.
run_launcher() {
  if (( DRY )); then
    printf '  would: VAULTED_AGENT_CONFIG_DIR=%s %s %s\n' "$CONFIG" "$LAUNCHER" "$*"
    return 0
  fi
  VAULTED_AGENT_CONFIG_DIR="$CONFIG" "$LAUNCHER" "$@"
}

# service_user is install-time identity, not vault wiring, and the launcher has
# no non-interactive setter for it. Written only for an explicit --user (the
# default runs agents as the invoker, no sudo hop); every other line is kept.
write_service_user() {
  local path="$CONFIG/defaults.conf" tmp
  (( USER_EXPLICIT )) || return 0
  if (( DRY )); then
    printf '  would set service_user = %s in %s\n' "$SERVICE_USER" "$path"
    return 0
  fi
  tmp="$(mktemp)" || die "mktemp failed"
  if [[ -f "$path" ]]; then
    awk '{ line = $0
           sub(/[[:space:]]*#.*/, "", line)
           split(line, kv, "=")
           key = kv[1]; gsub(/[[:space:]]/, "", key)
           if (key == "service_user") next
           print $0 }' "$path" > "$tmp"
  fi
  printf 'service_user = %s\n' "$SERVICE_USER" >> "$tmp"
  install -m 0644 "$tmp" "$path"
  rm -f "$tmp"
  printf '  service_user = %s  (%s)\n' "$SERVICE_USER" "$path"
}

# Resolve AUTH_MODE_CHOICE interactively when unset. Left unset when nobody
# can answer, so a re-install never resets a configured mode.
prompt_auth_mode_setup() {
  local choice
  if [[ -n "$AUTH_MODE_CHOICE" ]] || (( NO_SETUP )) || ! can_prompt_user; then
    return 0
  fi
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
}

# Record the chosen auth mode; a fresh install records file. Afterwards
# AUTH_MODE_CHOICE holds the mode in force, which decides whether a token is
# stored at all.
apply_auth_mode() {
  local shown
  if [[ -n "$AUTH_MODE_CHOICE" ]]; then
    run_launcher auth-mode "$AUTH_MODE_CHOICE"
  elif [[ ! -e "$CONFIG/defaults.conf" ]]; then
    AUTH_MODE_CHOICE=file
    run_launcher auth-mode file
  else
    # Read-only, so a dry run asks too: the binary it would install.
    shown="$(VAULTED_AGENT_CONFIG_DIR="$CONFIG" "$RUST_BIN" auth-mode show)" \
      || die "cannot read auth_mode (message above)"
    AUTH_MODE_CHOICE="${shown#auth_mode=}"
  fi
}

prompt_backend_setup() {
  local choice
  if [[ -n "$BACKEND_CHOICE" ]]; then
    return 0
  fi
  if (( ! NO_SETUP )) && can_prompt_user; then
    printf '\nDefault secret backend for this machine?\n'
    printf '  1) 1Password service account  (op inject)\n'
    printf '  2) Bitwarden Secrets Manager  (bws)\n'
    printf '  3) pass (passwordstore.org)\n'
    printf '  4) sops + age\n'
    printf '  5) Skip — leave the backend as it is (day-one agents launch with no vault secrets)\n'
    printf 'choice [1-5, default 5]: '
    read -r choice < /dev/tty || choice=5
    case "$choice" in
      1|onepassword|op|1password) BACKEND_CHOICE=onepassword ;;
      2|bitwarden|bws)  BACKEND_CHOICE=bitwarden ;;
      3|pass)           BACKEND_CHOICE=pass ;;
      4|sops)           BACKEND_CHOICE=sops ;;
      5|''|skip|plainfile|none) BACKEND_CHOICE=skip ;;
      *) printf '  unknown choice; skipping vault setup\n'; BACKEND_CHOICE=skip ;;
    esac
    return 0
  fi
  BACKEND_CHOICE=skip
  if (( ! NO_SETUP )); then
    printf '\nNo interactive terminal for setup questions (common with curl|bash in CI).\n'
    printf '  Backend skipped: default_backend and Harnesses left as they are.\n'
    printf '  Later: vaulted-agent setup   and/or   vaulted-agent auth-mode\n'
    printf '  Or re-run with flags, e.g.:\n'
    printf '    curl -fsSL …/install.sh | bash -s -- --backend bitwarden --auth-mode prompt\n'
  fi
}

# How to store a Manager token after the install (verified before written).
print_set_token_hint() {
  printf '    printf %%s "$TOKEN" | sudo vaulted-agent setup %s --set-token\n' "$1"
}

# Value of KEY in an env-style file (KEY=value, optional `export`, quotes).
token_from_env_file() {
  local file="$1" key="$2" line
  [[ -r "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line#export }"
    case "$line" in
      "$key="*)
        line="${line#"$key="}"
        line="${line%"${line##*[![:space:]]}"}"
        case "$line" in
          \"*\") line="${line#\"}"; line="${line%\"}" ;;
          \'*\') line="${line#\'}"; line="${line%\'}" ;;
        esac
        printf '%s' "$line"
        return 0
        ;;
    esac
  done < "$file"
}

# Hand a Manager token to the launcher's Token capture: piped with the printf
# builtin (never on argv), verified live, then written. A rejected token is not
# fatal: the install finishes, as it does when no token was given.
store_manager_token() {
  local be="$1" var token="" token_file=""
  case "$be" in
    bitwarden)   var=BWS_ACCESS_TOKEN;         token_file="$BWS_TOKEN_FILE" ;;
    onepassword) var=OP_SERVICE_ACCOUNT_TOKEN; token_file="$OP_TOKEN_FILE" ;;
    *) return 0 ;;
  esac
  if [[ "$AUTH_MODE_CHOICE" == prompt ]]; then
    printf '  auth_mode=prompt: no token stored; launch prompts for %s\n' "$var"
    printf '  change later: vaulted-agent auth-mode file|prompt\n'
    return 0
  fi
  if [[ -n "$token_file" ]]; then
    if [[ -r "$token_file" ]]; then
      token="$(tr -d '\n' < "$token_file")"
    else
      printf '  cannot read %s; no token from it\n' "$token_file"
    fi
  fi
  if [[ "$be" == onepassword && -n "$OP_ENV" ]]; then
    printf '  --op-env %s: the launcher reads only %s/op.env\n' "$OP_ENV" "$CONFIG"
    if [[ -n "$token" ]]; then
      printf '  not read: --op-token-file already gave the token\n'
    else
      token="$(token_from_env_file "$OP_ENV" "$var")"
      if [[ -n "$token" ]]; then
        printf '  read %s from it, to be stored there\n' "$var"
      else
        printf '  no %s in it (missing or unreadable)\n' "$var"
      fi
    fi
  fi
  if [[ -z "$token" ]]; then
    token="${!var:-}"
  fi
  if [[ -z "$token" ]] && can_prompt_user; then
    printf '%s (input hidden, empty to skip): ' "$var"
    read -rs token < /dev/tty || token=""
    printf '\n'
  fi
  if [[ -z "$token" ]]; then
    printf '  no token provided; store it later (verified before it is written):\n'
    print_set_token_hint "$be"
    printf '  or paste it each launch:  vaulted-agent auth-mode prompt\n'
    return 0
  fi
  if (( DRY )); then
    printf '  would: printf %%s <%s elided> | VAULTED_AGENT_CONFIG_DIR=%s %s setup %s --set-token\n' \
      "$var" "$CONFIG" "$LAUNCHER" "$be"
    return 0
  fi
  if printf '%s' "$token" | VAULTED_AGENT_CONFIG_DIR="$CONFIG" "$LAUNCHER" setup "$be" --set-token; then
    printf '  backend ready: %s\n' "$be"
  else
    printf '  %s: token was not stored (the launcher says why, above).\n' "$var"
    printf '  Retry:\n'
    print_set_token_hint "$be"
  fi
  token=""
}

if (( NO_SETUP )); then
  printf '\nskipped vault setup prompts (--no-setup)\n'
fi
prompt_backend_setup
prompt_auth_mode_setup
printf '\n'
write_service_user
apply_auth_mode
if [[ -n "$OP_ENV" && "$BACKEND_CHOICE" != onepassword ]]; then
  printf '  --op-env %s ignored: it is a token source for --backend onepassword only\n' "$OP_ENV"
fi
case "$BACKEND_CHOICE" in
  skip)
    printf '\nVault setup skipped: default_backend and Harnesses left as they are.\n'
    printf '  auth_mode=%s  (change later: vaulted-agent auth-mode)\n' "$AUTH_MODE_CHOICE"
    printf '  Later:  sudo vaulted-agent setup bitwarden|onepassword|pass|sops\n'
    ;;
  *)
    SETUP_BACKEND="$BACKEND_CHOICE"
    run_launcher setup "$BACKEND_CHOICE" --wire-only \
      || die "vault wiring failed (message above). Retry: sudo vaulted-agent setup $BACKEND_CHOICE --wire-only"
    case "$BACKEND_CHOICE" in
      bitwarden|onepassword) store_manager_token "$BACKEND_CHOICE" ;;
      pass)
        printf '  pass: ensure the service account can run `pass show` (GPG key).\n'
        printf '  auth_mode=%s is recorded; pass uses GPG, not a pasteable vault token file.\n' \
          "$AUTH_MODE_CHOICE"
        ;;
      sops)
        printf '  sops: place an age identity at %s/age.key (0600); give each Harness that\n' "$CONFIG"
        printf '  should use it backend = sops and a sops-encrypted manifest of its own.\n'
        printf '  auth_mode=%s is recorded; sops uses age.key, not a pasteable vault token.\n' \
          "$AUTH_MODE_CHOICE"
        ;;
    esac
    ;;
esac

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
case "${SETUP_BACKEND}" in
  bitwarden)
    printf '  Put Bitwarden credential references in the Refs file named under\n'
    printf '  "Vault wiring" above, or map them with:  sudo vaulted-agent refresh\n'
    ;;
  onepassword)
    printf '  Put 1Password credential references in the Refs file named under\n'
    printf '  "Vault wiring" above, or map them with:  sudo vaulted-agent refresh --backend onepassword\n'
    ;;
  pass)
    printf '  Put pass store paths (VAR=store/entry/path) in the Refs file named under\n'
    printf '  "Vault wiring" above.\n'
    ;;
esac
if [[ -n "$SETUP_BACKEND" && "$SETUP_BACKEND" != sops ]]; then
  printf '  (references only — never secret values; edit with checks: vaulted-agent edit-manifest)\n'
fi
if [[ "${AUTH_MODE_CHOICE:-file}" == prompt ]]; then
  printf '  auth_mode is prompt — paste the vault token when launching (nothing on disk).\n'
  printf '  Change later:  vaulted-agent auth-mode file|prompt\n'
else
  case "${SETUP_BACKEND}" in
    bitwarden|onepassword)
      printf '  Manager-token file (file auth): %s/%s  (0640)\n' "$CONFIG" \
        "$( [[ "$SETUP_BACKEND" == bitwarden ]] && printf bws.env || printf op.env )"
      printf '  Store or rotate it:\n'
      print_set_token_hint "$SETUP_BACKEND"
      ;;
    '')
      printf '  Set up a vault:  sudo vaulted-agent setup bitwarden|onepassword|pass|sops\n'
      ;;
  esac
  printf '  or switch to paste-each-launch:  vaulted-agent auth-mode prompt\n'
fi
if [[ -z "$SETUP_BACKEND" ]]; then
  printf '  copy a harness into place if needed:\n'
  printf '    cp %s/harnesses.d/claude.conf.example %s/harnesses.d/claude.conf\n' "$CONFIG" "$CONFIG"
fi
printf '  then run:  vaulted-agent   (or the short alias:  %s)\n' "$SHORT_NAME"
printf '    e.g.  %s claude   /   %s grok   /   %s kimi   /   %s agy   /   %s muse   /   %s bash\n' \
  "$SHORT_NAME" "$SHORT_NAME" "$SHORT_NAME" "$SHORT_NAME" "$SHORT_NAME" "$SHORT_NAME"
printf '    (or: sudo -u %s %s/vaulted-agent)\n' "$SERVICE_USER" "$PREFIX"
printf '\nTo remove this install later:\n'
printf '  sudo vaulted-agent uninstall\n'
printf '  sudo vaulted-agent uninstall --purge   # also remove config\n'
