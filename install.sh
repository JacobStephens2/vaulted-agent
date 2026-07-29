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
#   ./install.sh --user conductor --workdir /srv/orchestration --link-user alice \
#                --op-env /etc/orchestration/op.env --allow-user alice
#
# To remove it again, use ./uninstall.sh (a front door onto --uninstall here):
#
#   ./install.sh --uninstall [--link-user alice] [--purge] [--dry-run] [--yes]
#
# Uninstall removes the launcher, any symlinks that point at it, and the
# sudoers rule. It keeps your config unless you add --purge, and it never
# touches a backend credential, which may well be shared with something else.
# ---------------------------------------------------------------------------
set -euo pipefail

SERVICE_USER=""                  # default: whoever invoked this script
WORKDIR=""                       # default: the service account's home
PREFIX="/usr/local/bin"
CONFIG="/etc/vaulted-agent"
OP_ENV=""                        # default: $CONFIG/op.env
LINKS=""                         # e.g. claude,codex,grok -> claude-conductor, ...
ALLOW_USER=""                    # write a sudoers rule for this user
LINK_USER=""                     # symlink into this user's ~/.local/bin
NO_LINK=0                        # skip the default ~/.local/bin symlink
USER_EXPLICIT=0
FORCE=0
DRY=0
UNINSTALL=0
PURGE=0
ASSUME_YES=0

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ORIG_ARGS=( ${1+"$@"} )          # kept for the re-run hint; the parse loop below consumes $@
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
run() { if (( DRY )); then printf '  would: %s\n' "$*"; else "$@"; fi; }

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
    --no-link)    NO_LINK=1; shift ;;
    -h|--help)    sed -n "2,20p" "$0"; exit 0 ;;
    *)            die "unknown option '$1'" ;;
  esac
done

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
  if (( ! ASSUME_YES )) && (( ! DRY )) && [[ -t 1 && -r /dev/tty ]]; then interactive=1; fi

  # Work out what would go before touching anything. The prompt, --dry-run and
  # the real removal all render from these same two lists.
  targets=(); foreign=(); declare -A seen_user=()

  shopt -s nullglob
  for link in "$PREFIX"/*-conductor; do
    if [[ -L "$link" && "$(readlink -f "$link" 2>/dev/null || true)" == "$launcher" ]]; then
      targets+=("$link")
    elif [[ -e "$link" || -L "$link" ]]; then
      foreign+=("$link")
    fi
  done
  shopt -u nullglob

  for u in ${LINK_USER:+"$LINK_USER"} ${SUDO_USER:+"$SUDO_USER"}; do
    if [[ -n "${seen_user[$u]-}" ]]; then continue; fi
    seen_user[$u]=1
    uh="$(getent passwd "$u" 2>/dev/null | cut -d: -f6 || true)"
    if [[ -z "$uh" ]]; then continue; fi
    ul="$uh/.local/bin/vaulted-agent"
    if [[ -L "$ul" && "$(readlink -f "$ul" 2>/dev/null || true)" == "$launcher" ]]; then
      targets+=("$ul")
    elif [[ -e "$ul" || -L "$ul" ]]; then
      foreign+=("$ul")
    fi
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
  useradd --system --home-dir /srv/$SERVICE_USER --create-home --shell /bin/bash $SERVICE_USER"

# Put the command on the invoking user's PATH by default: /usr/local/bin is
# absent from it more often than people expect, and a launcher you cannot type
# the name of is not installed in any useful sense.
if [[ -z "$LINK_USER" ]] && (( ! NO_LINK )) && [[ -n "${SUDO_USER:-}" ]]; then
  LINK_USER="$SUDO_USER"
fi

[[ -n "$WORKDIR" ]] || WORKDIR="$(getent passwd "$SERVICE_USER" | cut -d: -f6)"
[[ -n "$OP_ENV" ]]  || OP_ENV="${CONFIG}/op.env"

for d in "$PREFIX" "$(dirname "$CONFIG")" ${ALLOW_USER:+/etc/sudoers.d}; do
  [[ -w "$d" ]] || die "$d is not writable; re-run with sudo"
done

printf 'vaulted-agent install\n'
printf '  service account : %s (workdir %s)%s\n' "$SERVICE_USER" "$WORKDIR" \
  "$( (( USER_EXPLICIT )) || printf '   <- you; --user <name> for a dedicated account' )"
printf '  launcher        : %s/vaulted-agent\n' "$PREFIX"
printf '  config          : %s\n' "$CONFIG"
printf '  backend token   : %s\n' "$OP_ENV"
(( DRY )) && printf '  (dry run)\n'
printf '\n'

# --- the launcher, with its constants rewritten to this host ---------------
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
sed -e "s|^SERVICE_USER=.*|SERVICE_USER=\"$SERVICE_USER\"|" \
    -e "s|^WORKDIR=.*|WORKDIR=\"$WORKDIR\"|" \
    -e "s|^CONFIG_DIR=.*|CONFIG_DIR=\"$CONFIG\"|" \
    -e "s|^LAUNCHER_BIN_DIR=.*|LAUNCHER_BIN_DIR=\"$PREFIX\"|" \
    -e "s|^OP_ENV_FILE=.*|OP_ENV_FILE=\"$OP_ENV\"|" \
    "$REPO/bin/vaulted-agent" > "$tmp"
bash -n "$tmp" || die "patched launcher failed to parse; not installing"
run install -m 0755 "$tmp" "$PREFIX/vaulted-agent"
printf 'installed %s/vaulted-agent\n' "$PREFIX"

# --- config directories and sample config, never overwriting ---------------
run install -d -m 0755 "$CONFIG" "$CONFIG/harnesses.d" "$CONFIG/manifests"
# Samples land with a .example suffix. They reference a vault that does not
# exist on your machine, so installing them as live config would leave a fresh
# install listing several harnesses that all fail at injection. Copy one and
# drop the suffix to activate it.
for src in "$REPO"/etc/harnesses.d/* "$REPO"/etc/manifests/*; do
  base="${src#"$REPO"/etc/}"
  case "$base" in
    */README) dst="$CONFIG/$base" ;;
    *)        dst="$CONFIG/${base}.example" ;;
  esac
  if [[ -e "$dst" ]]; then
    printf 'kept existing %s\n' "$dst"
  else
    run install -m 0644 "$src" "$dst"
    printf 'installed %s\n' "$dst"
  fi
done

# --- optional per-harness symlinks -----------------------------------------
if [[ -n "$LINKS" ]]; then
  IFS=',' read -r -a wanted <<< "$LINKS"
  for name in "${wanted[@]}"; do
    link="$PREFIX/${name}-conductor"
    if [[ -e "$link" || -L "$link" ]]; then
      target="$(readlink -f "$link" 2>/dev/null || true)"
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
  line="$ALLOW_USER ALL=($SERVICE_USER) NOPASSWD: $PREFIX/vaulted-agent"
  if (( DRY )); then
    printf '  would write %s:\n    %s\n' "$sudoers" "$line"
  else
    printf '%s\n' "$line" > "$sudoers"
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
  local u="$1" home grp
  home="$(getent passwd "$u" | cut -d: -f6)"
  grp="$(id -gn "$u")"
  [[ -n "$home" && -d "$home" ]] || die "cannot find a home directory for '$u'"
  [[ -d "$home/.local/bin" ]] || run install -d -o "$u" -g "$grp" -m 0755 "$home/.local/bin"
  run ln -sfn "$PREFIX/vaulted-agent" "$home/.local/bin/vaulted-agent"
  run chown -h "$u:$grp" "$home/.local/bin/vaulted-agent"
  printf 'linked %s/.local/bin/vaulted-agent -> %s/vaulted-agent\n' "$home" "$PREFIX"
}

if [[ -n "$LINK_USER" ]]; then
  id -u "$LINK_USER" >/dev/null 2>&1 || die "no such user '$LINK_USER'"
  link_into_home "$LINK_USER"
else
  # The check below is deliberately one-sided. A login shell FAILING to
  # resolve the command is conclusive: it is definitely not reachable. A login
  # shell finding it proves little, because `su -l` synthesizes a PATH from
  # /etc/login.defs and `$PATH` here is root's secure_path -- both routinely
  # contain /usr/local/bin when the user's actual interactive shell does not.
  # So: shout on a definite failure, and otherwise offer a check the reader
  # can run in their own shell, where the answer is authoritative.
  who="${ALLOW_USER:-${SUDO_USER:-}}"
  home="${who:+$(getent passwd "$who" | cut -d: -f6)}"
  fixcmd="mkdir -p ~/.local/bin && ln -s $PREFIX/vaulted-agent ~/.local/bin/vaulted-agent"
  rerun="sudo $0 ${ORIG_ARGS[*]-} --link-user ${who:-YOU}"
  if [[ -n "$who" && "$(id -u)" -eq 0 ]] \
     && ! su -l "$who" -c 'command -v vaulted-agent' >/dev/null 2>&1; then
    printf '\nNOT REACHABLE: %s cannot run `vaulted-agent`; %s is not on their PATH.\n' \
      "$who" "$PREFIX"
    printf '  Fix it for them:   %s\n' "$rerun"
    printf '  Or, as %s:   %s\n' "$who" "$fixcmd"
  else
    printf '\nConfirm it is reachable from your own shell (this is the authoritative test,\n'
    printf 'since an installer cannot see your interactive PATH):\n'
    printf '    command -v vaulted-agent\n'
    printf '  Finding nothing means %s is not on your PATH. Then either:\n' "$PREFIX"
    printf '    %s\n' "$fixcmd"
    printf '  or re-run with:  --link-user %s\n' "${who:-<you>}"
  fi
  unset who home fixcmd rerun
fi

printf '\nNext: put a backend credential at %s (0640 root:%s),\n' "$OP_ENV" "$SERVICE_USER"
printf 'copy a harness into place:\n'
printf '  cp %s/harnesses.d/claude.conf.example %s/harnesses.d/claude.conf\n' "$CONFIG" "$CONFIG"
printf 'then run:  sudo -u %s %s/vaulted-agent\n' "$SERVICE_USER" "$PREFIX"
