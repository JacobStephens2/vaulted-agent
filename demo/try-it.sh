#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# try-it.sh — see what vaulted-agent does, without installing it.
#
# Builds a throwaway config in a temp directory with two stub "agents" and a
# fake secret store, runs them, and shows the result. No root, no vault, and
# nothing written outside the temp directory, which is removed on exit.
#
#   ./demo/try-it.sh            run it
#   ./demo/try-it.sh --keep     keep the temp tree afterwards to poke at
# ---------------------------------------------------------------------------
set -euo pipefail

KEEP=0
[[ "${1-}" == "--keep" ]] && KEEP=1

REPO="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

# mktemp -d, not a fixed path. A predictable name under a world-writable /tmp
# collides with whatever another user left behind, and invites someone to
# pre-create it as a symlink to somewhere it should not point.
DEMO="$(mktemp -d "${TMPDIR:-/tmp}/vaulted-agent-demo.XXXXXXXX")"
cleanup() { (( KEEP )) || rm -rf "$DEMO"; }
trap cleanup EXIT

if [[ -t 1 ]]; then B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m'; else B=""; D=""; R=""; fi
step() { printf '\n%s%s%s\n\n' "$B" "$*" "$R"; }
note() { printf '   %s%s%s\n' "$D" "$*" "$R"; }

mkdir -p "$DEMO"/{bin,agents,etc/harnesses.d,etc/manifests,work}

# --- A patched copy of the launcher ----------------------------------------
# The paths at the top of the launcher are constants, not environment
# variables, on purpose: a caller who could set CONFIG_DIR could point it at a
# manifest of their own and name any secret the backend can reach. So the demo
# patches a copy rather than overriding anything at runtime.
sed -e "s|^SERVICE_USER=.*|SERVICE_USER=\"$(id -un)\"|" \
    -e "s|^WORKDIR=.*|WORKDIR=\"$DEMO/work\"|" \
    -e "s|^CONFIG_DIR=.*|CONFIG_DIR=\"$DEMO/etc\"|" \
    -e "s|^LAUNCHER_BIN_DIR=.*|LAUNCHER_BIN_DIR=\"$DEMO/bin\"|" \
    "$REPO/bin/vaulted-agent" > "$DEMO/bin/vaulted-agent"
chmod +x "$DEMO/bin/vaulted-agent"
export PATH="$DEMO/bin:$PATH"

# --- Stub agents. Each prints the secrets it was given, one name per line. --
# Anything not on the launcher's passthrough allowlist came from a manifest.
cat > "$DEMO/agents/show-secrets" <<'EOF'
#!/usr/bin/env bash
env | sed -n 's/=.*//p' \
    | grep -vxE 'HOME|PATH|USER|LOGNAME|SHELL|TERM|COLORTERM|TZ|LANG|LC_ALL|PWD|SHLVL|_' \
    | sort
EOF
cp "$DEMO/agents/show-secrets" "$DEMO/agents/claude"
cp "$DEMO/agents/show-secrets" "$DEMO/agents/grok"
chmod +x "$DEMO"/agents/*

# --- A fake secret store. With `plainfile`, the manifest IS the secrets. ----
cat > "$DEMO/etc/manifests/full.env" <<'EOF'
APP_DB_HOST=db.example.internal
APP_DB_USER=app
APP_DB_PASS=corr3ct-h0rse$battery`staple`
GH_TOKEN=ghp_exampleexampleexampleexample
SMTP_PASS=smtp-example-key
EOF
cat > "$DEMO/etc/manifests/readonly.env" <<'EOF'
APP_DB_HOST=db.example.internal
APP_DB_USER=readonly
APP_DB_PASS=readonly-password
EOF

cat > "$DEMO/etc/harnesses.d/claude.conf" <<EOF
backend  = plainfile
manifest = full.env
bin      = $DEMO/agents
command  = claude --permission-mode auto
EOF
cat > "$DEMO/etc/harnesses.d/grok.conf" <<EOF
backend  = plainfile
manifest = readonly.env
bin      = $DEMO/agents
command  = grok
EOF

printf '\n%svaulted-agent demo%s  %sno install, no vault, no root%s\n' "$B" "$R" "$D" "$R"

# --- 1. What is configured -------------------------------------------------
step "Two harnesses, sharing one secret store"
vaulted-agent 2>&1 | sed -n '/^  [a-z]/p' || true

# --- 2. The point: different harnesses get different secrets ---------------
step "Each receives only what its own manifest names"
mapfile -t c_secrets < <(vaulted-agent claude)
mapfile -t g_secrets < <(vaulted-agent grok)
has() { local n="$1"; shift; local x; for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done; return 1; }
printf '   %-16s %-8s %s\n' "" "claude" "grok"
while read -r name; do
  has "$name" ${c_secrets[@]+"${c_secrets[@]}"} && a="yes" || a=" -"
  has "$name" ${g_secrets[@]+"${g_secrets[@]}"} && b="yes" || b=" -"
  printf '   %-16s %-8s %s\n' "$name" "$a" "$b"
done < <(printf '%s\n' ${c_secrets[@]+"${c_secrets[@]}"} ${g_secrets[@]+"${g_secrets[@]}"} | sort -u)
note "grok's manifest never named GH_TOKEN or SMTP_PASS, so grok cannot see them."

# --- 3. Where the secrets live, and where they do not ----------------------
step "They reach the agent's environment, and nowhere else"
cat > "$DEMO/agents/probe" <<'EOF'
#!/usr/bin/env bash
# $$, not /proc/self: in a redirection that resolves to the reading process.
printf '   in its environment   APP_DB_PASS=%s\n' "${APP_DB_PASS-<unset>}"
printf '   on its command line  %s\n' "$(tr '\0' ' ' < "/proc/$$/cmdline")"
grep -qa 'corr3ct-h0rse' "/proc/$$/cmdline" \
  && printf '   LEAK: the secret is on the command line\n' \
  || printf '   from the caller      CALLER_SECRET=%s\n' "${CALLER_SECRET-removed by the scrub}"
EOF
chmod +x "$DEMO/agents/probe"
sed 's/^command  = .*/command  = probe/' "$DEMO/etc/harnesses.d/claude.conf" \
  > "$DEMO/etc/harnesses.d/probe.conf"
CALLER_SECRET="leaked-from-parent" vaulted-agent probe
note "'ps' shows the command line, never the environment. The caller's own"
note "secret was stripped, which is what keeps a narrow manifest meaningful"
note "when one agent launches another."

# --- 4. What it refuses to do ----------------------------------------------
step "It refuses rather than starting an agent half-fed"
sed 's/^manifest = .*/manifest = does-not-exist.env/' "$DEMO/etc/harnesses.d/grok.conf" \
  > "$DEMO/etc/harnesses.d/broken.conf"
printf '   unreachable secrets   '; vaulted-agent broken 2>&1 | sed 's/.*: //' || true
ln -sf "$DEMO/bin/vaulted-agent" "$DEMO/bin/grok-conductor"
printf '   borrowing a harness   '; grok-conductor -H claude 2>&1 | sed 's/.*: //' || true

# --- done ------------------------------------------------------------------
if (( KEEP )); then
  printf '\nTemp tree kept at %s\n' "$DEMO"
  printf 'Try:  PATH=%s/bin:$PATH vaulted-agent pick\n\n' "$DEMO"
else
  printf '\n%s\n\n' "Done. Nothing was installed; the temp tree has been removed. (--keep to keep it)"
fi
