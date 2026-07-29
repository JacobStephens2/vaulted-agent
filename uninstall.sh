#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# uninstall.sh — remove what install.sh installed.
#
#   sudo ./uninstall.sh                        interactive: shows what is
#                                              installed, asks what to remove
#   sudo ./uninstall.sh --dry-run              show what would go, change nothing
#   sudo ./uninstall.sh --yes                  no prompts, for scripts and cron
#   sudo ./uninstall.sh --purge                also remove the config directory
#   sudo ./uninstall.sh --link-user alice      also remove alice's ~/.local/bin link
#
# Accepts the same --prefix / --config as install.sh, if you installed
# somewhere other than the defaults.
#
# This is deliberately a four-line front door rather than a second
# implementation. Removal has to agree with installation about which files are
# "ours" -- specifically, that a symlink is only removed when it resolves to
# the launcher being uninstalled. Two copies of that rule would drift, and the
# failure mode is deleting somebody else's launcher.
# ---------------------------------------------------------------------------
set -euo pipefail

# Answer --help here. Forwarding it would print install.sh's usage, which is
# the opposite of why this file exists.
case "${1-}" in -h|--help) sed -n '2,19p' "$0"; exit 0 ;; esac

exec "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/install.sh" --uninstall ${1+"$@"}
