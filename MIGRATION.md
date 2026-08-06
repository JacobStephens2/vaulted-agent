# Migration: Bash runtime → Rust (v0.4.0)

## What changed

- **Runtime** is the Rust binary `vaulted-agent` (and `va` symlink). The Bash
  script is no longer installed; its last tree copy was removed after the Rust
  rewrite — use git history on `main` before v0.4.0 if you need the old script.
- **Machine defaults** (`auth_mode`, `default_backend`, optional `service_user`)
  live in `/etc/vaulted-agent/defaults.conf`. Install no longer sed-patches a
  shell script.
- **Service-user re-exec** uses `service_user = …` in `defaults.conf` (or
  `VAULTED_AGENT_SERVICE_USER`). Only set when you install with `--user` for a
  dedicated account.
- **Config dir** override remains `VAULTED_AGENT_CONFIG_DIR` (tests and alternate
  layouts).
- **Backends** are a typed enum: unknown names fail closed at parse/validate time
  (including `secrets validate` and harness load).

## Intentional breaks

- Hosts without a prebuilt binary or Rust toolchain cannot install from a bare
  source tree until they build (`cargo build --release --locked`) or use
  `install-remote.sh` / a release asset (`VAULTED_AGENT_BIN=…`).
- Bash-only extensions that sourced `bin/vaulted-agent` internals no longer
  work; use the CLI surface (`run`, `secrets`, `doctor`, …).
- Launcher flags (`-p`/`--prompt-auth`, `-H`/`--harness`) are only parsed
  **before** the first non-flag token. After the harness name, flags go to the
  agent (`va claude --version`, `va claude -p "…"`). Put launcher `-p` first:
  `va -p claude`.
- Dotenv-style manifests strip a single layer of surrounding quotes and keep
  double-quoted multi-line values (bash `source` parity). Invalid variable names
  fail closed instead of being silently dropped.

## Unchanged operator contract

- Harness files, manifests, backends (`bitwarden` / `onepassword` / `pass` /
  `sops` / `plainfile`), scrub → resolve → drop token → exec.
- `workdir = caller`, resume argv normalization, `labels = yes` UUIDv5.
- `va run`, `setup`, `refresh`, `auth-mode`, `uninstall` (including sudoers
  removal and `--link-user` user-local symlinks).
- Sudo re-exec replays the original argv as typed (sudoers-friendly).

## Upgrade

```bash
# From a release (recommended)
VAULTED_AGENT_VERSION=v0.4.0 curl -fsSL https://vaultedagent.com/install.sh | bash

# From a checkout with Rust
cargo build --release --locked && sudo ./install.sh --backend bitwarden --auth-mode file
```

Existing harnesses and manifests under `/etc/vaulted-agent` are kept. Re-run
`vaulted-agent doctor` after install.
