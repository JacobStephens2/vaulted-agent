# Migration: Bash runtime → Rust (v0.4.0)

## What changed

- **Runtime** is the Rust binary `vaulted-agent` (and `va` symlink). The Bash
  script is no longer installed; `bin/vaulted-agent.bash.retired` remains in the
  repo for history only.
- **Machine defaults** (`auth_mode`, `default_backend`, optional `service_user`)
  live in `/etc/vaulted-agent/defaults.conf`. Install no longer sed-patches a
  shell script.
- **Service-user re-exec** uses `service_user = …` in `defaults.conf` (or
  `VAULTED_AGENT_SERVICE_USER`). Only set when you install with `--user` for a
  dedicated account.
- **Config dir** override remains `VAULTED_AGENT_CONFIG_DIR` (tests and alternate
  layouts).

## Intentional breaks

- Hosts without a prebuilt binary or Rust toolchain cannot install from a bare
  source tree until they build (`cargo build --release`) or use
  `install-remote.sh` / a release asset (`VAULTED_AGENT_BIN=…`).
- Bash-only extensions that sourced `bin/vaulted-agent` internals no longer
  work; use the CLI surface (`run`, `secrets`, `doctor`, …).

## Unchanged operator contract

- Harness files, manifests, backends (`bitwarden` / `onepassword` / `pass` /
  `sops` / `plainfile`), scrub → resolve → drop token → exec.
- `workdir = caller`, resume argv normalization, `labels = yes` UUIDv5.
- `va run`, `setup`, `refresh`, `auth-mode`, `uninstall`.

## Upgrade

```bash
# From a release (recommended)
VAULTED_AGENT_VERSION=v0.4.0 curl -fsSL https://stephens.page/vaulted-agent/install.sh | bash

# From a checkout with Rust
cargo build --release && sudo ./install.sh --backend bitwarden --auth-mode file
```

Existing harnesses and manifests under `/etc/vaulted-agent` are kept. Re-run
`vaulted-agent doctor` after install.
