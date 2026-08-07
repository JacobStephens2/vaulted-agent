# Migration: 1Password refresh naming and duplicates (unreleased)

## 1Password variable names drop the default section label

`refresh` builds each variable name from item title + section + field. 1Password
labels the section holding custom fields added without choosing one `add more`,
so items across a vault carry a section nobody named, and every field under one
was mapped as `ANTHROPIC_ADD_MORE_CONDUCTOR_API_KEY` rather than
`ANTHROPIC_CONDUCTOR_API_KEY`.

A default section label no longer reaches the name. References are unchanged —
they still carry the section, so what `op` resolves is exactly what it was.

**This renames variables the next `refresh` writes.** Existing manifests are not
rewritten and keep working; nothing breaks until you refresh, and then only for
names the tool generated. `doctor` reports any manifest still carrying the old
form.

To adopt the new names:

```bash
vaulted-agent doctor                      # lists manifests with legacy names
vaulted-agent refresh --replace           # rewrite with the new scheme
```

Rewriting drops names you hand-wrote, so if a manifest mixes curated and
generated entries, edit the generated ones in place instead — or leave them.
Anything reading a renamed variable (a service file, an agent's config) has to
move at the same time, which is why nothing renames itself.

Two fields in one item that would now collide — the same label inside and
outside the default section — both keep the section, so no secret is lost to
the rename.

## `refresh` no longer has to map every field

`refresh` maps every referenceable field of every item it is given, including
the ones around a credential: the `username` beside a password, or a login item
whose password field holds `google` because the account signs in with Google.

`--exclude` takes a variable-name pattern (`*` and `?`, matched against the
whole name, case-insensitive), is repeatable, and is recorded in the manifest so
later runs honour it without retyping:

```bash
vaulted-agent refresh --exclude '*_USERNAME' --exclude 'ZOOM_*'
```

Patterns live as `# exclude: <pattern>` lines and survive `--replace`. Remove a
line to map those fields again. Excluded fields are listed on each run rather
than dropped silently.

## Duplicate mappings on merge

`refresh --merge` skipped an entry only when the manifest held a byte-identical
`op://` string. A curated `op://V/item/field` and a generated
`op://V/item/add more/field` are the same secret, so merge appended the second
as a new mapping — on one 60-item vault, 81 credentials reaching the agent twice
under two names.

Merge now compares the field a reference identifies, treating a default section
label as equivalent to no section. Existing duplicates are not removed; a
`refresh --replace`, or deleting the generated lines, clears them.

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
