# Migration: a failed launch names the variable (unreleased)

When a launch could not resolve its manifest, the launcher printed the resolver
error and nothing else. For 1Password that names the *item* the vault could not
find, and `op inject` fails the whole file at the first bad reference — so the
message said neither which of 200 variables was at fault nor how much else was
broken.

A launch that cannot resolve now lists the manifest entries the error implicates
and names the command that confirms a fix:

```
vaulted-agent: could not resolve 1 reference(s) in orchestrator-all.env.tpl:
    TOURBOT_WEBHOOK_SHARED_SECRET_PASSWORD
      op://Orchestrator/Tourbot Webhook Shared Secret/password
  An item may have been renamed or removed in the vault.
  Confirm with: vaulted-agent secrets validate
```

The launch still fails, with the same error and exit status underneath. This is
additive output on a path that was already failing.

The attribution is the same one `secrets validate` uses, moved to
`validate::blame_manifest_lines` so both call sites share it rather than
drifting apart.

Renaming an item in the vault is the usual cause: the reference stays
well-formed and stops resolving, so no offline check can catch it. `doctor` is
offline by design and will still pass.

# Migration: `secrets validate` asks the vault (unreleased)

`secrets validate` checked that each reference was well *formed* and stopped
there. A reference can be perfectly well-formed and name an item that no longer
exists — after a rename in the vault, say — so the command printed `ok`, exited
0, and every launch then failed on the same file.

`CONTEXT.md` lists this command as the pre-flight gate that must not fail open.
It was failing open.

It now resolves every reference through `backend::resolve`, the same call a
launch makes, so validate agrees with a launch by construction rather than
through a second implementation that can drift. Resolved values are counted and
dropped — never printed, logged or returned.

When a reference cannot be resolved, the failing item is matched back to the
variables that use it, because the item is what the vault names and the variable
is what you can act on:

```
$ va secrets validate orchestrator-all.env.tpl
orchestrator-all.env.tpl: could not resolve:
    TOURBOT_WEBHOOK_SHARED_SECRET_PASSWORD
      op://Orchestrator/Tourbot Webhook Shared Secret/password
```

**This is a behaviour change.** Validation now needs a manager token and one
vault round trip, so it fails on a host that has neither where it used to pass.
That is the point — a gate that cannot reach the vault should say so rather than
report ok. `--offline` keeps the old check:

```bash
va secrets validate orchestrator-all.env.tpl --offline   # syntax only
```

`doctor` is unchanged and remains offline by design; it already says "syntax
checks only; live vault access not probed".

# Migration: launching a harness against another manifest (unreleased)

## `-m` on the harness path

`va run -m MANIFEST -- cmd` has always let a one-off command name its own
manifest. A harness could not: `claude.conf` fixed the manifest, and trying a
narrower one for a session meant editing config.

`va -m readonly.env.tpl claude` now launches the `claude` harness against
`readonly.env.tpl`. The harness still decides the command, the workdir, the
backend and everything else; only which credentials it carries changes. The
override replaces the configured manifest rather than merging with it, and a
manifest that does not exist is an error before the agent starts rather than an
agent that launches with an empty environment. Each overridden launch prints
which manifest it used.

Like `-p` and `-H`, it is a launcher flag, so it goes **before** the harness
name — `va -m x claude`, not `va claude -m x`, where it would be passed to the
agent instead.

**Refused under a `*-conductor` symlink**, alongside `-H` and for the same
reason. That symlink is what lets a sudoers rule grant one harness and have it
mean one set of credentials; a flag naming the manifest outright would undo it.
On the direct `va` path there is nothing to protect — a caller who can run `va`
can already run `va run -m` with any manifest — so it is allowed there.

Also refused in front of most management commands (`va -m x doctor`), where
`run` and `refresh` read their own `-m` from after the command name. Allowed
with `pick` (`va -m narrow.env pick`), which is a harness launch after the menu.

With `service_user`, the privilege hop re-execs the command line as typed. A
sudoers rule that only allows `vaulted-agent claude` will not match
`vaulted-agent -m … claude`. Prefer conductor links for delegated grants, or
extend sudoers to allow the launcher flags before the harness name.

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
- Launcher flags (`-p`/`--prompt-auth`, `-H`/`--harness`, `-m`/`--manifest`) are only parsed
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
