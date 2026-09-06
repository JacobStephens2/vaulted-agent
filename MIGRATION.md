# Migration: glued Bitwarden refs from bash 0.3.0 `va refresh` (unreleased)

`va refresh` on the bash launcher (v0.3.0) captured each new `VAR=name:KEY`
line with `$(…)`, which strips the trailing newline, then concatenated. A
refs file could end up with one physical line:

```
META_AI_API_KEY=name:META_AI_API_KEYFIREWORKS_API_KEY=name:FIREWORKS_API_KEY…
```

Launch used to send that blob to the vault and fail with `no secret matched
'name:META_AI_API_KEYFIREWORKS_API_KEY=name:…'`.

**What to do.** `va refresh` now splits those mappings onto their own lines
(even when every secret already appears as a substring, so a second refresh
is not a no-op). `va doctor` and `va secrets validate --offline` fail closed
on the glued shape and print the recovered lines.

A host still running the 0.3.0 bash binary will re-glue on the next merge
refresh. `va update` (or a reinstall) is the way off that writer.

# Migration: `va update` replaces the installed binary (unreleased)

`va update` downloads a GitHub release asset for this OS/arch and overwrites
the running launcher (`current_exe`, usually `/usr/local/bin/vaulted-agent`).
Default target is `VAULTED_AGENT_VERSION`, else the latest GitHub release.
`va update v0.4.21` pins. `--check` and `--dry-run` write nothing.

This is not `install.sh`. Harnesses, manifests, and token files stay put. If
the dest is not writable, it retries with `sudo install`. `va` and
`*-conductor` links keep working because they point at the same binary.

A host that does not yet have this command still bootstraps with
`curl -fsSL https://vaultedagent.com/install.sh | bash`.

# Migration: `secrets validate` names the manifest on every line (unreleased)

`va secrets validate` with no argument now prints the manifest alongside the
harness, and checks every `extra_manifest` recorded in `defaults.conf` as well
(issue #359, ADR-0006):

```
claude (/etc/vaulted-agent/manifests/full.env.tpl): ok (252 variable(s) resolved)
/srv/orchestration/env.tpl: ok (252 variable(s) resolved)
```

The old shape was `claude: ok (252 variable(s) resolved)`. **Anything parsing
that output needs updating**; exit status is unchanged in meaning (non-zero on
any reference that will not resolve).

**Nothing you have to do.** A machine that records no `extra_manifest` checks
exactly the same files as before. Adding one is a line in `defaults.conf`:

```conf
extra_manifest = /srv/orchestration/env.tpl
```

A recorded manifest that is missing, unparseable, or names an unknown backend
now fails the check rather than being skipped.

# Migration: `va bash` is a harness, not the retired Bash launcher (unreleased)

`va bash` is a named harness whose `command` is always `bash` (extra argv is
appended: `va bash ./script.sh`). It is not `va run` (any program) and not a
return of the pre-v0.4.0 Bash launcher or `*-orchestrator` wrappers — those
stay retired. Same scrub → resolve → exec path as `va claude`.

# Migration: refs lines record their source secret (unreleased)

`vaulted-agent setup` and `vaulted-agent refresh` now write the source UUID on
the lines they generate, as a trailing comment:

```
ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:ea6db86f-e103-4153-a71e-b4b100c30b65
```

This is a **Bitwarden refs-file format change** (issue #82, ADR-0004). It is what
lets `refresh` report a vault-side rename as a rename and repair the one line —
keeping the variable name, so a harness `alias =` reading it does not break.

**Nothing you have to do.** Existing lines are never backfilled and keep their
current behaviour exactly. The recording is stripped before the reference is
resolved, so an annotated line launches and validates the same as before.

**One-way, though.** A refs file containing an annotated line will not resolve
under a launcher older than this release: it reads `name:KEY # uuid:…` as the
whole reference and fails the launch closed. If you downgrade, either re-run
`refresh --replace` on the old binary or strip the ` # uuid:…` tails by hand.

Applies to `bitwarden` only. 1Password `op://` references carry their own
identity, and dotenv manifests hold secret *values*, where a `#` is material and
is left alone.

# Migration: kimi is not env-blind (retracts v0.4.16 / #69) (unreleased)

v0.4.16 classified kimi as env-blind and stopped vault wiring (#68 / #69).
End-to-end probes (issue #70) show kimi **does** read OpenAI-compatible
provider keys from `process.env` (print mode verified). Failures on Kimi Code
0.33+ come from an upstream auth-gate regression
([kimi-code#2745](https://github.com/MoonshotAI/kimi-code/issues/2745),
fix [PR #2746](https://github.com/MoonshotAI/kimi-code/pull/2746) — not yet
in a kimi release when this was written), not from a design that ignores the
environment.

**This release:**

- Removes `kimi` from `etc/env-blind-agents` (registry may stay empty).
- Install wires day-one kimi harnesses to the vault refs file again.
- `va doctor` no longer warns that inject/alias are useless for kimi.
- Restores harness `alias = OPENAI_API_KEY = …` guidance for type-based env
  selection (#66); Fireworks is the motivating example, not a second probe.
- Adds harness `env = NAME = value` for non-secret child vars. Shipped
  `kimi.conf` sets `env = KIMI_CODE_LEGACY_FLAG = 1` so vault inject works on
  the broken gate; **delete that line** once your kimi includes #2746.

**If you already applied v0.4.16:** re-run setup / wire so kimi is not stuck on
`empty.env`, or set `backend` + `manifest` on `kimi.conf` by hand.

File-render backends remain useful for tools that truly need secrets on disk
(`.aws/credentials`, `.npmrc`, …) but are **not** justified by the kimi case.
Follow-up: drop the shipped LEGACY `env=` line when #2746 is in a kimi release
(track: issue #72).

# Migration: harness `alias` renames an injected secret (unreleased)

A harness could not hand an injected secret to the agent under a different
variable name. When the agent hardcodes `OPENAI_API_KEY` (or similar) for a
non-OpenAI provider, and a shared manifest already maps that name to another
key, the harness launched with the wrong credential and the agent failed at the
provider (issue #66).

```ini
# harnesses.d/kimi.conf
manifest = orchestrator-all.env.tpl
alias    = OPENAI_API_KEY = FIREWORKS_AI_API_KEY
command  = kimi --auto
```

Read it as the assignment it resembles: in this harness's child environment,
`OPENAI_API_KEY` takes a **copy** of the resolved value of `FIREWORKS_AI_API_KEY`.
Every other harness on the same manifest is unchanged.

Rules:

- Fail closed if the source is missing or empty (no silent leave-wrong-key).
- Source must be an **injected** secret from the manifest, not parent env
  (`keep` already covers passthrough).
- Manager-token names are refused as source and target.
- A target that also appears in the manifest is overwritten for this harness.

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
