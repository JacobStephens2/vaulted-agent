# Domain model — vaulted-agent-launcher

Single-context glossary for agents and architecture work. Prefer these terms over synonyms.

## Core concepts

| Term | Meaning |
|------|---------|
| **Launcher** | The `vaulted-agent` / `va` binary. Resolves secrets, scrubs the environment, and execs an agent. Not a long-running daemon. |
| **Harness** | A named launch profile (`harnesses.d/<name>.conf`): backend, manifest, command, optional workdir/bin/labels/keep/**alias**. |
| **Bash harness** | A Harness whose `command` is `bash`. Extra argv is appended (`va bash ./script.sh`). Not `va run` (any program) and not a retired `*-orchestrator` shell wrapper. |
| **Alias** | Per-harness child-env rename after inject: `alias = TARGET = SOURCE` copies the resolved source secret onto TARGET (fail closed if source missing). |
| **Env-blind agent** | Tool listed in `etc/env-blind-agents` that does not consume vault-injected process-env credentials for the usual provider path. Doctor warns; install skips vault rewire. (kimi is **not** in this list — issue #70.) |
| **Conf file** | The `key = value` text format of `defaults.conf` and Harness confs: one line rule (blank and `#` lines are not entries; the key is the text before the first `=`), read and edited through one module (`src/conf_file.rs`). An edit changes only the key it names and replaces the file atomically. Distinct from a Manifest, which is dotenv and read through Manifest entry. |
| **Manifest** | The file a harness points at: either **refs** (references only) or dotenv-style secret material (plainfile/sops decrypt). |
| **Manifest entry** | One `KEY=value` mapping as the shared Manifest parser reads it. It may span several physical lines (a double-quoted value, or a bare PEM / JSON key continued below its first line). Quotes are removed from its value. It is the unit that validate, resolve, `refresh` and `edit-manifest` all agree on (`src/manifest_entry.rs`). |
| **Extra manifest** | A Manifest something on the machine reads that no Harness launches from (systemd units, deploy scripts). Recorded in `defaults.conf` as `extra_manifest = <path>[ = <backend>]`; validated with the harness manifests and launchable by nothing (ADR-0006). |
| **Inventory** | Every Harness and Extra manifest a machine's config declares, each with its effective Backend and resolved Manifest path, or the error that stopped it loading. The one walk that `secrets validate`, `secrets which`, `refresh` (and `setup bitwarden`, through refresh's Refs-file default), `edit-manifest`, `pick` and `update` share; launch reads a single Harness and does not use it, and the doctor keeps its own Harness loop for now (#74) (`src/inventory.rs`). |
| **Backend** | Where secret values come from: `bitwarden`, `onepassword`, `pass`, `sops`, `plainfile`. Typed in the runtime; unknown names fail closed. |
| **Refs file** | Manifest of `VAR=reference` lines — Bitwarden (uuid / name: / project:) or 1Password (`op://vault/item[/section]/field`). **No secret values** on disk. |
| **Dangling ref** | A refs-file mapping whose reference matches no secret the manager token can see — on 1Password, a missing item or a missing field: the **1Password listing** lookup's absent. Fails the launch closed; `secrets validate` detects one, `refresh` prunes it. Distinct from a malformed ref, which is a shape problem `validate` owns. |
| **Bitwarden listing** | The secrets one manager token can see, as one `bws secret list` returns them (id, key, project). The world the launch and `refresh` both judge a Bitwarden reference against, through one lookup: found, absent, ambiguous, or not a reference (`src/bitwarden.rs`). |
| **1Password listing** | The items one manager token can see, as one `op item list` returns them, plus the fields of the items this `refresh` run expanded. The world `refresh` judges an `op://` reference against, through one lookup: found, absent, unexpanded, or not a reference (`src/onepassword.rs`). |
| **Ambiguous ref** | A Bitwarden mapping whose reference matches more than one listed secret (a `name:` key in two projects, or a key twice in one project). Fatal to the launch, never pruned (the secrets exist) and never repaired (which one is meant is the operator's choice). Fixed by qualifying it with `project:` or `uuid:`. |
| **Unchecked ref** | A 1Password mapping into an item this `refresh` run never expanded (not selected, or a read that failed): the **1Password listing** lookup's unexpanded. Nothing was learned about it: reported, never pruned (ADR-0005). |
| **Prune** | `refresh` removing dangling refs from a manifest. Only ever removes what does not resolve — never rewrites or reorders a working mapping — and only under `--prune` or an interactive confirmation. Since ADR-0004 the `--prune` **flag** also gates repairing a renamed ref; prune itself still means removal alone. A recorded `# exclude:` pattern does **not** make a resolving mapping prunable (ADR-0005). |
| **Source recording** | Trailing `# uuid:UUID` on a refs line, naming the secret the line was generated from. Written by `setup` and `refresh` on the lines they generate. Metadata: stripped before the reference is resolved, so it never disambiguates one. Bitwarden only; never backfilled onto lines already on disk (ADR-0004). |
| **Renamed ref** | A refs mapping whose reference matches nothing but whose source recording names a secret still visible under a different key. Repaired in place — reference rewritten, **variable name kept** — not pruned. Distinct from a dangling ref, where the secret is genuinely gone. |
| **Refresh report** | What one `refresh` run found in the lines already in a Refs file: every line that does not simply resolve, each listed once: under its fate (renamed, dangling, ambiguous, unchecked, or unjudged — a shape refresh cannot judge), or, if it resolves but matches a recorded `# exclude:`, as mapped-but-excluded. Holds the alias warnings and the edits the run would make (repairs before removals). Built before anything is decided and printed on every run, whether or not the file changes; the `--prune` / confirmation gate then decides about the edits (`src/refresh.rs`). |
| **Manager token** | Vault *manager* credential (`BWS_ACCESS_TOKEN`, `OP_SERVICE_ACCOUNT_TOKEN`). Used only to resolve secrets; must never appear in the child agent env. |
| **Secret value** | A resolved secret destined for the child environment. Redacted on Display/Debug. |
| **Agent-owned credential** | Authentication state created, stored, and consumed by the launched agent itself. Outside launcher manifest resolution and rotation; distinct from a Manager token or an injected Secret value. |
| **Auth mode** | How the manager token is obtained: `file` (token file on disk) or `prompt` (TTY each launch). One input to the Token source, which settles token loading for each invocation. |
| **Token source** | How one invocation obtains a Manager token (manager-token env var, else prompt when forced or auth mode is `prompt`, else the token file, else a one-shot TTY prompt), settled once from the environment, the `-p` flag and the configured Auth mode. Distinct from Token capture, which is `setup`-only and writes the file. |
| **Token capture** | `setup`-only path that obtains a manager token (TTY paste, or piped stdin under `--set-token`), verifies it against the backend, then writes the token file. Distinct from load: never runs on the launch path, and never fires for an unreadable existing token file (invariant 6). |
| **Operator identity** | The human on whose behalf a Harness is launched; determines personal agent state and source-control attribution. Distinct from the Service user that executes the process. |
| **Service user** | Optional dedicated OS account; launcher re-execs via `sudo -u` so the agent runs as that user. |
| **Conductor link** | Symlink `*-conductor` → fixed harness name; `-H` must not override (narrow entitlement). |
| **Launch path** | scrub → resolve (loading the manager token through the Token source) → drop manager token → exec (story #44: keep small and auditable). |
| **Launch plan** | Pure result of the launch path before handoff: program, agent argv, workdir, child env. Tests assert the plan without process exec. |
| **Child environment** | Explicit allowlist construction (`build_child_env`): passthrough + keep + injected secrets (after aliases), then harness `env=` non-secret pairs and optional `bin`→PATH. |
| **Invocation route** | What one command line asks the Launcher to do (a Harness launch, a Conductor link launch, or a management verb) and which Service-user re-exec it takes, decided once and purely before anything runs. The reserved verbs are one typed set; a Harness conf of the same name shadows a verb. The binary's entry point is its only adapter (`src/route.rs`). |
| **Service-user re-exec** | When `service_user` differs from the caller, plan a sudo hop (original argv preserved for sudoers); pure decision, thin adapter. |
| **Caller cwd** | Invocation directory preserved across sudo re-exec (`VAULTED_AGENT_CALLER_CWD`) for `workdir = caller`. |
| **Workdir** | Where a Harness's agent starts: the Caller cwd when `workdir` is `caller`, empty or unset, otherwise a fixed path with a leading `$HOME` / `${HOME}` expanded. The launch preflight and `doctor` judge whether the launching account can enter it through one module, which also owns the traverse-only `setfacl` remedy that `setup` prints (`src/workdir.rs`). |
| **Manifest override** | Launcher flag `-m` / `--manifest` before the harness name: this launch uses another refs file (replace, no merge). Refused under conductor links. |
| **Default section label** | 1Password’s unnamed custom-field section (`add more`); must not appear in generated env **names** (still may appear inside `op://` for inject). |

## Operator surface (acceptance seam)

The **CLI** is the primary and sole public acceptance seam (story #50). Library modules support the binary; they are not a second product API.

Management verbs: `setup`, `refresh`, `secrets`, `doctor`, `auth-mode`, `run`, `edit-manifest`, `pick`, `uninstall`, `update`, `version`, `help`.

Agent-facing ops contract (commands, recipes, failure modes): **`AGENTS.md`**.

## Invariants (do not break casually)

1. Manager tokens never reach the child environment.
2. No secret material on the agent argv.
3. Sudo re-exec replays **original** argv so sudoers matches what the operator typed. The one exception is `pick`: it hops after the menu and replays as though the operator had typed the chosen Harness (launcher flags as typed, then the Harness name, then the rest), so a sudoers grant for `pick` never authorizes more than the Harness picked.
4. Fail closed on unknown backend, bad var names, and placeholder refs (misconfiguration).
5. `secrets validate` is the pre-flight gate before privileged/paid launches — must not fail open. It covers every manifest the machine reads, harness or **extra** (ADR-0006).
6. Unreadable manager-token files are not reported as missing and do not fall through to an interactive SA-token paste.
7. Conductor invocation must not honor `-H` or `-m` (fixed entitlement).

## Related docs

- `AGENTS.md` — agent / operator contract (prefer for automation)
- `MIGRATION.md` — Bash → Rust and later behavior breaks
- `docs/adr/` — architecture decision records (create when a choice is load-bearing)
- Product page: https://vaultedagent.com/ · agent copy: https://vaultedagent.com/AGENTS.md
