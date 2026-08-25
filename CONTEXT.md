# Domain model — vaulted-agent-launcher

Single-context glossary for agents and architecture work. Prefer these terms over synonyms.

## Core concepts

| Term | Meaning |
|------|---------|
| **Launcher** | The `vaulted-agent` / `va` binary. Resolves secrets, scrubs the environment, and execs an agent. Not a long-running daemon. |
| **Harness** | A named launch profile (`harnesses.d/<name>.conf`): backend, manifest, command, optional workdir/bin/labels/keep/**alias**. |
| **Alias** | Per-harness child-env rename after inject: `alias = TARGET = SOURCE` copies the resolved source secret onto TARGET (fail closed if source missing). |
| **Env-blind agent** | Tool listed in `etc/env-blind-agents` that does not consume vault-injected process-env credentials for the usual provider path. Doctor warns; install skips vault rewire. (kimi is **not** in this list — issue #70.) |
| **Manifest** | The file a harness points at: either **refs** (references only) or dotenv-style secret material (plainfile/sops decrypt). |
| **Backend** | Where secret values come from: `bitwarden`, `onepassword`, `pass`, `sops`, `plainfile`. Typed in the runtime; unknown names fail closed. |
| **Refs file** | Bitwarden-oriented manifest of `VAR=reference` lines (uuid / name: / project:) — **no secret values** on disk. |
| **Manager token** | Vault *manager* credential (`BWS_ACCESS_TOKEN`, `OP_SERVICE_ACCOUNT_TOKEN`). Used only to resolve secrets; must never appear in the child agent env. |
| **Secret value** | A resolved secret destined for the child environment. Redacted on Display/Debug. |
| **Auth mode** | How the manager token is obtained: `file` (token file on disk) or `prompt` (TTY each launch). |
| **Token capture** | `setup`-only path that obtains a manager token (TTY paste, or piped stdin under `--set-token`), verifies it against the backend, then writes the token file. Distinct from load: never runs on the launch path, and never fires for an unreadable existing token file (invariant 6). |
| **Service user** | Optional dedicated OS account; launcher re-execs via `sudo -u` so the agent runs as that user. |
| **Conductor link** | Symlink `*-conductor` → fixed harness name; `-H` must not override (narrow entitlement). |
| **Launch path** | scrub → resolve → drop manager token → exec (story #44: keep small and auditable). |
| **Launch plan** | Pure result of the launch path before handoff: program, agent argv, workdir, child env. Tests assert the plan without process exec. |
| **Child environment** | Explicit allowlist construction (`build_child_env`): passthrough + keep + injected secrets (after aliases), then harness `env=` non-secret pairs and optional `bin`→PATH. |
| **Service-user re-exec** | When `service_user` differs from the caller, plan a sudo hop (original argv preserved for sudoers); pure decision, thin adapter. |
| **Caller cwd** | Invocation directory preserved across sudo re-exec (`VAULTED_AGENT_CALLER_CWD`) for `workdir = caller`. |
| **Manifest override** | Launcher flag `-m` / `--manifest` before the harness name: this launch uses another refs file (replace, no merge). Refused under conductor links. |
| **Default section label** | 1Password’s unnamed custom-field section (`add more`); must not appear in generated env **names** (still may appear inside `op://` for inject). |

## Operator surface (acceptance seam)

The **CLI** is the primary and sole public acceptance seam (story #50). Library modules support the binary; they are not a second product API.

Management verbs: `setup`, `refresh`, `secrets`, `doctor`, `auth-mode`, `run`, `pick`, `uninstall`, `version`.

Agent-facing ops contract (commands, recipes, failure modes): **`AGENTS.md`**.

## Invariants (do not break casually)

1. Manager tokens never reach the child environment.
2. No secret material on the agent argv.
3. Sudo re-exec replays **original** argv so sudoers matches what the operator typed.
4. Fail closed on unknown backend, bad var names, and placeholder refs (misconfiguration).
5. `secrets validate` is the pre-flight gate before privileged/paid launches — must not fail open.
6. Unreadable manager-token files are not reported as missing and do not fall through to an interactive SA-token paste.
7. Conductor invocation must not honor `-H` or `-m` (fixed entitlement).

## Related docs

- `AGENTS.md` — agent / operator contract (prefer for automation)
- `MIGRATION.md` — Bash → Rust and later behavior breaks
- `docs/adr/` — architecture decision records (create when a choice is load-bearing)
- Product page: https://vaultedagent.com/ · agent copy: https://vaultedagent.com/AGENTS.md
