# Domain model — vaulted-agent-launcher

Single-context glossary for agents and architecture work. Prefer these terms over synonyms.

## Core concepts

| Term | Meaning |
|------|---------|
| **Launcher** | The `vaulted-agent` / `va` binary. Resolves secrets, scrubs the environment, and execs an agent. Not a long-running daemon. |
| **Harness** | A named launch profile (`harnesses.d/<name>.conf`): backend, manifest, command, optional workdir/bin/labels/keep. |
| **Manifest** | The file a harness points at: either **refs** (references only) or dotenv-style secret material (plainfile/sops decrypt). |
| **Backend** | Where secret values come from: `bitwarden`, `onepassword`, `pass`, `sops`, `plainfile`. Typed in the runtime; unknown names fail closed. |
| **Refs file** | Bitwarden-oriented manifest of `VAR=reference` lines (uuid / name: / project:) — **no secret values** on disk. |
| **Manager token** | Vault *manager* credential (`BWS_ACCESS_TOKEN`, `OP_SERVICE_ACCOUNT_TOKEN`). Used only to resolve secrets; must never appear in the child agent env. |
| **Secret value** | A resolved secret destined for the child environment. Redacted on Display/Debug. |
| **Auth mode** | How the manager token is obtained: `file` (token file on disk) or `prompt` (TTY each launch). |
| **Service user** | Optional dedicated OS account; launcher re-execs via `sudo -u` so the agent runs as that user. |
| **Conductor link** | Symlink `*-conductor` → fixed harness name; `-H` must not override (narrow entitlement). |
| **Launch path** | scrub → resolve → drop manager token → exec (story #44: keep small and auditable). |
| **Launch plan** | Pure result of the launch path before handoff: program, agent argv, workdir, child env. Tests assert the plan without process exec. |
| **Child environment** | Explicit allowlist construction (`build_child_env`): passthrough + keep + injected secrets only. |
| **Service-user re-exec** | When `service_user` differs from the caller, plan a sudo hop (original argv preserved for sudoers); pure decision, thin adapter. |
| **Caller cwd** | Invocation directory preserved across sudo re-exec (`VAULTED_AGENT_CALLER_CWD`) for `workdir = caller`. |

## Operator surface (acceptance seam)

The **CLI** is the primary and sole public acceptance seam (story #50). Library modules support the binary; they are not a second product API.

Management verbs: `setup`, `refresh`, `secrets`, `doctor`, `auth-mode`, `run`, `pick`, `uninstall`, `version`.

## Invariants (do not break casually)

1. Manager tokens never reach the child environment.
2. No secret material on the agent argv.
3. Sudo re-exec replays **original** argv so sudoers matches what the operator typed.
4. Fail closed on unknown backend, bad var names, and placeholder refs (misconfiguration).
5. `secrets validate` is the pre-flight gate before privileged/paid launches — must not fail open.

## Related docs

- Issue #1 — user stories and implementation decisions
- `MIGRATION.md` — Bash → Rust (v0.4.0) contract and intentional breaks
- `docs/adr/` — architecture decision records (create when a choice is load-bearing)
