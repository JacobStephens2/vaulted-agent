# vaulted-agent for agents

You are an autonomous coding agent on a host that may use **vaulted-agent**
(`va`) to launch Claude Code, Codex, Grok, Kimi, or Antigravity - or a
secrets-injected `bash` - with vault-resolved secrets **in the child process
environment** - not via `.env` files on disk.

Read this file for the operator contract. Prefer it over skimming the full README
when you need commands, paths, and failure modes. Full reference:
[README.md](README.md). Product page: https://vaultedagent.com/  
Also hosted: https://vaultedagent.com/AGENTS.md

Glossary for domain terms (harness, manifest, backend, …): [CONTEXT.md](CONTEXT.md).

Current release pin (product install): **v0.4.21**

```bash
curl -fsSL https://vaultedagent.com/install.sh | bash
# pin:
VAULTED_AGENT_VERSION=v0.4.21 curl -fsSL https://vaultedagent.com/install.sh | bash
vaulted-agent version   # expect 0.4.21 (git stamp may appear in parentheses)
```

## What you must not do

1. **Do not put secret values in manifests or harness confs.** Refs only:
   `VAR=name:…`, `VAR=op://…`, etc.
2. **Do not export `BWS_ACCESS_TOKEN` / `OP_SERVICE_ACCOUNT_TOKEN` into the
   agent’s environment on purpose.** The launcher drops the manager token before
   `exec`. If you re-export it after launch, you have widened blast radius.
3. **Do not put secrets on the agent argv** (`va claude --api-key …`).
4. **Do not “fix” a bad launch by pasting a vault service-account token into a
   random shell** when the real issue is EACCES on `op.env` / missing
   `service_user`. Read the error; run `va doctor`.
5. **Do not use `-m` under a `*-conductor` symlink.** It is refused on purpose
   (fixed entitlement = one harness → one credential set).

## Ubiquitous language (short)

| Term | Meaning |
|------|---------|
| **Harness** | Named profile in `harnesses.d/<name>.conf` (command, manifest, backend, workdir, optional `alias` / `keep`, …) |
| **Bash harness** | `va bash` - named harness whose `command` is `bash`; extra argv is appended (`va bash ./script.sh`). Not `va run`. |
| **Alias** | `alias = TARGET = SOURCE` in a harness conf: copy resolved SOURCE onto TARGET in that harness's child env only |
| **Manifest / refs file** | Mapping file under `manifests/` - references only for vault backends |
| **Manager token** | Vault SA token (`op.env` / `bws.env` or prompt) - used only to resolve, then dropped |
| **Token capture** | `setup`-only: obtain a manager token (TTY paste, or piped stdin under `--set-token`), verify it live, then write the token file. Never on the launch path |
| **Service user** | Optional OS account; launcher re-execs via `sudo -u` so the agent runs as that user |
| **Conductor link** | `*-conductor` → fixed harness; no `-H` / `-m` override |

## Machine layout (defaults)

| Path | Role |
|------|------|
| `/etc/vaulted-agent/defaults.conf` | `auth_mode`, `service_user`, `default_backend`, `allow_run` |
| `/etc/vaulted-agent/harnesses.d/*.conf` | Harnesses |
| `/etc/vaulted-agent/manifests/*` | Refs / manifests |
| `/etc/vaulted-agent/op.env` | `OP_SERVICE_ACCOUNT_TOKEN=…` when `auth_mode=file` (often `0640` root:service_user) |
| `/etc/vaulted-agent/bws.env` | `BWS_ACCESS_TOKEN=…` when `auth_mode=file` |

Override root: `VAULTED_AGENT_CONFIG_DIR` (does **not** cross the privilege hop;
elevated launches always read the machine config dir).

## Command surface

| Goal | Command |
|------|---------|
| List harnesses | `va` |
| Health (as launch account) | `va doctor` (syntax / config; offline by design) |
| Pre-flight: refs resolve in vault | `va secrets validate` (live; needs manager token; covers every harness manifest **and** every `extra_manifest`) |
| Pre-flight: shape only | `va secrets validate --offline` |
| Launch harness | `va claude` / `va codex` / `va grok` / `va kimi` / `va agy` / `va bash` |
| **This launch only: other manifest** | `va -m readonly.env.tpl claude` |
| Interactive pick + optional -m | `va -m narrow.env.tpl pick` |
| One-shot command | `va run -m REFS --backend bitwarden -- cmd…` |
| Map new vault secrets into refs | `va refresh` / `va refresh --backend onepassword` |
| Skip fields by name pattern (1P) | `va refresh --exclude '*_USERNAME'` |
| Remove dangling refs / repair renamed refs | `va refresh --prune` (repair is bitwarden only) |
| Edit a refs file (with checks) | `va edit-manifest` / `va edit-manifest name.env.tpl` |
| Auth mode | `va auth-mode` / `va auth-mode prompt` / `va auth-mode file` |
| Interactive install-time config | `va setup` |
| Store / rotate the manager token | `printf %s "$TOKEN" \| sudo va setup bitwarden --set-token` |
| Replace the installed launcher binary | `va update` (latest GitHub release) / `va update v0.4.21` |
| Uninstall | `sudo va uninstall` |

Launcher flags **before** the harness name: `-p` / `--prompt-auth`,
`-m` / `--manifest`, `-H` / `--harness`. After the harness name, flags go to the
agent (`va claude -p "…"` is agent `-p`, not launcher prompt-auth).

`va bash` is a harness whose command is always bash; extra argv is appended
(`va bash ./script.sh`). It is not `va run` (any program) and not a retired
`*-orchestrator` wrapper.

`va update` replaces the installed launcher binary from a GitHub release asset
(same stems as `install-remote.sh`). It does not re-run `install.sh` and does
not change harnesses or manifests. `--check` / `--dry-run` write nothing. If
the dest is not writable: `sudo va update`.

### Prompt auth

| Path | How to force prompt this launch |
|------|----------------------------------|
| `va …` | `va -p grok` or `va --prompt-auth claude` |
| `*-conductor` | `VAULTED_AGENT_PROMPT_AUTH=1 claude-conductor …` (`-p` is the agent’s) |

### Antigravity

The shipped / auto Harness runs bare `agy` with `workdir = caller`, preserving
AGY's permission settings and cwd-scoped conversations. Arguments pass through
unchanged: `va agy --continue` (or `-c`) continues the latest conversation for
the cwd, and `va agy --conversation <uuid>` selects one explicitly.

AGY owns its OAuth login and settings under the launch account's home. When a
Harness uses `service_user`, it does not inherit the invoking user's AGY login.
Vaulted-agent injects the selected Manifest but does not configure AGY's
authentication. AGY reads an injected `GEMINI_API_KEY` only when its settings
select `modelProvider = gemini`. Authentication details:
https://antigravity.google/docs/cli/install/

### Kimi

Shipped / auto harness defaults to `kimi --auto` (unattended). Day-one is
`plainfile` + `empty.env`; vault setup rewires kimi like claude/codex/grok.

**Credentials (issue #70).** Kimi **does** read OpenAI-compatible provider keys
from the process environment. Selection is by provider **type** (`openai` →
`OPENAI_API_KEY`), not provider id. Vault inject works (verified in print mode
with a custom `type = "openai"` provider).

If a shared manifest maps `OPENAI_API_KEY` to a different vault item than this
harness needs (e.g. real OpenAI vs Fireworks), rename for this harness only
(#66). Provider **type** still drives the env var name kimi reads:

For a custom openai-compatible provider (Fireworks, Together, local vLLM), the
key goes in `~/.kimi-code/config.toml`, literally:

```toml
[providers.fireworks]
type    = "openai"
api_key = "fw_…"          # read from here, never from the environment
```

**Upstream gate bug (not env-blind).** Kimi Code 0.33+ default print mode has an
auth-gate regression
([kimi-code#2745](https://github.com/MoonshotAI/kimi-code/issues/2745);
fix [#2746](https://github.com/MoonshotAI/kimi-code/pull/2746), not yet in a
kimi release when this was written). v0.4.16 wrongly called that “env-blind”
(#68/#69); **retracted** in v0.4.17. Shipped `kimi.conf` carries:

```ini
env = KIMI_CODE_LEGACY_FLAG = 1
```

Delete that line once your kimi includes #2746 (0.32 never needed it). Opt-out
is deleting the harness line — not a keep/export dance.

`KIMI_API_KEY` is only for kimi’s **built-in** provider. Literal `api_key` in
`~/.kimi-code/config.toml` still works if you prefer not to inject.

## Recipes agents actually need

### Add one credential to a harness

1. Create the secret in the vault (Bitwarden SM or 1Password), readable by the
   machine / service account.
2. Map it into a refs file under `/etc/vaulted-agent/manifests/`:
   - Prefer: `va refresh` (interactive merge of unmapped secrets).
     If the file is root-owned, `refresh` fails *before* vault work and tells you
     to re-run as `sudo /usr/local/bin/vaulted-agent refresh`.
   - Or edit with checks: `va edit-manifest` (or `va edit-manifest name.env.tpl`).
     Uses `sudoedit` when needed so the editor is not root.
   - Or append one line by hand:
     - Bitwarden: `OPENAI_API_KEY=name:openai-api-key`
     - 1Password: `OPENAI_API_KEY=op://Vault/item/field`
3. Ensure the harness conf has `manifest = that-file` (relative to `manifests/`).

**Never put illustrative `op://…` in comments.** `op inject` resolves comments too;
one bad reference aborts the whole manifest. `va doctor` and `edit-manifest` both
flag that.

**Rotate value in vault** → no command; next launch fetches live.  
**Add a new mapping** → `va refresh` or `va edit-manifest`.  
**Renamed a secret in the vault** → `va refresh --prune`. If the mapping carries a
`# uuid:…` source recording, `refresh` reports `renamed` and repairs that one line,
keeping the variable name — so an `alias =` reading it keeps working. Without a
recording (any line written before this existed) the old mapping is a dangling ref:
reported every run, removed under `--prune` or an interactive yes. Either way the
change happens only when asked, changed lines print verbatim — there is no backup
file — and lines that still resolve, comments, and ordering are untouched.  
**Renamed or deleted a 1Password item / field** → `va refresh --backend onepassword
--all --prune`. There is no source recording on an `op://` line, so a renamed item
is indistinguishable from a deleted one: both are dangling refs and both are
removed, never repaired. `refresh` judges only what the run fetched — items come
from one `op item list`, fields only for the items it expanded — so use `--all` for
full coverage; mappings into items it did not open are listed as unchecked and left
alone. A mapping that still resolves but matches a recorded `# exclude:` is listed
and **kept**: exclusion governs what refresh *adds* (ADR-0005). Delete it yourself
with `va edit-manifest` if you meant it to go.  
**1Password name cleanup / exclude** → see MIGRATION.md; `va refresh --exclude '…'`.

### Launch with a particular manifest (one session)

```bash
# Flag BEFORE harness name. Replaces configured manifest (no merge).
va -m readonly.env.tpl claude
va --manifest=/etc/vaulted-agent/manifests/narrow.env.tpl claude --resume <id>
va -m readonly.env.tpl pick
```

- Relative paths resolve under `/etc/vaulted-agent/manifests/` unless absolute.
- Missing file → error **before** the agent starts.
- stderr announces the override (search scrollback for `launching with manifest`).
- **Refused** under `*-conductor`. Use direct `va` for `-m`.
- With `service_user`, sudoers must match the line as typed (flags before harness
  name). Prefer conductor links for delegated grants, or extend sudoers.

### Diagnose before changing config

```bash
va doctor
va secrets validate          # live vault resolve; fail-closed if no token
va secrets validate --offline
```

Interpret carefully:

| Symptom | Meaning |
|---------|---------|
| `op.env: missing` | File really absent (or not a file) |
| `op.env: unreadable (… as user)` | Present but EACCES - often need `service_user` or group/ACL, **not** a paste of the vault SA token |
| `cannot enter /home/…` | `workdir=caller` + service account cannot traverse (often `setfacl -m u:<svc>:x /home/<op>`) |
| `op cannot parse N reference(s)` | Only **malformed `op://`** lines - plain literals (region, URL) are fine |
| `could not resolve` / item named on validate or launch | Well-formed ref, vault item missing or renamed - fix the refs file or vault. Launch lists the variables implicated and suggests `secrets validate` |
| `Dangling refs in <file>` on refresh | Mappings matching nothing the token can see - on 1Password, a missing item or field. Reported every run; exit stays 0. `--prune` removes them |
| `Refs this run did not check` on refresh | 1Password mappings into items this run never expanded (not selected, or a read that failed). Never pruned; `refresh --all --prune` checks every item |
| `Mapped but excluded in <file>` | 1Password mappings that resolve but match a recorded `# exclude:`. Kept on purpose (ADR-0005) - exclusion governs what refresh *adds*. Delete the line with `va edit-manifest` if you meant it to go |
| `Renamed secrets in <file>` on refresh | Mappings whose `# uuid:…` recording names a secret now under a different key. `--prune` rewrites the reference and keeps the variable name |
| `Refs refresh cannot judge (…)` | Shapes prune will not touch — an unreadable ref, a placeholder, a multi-line value. `secrets validate` owns those |
| `no secret matched name:X (VAR in <file>)` | A dangling ref hit at launch. `va refresh --prune` removes the mapping — or repairs it, if the line records a `# uuid:…` and the secret was only renamed |
| `secrets validate` needs token / fails without | Live gate by design; use `--offline` only for shape |
| A manifest on a validate line you did not expect | An `extra_manifest` from `defaults.conf`: a file the machine reads that no harness launches from (ADR-0006). Fix it where it lives, not in `harnesses.d` |
| Validate FAILs on a manifest that is not on disk | An `extra_manifest` path that no longer exists. Fail-closed on purpose: correct the path or drop the line |
| Legacy `*_ADD_MORE_*` names | Old 1Password refresh naming; still works; next refresh renames - see MIGRATION.md |
| `run is disabled while service_user=…` | Expected; set `allow_run = yes` only if you intend that grant |
| `no manager token yet and no terminal to paste one` | `setup` with `auth_mode=file` and nothing to capture; pipe it with `--set-token`, export the token, or `va auth-mode prompt` |
| `--set-token: … rejected by the vault` | Token verified live before write; nothing was stored. Check you pasted a Machine Account access token / service-account token |

## Launch path (invariants)

```
optional sudo -u <service_user>
→ workdir (caller cwd or absolute)
→ scrub environment (allowlist)
→ load manager token (file / prompt / env)
→ resolve manifest refs into process env
→ drop manager token
→ apply harness alias= (secret renames) and env= (non-secret child vars)
→ prepend bin= to PATH if set
→ exec agent …
```

Secrets live only in the **child** environment until the process exits. The agent
can still read its own env (and so can anything as that user). Manifests are
**blast-radius control**, not containment.

## Environment variables (launcher)

| Variable | Role |
|----------|------|
| `VAULTED_AGENT_CONFIG_DIR` | Config root (not forwarded across privilege hop) |
| `VAULTED_AGENT_CALLER_CWD` | Caller directory for `workdir = caller` (set by launcher) |
| `VAULTED_AGENT_PROMPT_AUTH=1` | Force prompt auth (needed under conductor) |
| `VAULTED_AGENT_AUTH_MODE` | `file` \| `prompt` override |
| `VAULTED_AGENT_SERVICE_USER` | Override service account |
| `VAULTED_AGENT_NO_REEXEC=1` | Skip sudo hop (debug / doctor as caller) |
| `VAULTED_AGENT_HANDOFF=spawn` | Tests only: spawn instead of exec |
| `BWS_ACCESS_TOKEN` / `OP_SERVICE_ACCOUNT_TOKEN` | Manager token if already in env (wins over file) |
| `KIMI_CODE_LEGACY_FLAG` | Optional; shipped on `kimi.conf` via `env=` until kimi-code#2746 is in a release (issue #70). Delete the harness line to drop it. |

## Developing this repo (contributors / coding agents)

- Domain vocabulary: [CONTEXT.md](CONTEXT.md)
- How to use domain docs: [docs/agents/domain.md](docs/agents/domain.md)
- Issues: `gh` against `JacobStephens2/vaulted-agent` - [docs/agents/issue-tracker.md](docs/agents/issue-tracker.md)
- Bash→Rust and later behavior breaks: [MIGRATION.md](MIGRATION.md)
- Installer hosting: [docs/hosting-the-installer.md](docs/hosting-the-installer.md)
- ADRs: [docs/adr/](docs/adr/)

```bash
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

## Done when (ops change)

- `vaulted-agent version` matches the intended pin
- `va doctor` is clean or only expected warnings (and summary counts match)
- Target harness launches; secrets present in the child (not in manager-token form)
- If you used `-m`, stderr shows the override and the agent did not inherit the wider default manifest

## Agent skills

### Issue tracker

GitHub Issues on `JacobStephens2/vaulted-agent`, via the `gh` CLI. See [docs/agents/issue-tracker.md](docs/agents/issue-tracker.md).

### Triage labels

The five canonical roles, each label string equal to its name. See [docs/agents/triage-labels.md](docs/agents/triage-labels.md).

### Domain docs

Single-context - `CONTEXT.md` + `docs/adr/` at the repo root. See [docs/agents/domain.md](docs/agents/domain.md).
