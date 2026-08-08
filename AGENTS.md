# vaulted-agent for agents

You are an autonomous coding agent on a host that may use **vaulted-agent**
(`va`) to launch Claude Code, Codex, Grok, or Kimi with vault-resolved secrets
**in the child process environment** - not via `.env` files on disk.

Read this file for the operator contract. Prefer it over skimming the full README
when you need commands, paths, and failure modes. Full reference:
[README.md](README.md). Product page: https://vaultedagent.com/  
Also hosted: https://vaultedagent.com/AGENTS.md

Glossary for domain terms (harness, manifest, backend, …): [CONTEXT.md](CONTEXT.md).

Current release pin (product install): **v0.4.15**

```bash
curl -fsSL https://vaultedagent.com/install.sh | bash
# pin:
VAULTED_AGENT_VERSION=v0.4.15 curl -fsSL https://vaultedagent.com/install.sh | bash
vaulted-agent version   # expect 0.4.15 (git stamp may appear in parentheses)
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
| **Alias** | `alias = TARGET = SOURCE` in a harness conf: copy resolved SOURCE onto TARGET in that harness's child env only |
| **Manifest / refs file** | Mapping file under `manifests/` - references only for vault backends |
| **Manager token** | Vault SA token (`op.env` / `bws.env` or prompt) - used only to resolve, then dropped |
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
| Pre-flight: refs resolve in vault | `va secrets validate` (live; needs manager token) |
| Pre-flight: shape only | `va secrets validate --offline` |
| Launch harness | `va claude` / `va codex` / `va grok` / `va kimi` |
| **This launch only: other manifest** | `va -m readonly.env.tpl claude` |
| Interactive pick + optional -m | `va -m narrow.env.tpl pick` |
| One-shot command | `va run -m REFS --backend bitwarden -- cmd…` |
| Map new vault secrets into refs | `va refresh` / `va refresh --backend onepassword` |
| Skip fields by name pattern (1P) | `va refresh --exclude '*_USERNAME'` |
| Edit a refs file (with checks) | `va edit-manifest` / `va edit-manifest name.env.tpl` |
| Auth mode | `va auth-mode` / `va auth-mode prompt` / `va auth-mode file` |
| Interactive install-time config | `va setup` |
| Uninstall | `sudo va uninstall` |

Launcher flags **before** the harness name: `-p` / `--prompt-auth`,
`-m` / `--manifest`, `-H` / `--harness`. After the harness name, flags go to the
agent (`va claude -p "…"` is agent `-p`, not launcher prompt-auth).

### Prompt auth

| Path | How to force prompt this launch |
|------|----------------------------------|
| `va …` | `va -p grok` or `va --prompt-auth claude` |
| `*-conductor` | `VAULTED_AGENT_PROMPT_AUTH=1 claude-conductor …` (`-p` is the agent’s) |

### Kimi

Shipped / auto harness defaults to `kimi --auto` (unattended). Edit the harness
to drop `--auto` if you want manual approval.

If Kimi is configured as an OpenAI-compatible provider (e.g. Fireworks) but the
shared manifest maps `OPENAI_API_KEY` to the real OpenAI key, rename for this
harness only:

```ini
# harnesses.d/kimi.conf
manifest = orchestrator-all.env.tpl
alias    = OPENAI_API_KEY = FIREWORKS_AI_API_KEY
command  = kimi --auto
```

Source must already be in the resolved manifest. Missing source fails the launch
(no silent wrong key).

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
| `secrets validate` needs token / fails without | Live gate by design; use `--offline` only for shape |
| Legacy `*_ADD_MORE_*` names | Old 1Password refresh naming; still works; next refresh renames - see MIGRATION.md |
| `run is disabled while service_user=…` | Expected; set `allow_run = yes` only if you intend that grant |

## Launch path (invariants)

```
optional sudo -u <service_user>
→ workdir (caller cwd or absolute)
→ scrub environment (allowlist)
→ load manager token (file / prompt / env)
→ resolve manifest refs into process env
→ drop manager token
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

## Developing this repo (contributors / coding agents)

- Domain vocabulary: [CONTEXT.md](CONTEXT.md)
- How to use domain docs: [docs/agents/domain.md](docs/agents/domain.md)
- Issues: `gh` against `JacobStephens2/vaulted-agent-launcher` - [docs/agents/issue-tracker.md](docs/agents/issue-tracker.md)
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
