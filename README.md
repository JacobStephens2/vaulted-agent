# vaulted-agent-launcher

Give Claude Code, Codex, Grok, and Kimi Code real vault credentials
**in-process** - without leaving a pile of `.env` files on disk.

One launcher (`va`), one secrets backend (1Password, Bitwarden Secrets Manager,
pass, sops, …), **per-agent manifests** for blast radius. Optional **prompt
auth**: paste the vault token at each launch so even the manager token need not
live on disk. Same scrub/resolve/exec path for one-shot tools via `va run`.

**macOS and Linux.** Product page: [stephens.page/vaulted-agent](https://stephens.page/vaulted-agent) ·
Latest: [v0.3.0](https://github.com/JacobStephens2/vaulted-agent-launcher/releases/tag/v0.3.0)

## Contents

- [Usage](#usage) · [va run](#one-shot-commands-va-run) · [Doctor & secrets](#doctor--secrets-helpers)
- [Resume sessions](#resume-sessions)
- [Install](#install) · [Auth modes](#auth-mode-file-vs-prompt) · [Bitwarden](#bitwarden-secrets-manager)
- [How it works](#how-it-works) · [Honest claim](#the-honest-claim)
- [Configuration](#configuration) · [Backends](#backends)
- [Install details](#install-details) · [Uninstall](#uninstall)

## Usage

Day to day you name the harness as the first argument:

```bash
va claude
va codex
va grok
va kimi                  # Kimi Code CLI (binary: kimi) if on PATH
va pick
# full name also works: vaulted-agent claude
```

After a fresh install, agents found on your PATH get harnesses that start with
**no vault secrets** (`plainfile` + `empty.env`). Wire a vault when ready:

```bash
vaulted-agent setup                 # backend / token; Bitwarden can build a refs file
vaulted-agent refresh               # rebuild refs after adding secrets in Bitwarden SM
vaulted-agent auth-mode             # file (token on disk) vs prompt (paste each launch)
vaulted-agent doctor                # harnesses, backends, manifest syntax (no secret values)
vaulted-agent version               # e.g. vaulted-agent 0.3.0
va claude                           # with auth_mode=prompt: asks for vault token
va claude -p                        # force prompt this launch only
```

List harnesses: `vaulted-agent` or `va` (no args).  
Uninstall: `sudo vaulted-agent uninstall` (or `sudo va uninstall`).

### One-shot commands (`va run`)

Inject a manifest into **any** command without writing a harness file. Same
scrub → resolve → drop vault token → `exec` path as `va claude`. Useful for
scripts, deploys, and tools (e.g. [gpt-image](https://stephens.page/gpt-image)).

```bash
va run -m openai.env.refs --backend bitwarden -p -- \
  python gpt_image.py generate "a lighthouse in a storm, gouache" \
  --output out.png

va run -m readonly.env --backend plainfile -- env | sort
```

| flag | |
|---|---|
| `-m` / `--manifest` | refs file; relative paths are under `/etc/vaulted-agent/manifests/` |
| `--backend NAME` | `onepassword` · `bitwarden` · `sops` · `pass` · `plainfile` (default: install-time `DEFAULT_BACKEND`) |
| `--workdir DIR` | `caller` (default) · absolute path · `$HOME/…` |
| `-p` | prompt for vault token this launch only (never written) |
| `--` | end of launcher flags; rest is the command |

### Doctor & secrets helpers

```bash
va doctor                           # install health (no secret values)
va secrets list                     # bws secret list (same auth as launches)
va secrets get name:openai-api-key  # print one value
va secrets which                    # harness → variable names only
va secrets validate                 # every harness manifest
va secrets validate openai.env.refs bitwarden
va refresh openai.env.refs          # rebuild refs after adding secrets in SM
va refresh openai.env.refs --all    # non-interactive: include every secret
va secrets refresh                  # same as va refresh
```

**`va doctor`** reports version, service user, auth mode, whether
`bws` / `op` / `sops` / `pass` are on PATH, presence of `op.env` / `bws.env` /
`age.key`, and each harness’s backend / manifest / workdir plus **manifest
syntax** (placeholders fail). It does not call the vault for live values.

**`va secrets`** reuses the same token rules as launches (env → file → TTY
prompt). Prefer it over raw `bws` so auth matches.

**Updating secrets (Bitwarden SM).** The refs file never stores secret *values*
- only which env vars map to which SM secrets. Values are fetched live on every
launch (`bws secret get`). So:

| You did in Bitwarden SM | What to run |
|---|---|
| Rotated a secret’s **value** | Nothing - next `va claude` / `va run` gets the new value |
| **Added** a new secret you want in a harness | `va refresh openai.env.refs` (or edit the refs file by hand) |
| Removed a secret from a harness | Edit the refs file (or refresh and re-pick) |

Bitwarden refs accept `UUID`, `uuid:UUID`, `name:KEY`, or `project:PROJECT/KEY`.
Placeholder values (`REPLACE_…`, all-zero UUIDs, …) fail validation before
launch - in `doctor`, `secrets validate`, and every real launch.

### Resume sessions

Extra args after the harness go to the agent. Resume shape is normalized so
either form works under `va` (Claude/Grok speak `--resume`; Codex speaks the
`resume` subcommand):

```bash
va claude --resume b03ca221-798e-457b-8f64-f71713e7066c
va claude resume b03ca221-798e-457b-8f64-f71713e7066c
va codex resume 019fabc2-fe4f-7e00-a431-a6a44d94b559
va codex --resume 019fabc2-fe4f-7e00-a431-a6a44d94b559
va grok --resume 019fabde-7535-7cc2-ab09-7987edc08ff8
va grok resume 019fabde-7535-7cc2-ab09-7987edc08ff8
# Kimi Code (https://www.kimi.com/code/en) — sessions live under ~/.kimi-code/
va kimi --continue
va kimi --session abc123
va kimi resume abc123              # normalized to --resume (kimi alias for --session)
```

Harnesses use `workdir = caller` by default so the agent runs in the directory
you launched from (sessions are often cwd-scoped).

Other examples:

```bash
va claude "fix the flaky test in auth"
va codex --help
va claude -c                          # continue latest (claude native)
```

## Install

**macOS · Linux** (not Windows natively - use WSL).

```bash
curl -fsSL https://stephens.page/vaulted-agent/install.sh | bash
```

The remote installer pins a **tagged release** (default `v0.3.0`, not floating
`main`). Override with `VAULTED_AGENT_VERSION=…` or `latest`.

The installer:

1. Installs `vaulted-agent` and the `va` alias  
2. Detects `claude` / `codex` / `grok` / `kimi` (Kimi Code) on your PATH and writes live harnesses (`workdir = caller`)  
3. Optionally asks for a vault backend (1Password, **Bitwarden Secrets Manager**, pass, sops, …) when a TTY is present  
4. Asks for a default **auth mode**: `file` (token on disk) or `prompt` (paste each launch; nothing stored)  
5. Rewrites the launcher’s `DEFAULT_BACKEND` from `--backend` and prints the matching token path (`bws.env` vs `op.env`)  
6. For 1Password / Bitwarden / pass, prints the **refs manifest path** where you put `VAR=…` references  

Then, if detection found your agents:

```bash
va claude
va codex
va grok
va kimi
```

Or from a release tag / local clone:

```bash
git clone --branch v0.3.0 --depth 1 \
  https://github.com/JacobStephens2/vaulted-agent-launcher
cd vaulted-agent-launcher && sudo ./install.sh
# local tree with Bitwarden + prompt auth (no token file):
sudo ./install.sh --backend bitwarden --auth-mode prompt
```

| | |
|---|---|
| Pin a version | `VAULTED_AGENT_VERSION=v0.3.0 curl -fsSL …/install.sh \| bash` |
| Skip short alias `va` | `… \| bash -s -- --no-va` |
| Skip agent auto-detect | `… \| bash -s -- --no-auto-harness` |
| Non-interactive backend | `… \| bash -s -- --backend onepassword --op-token-file ./token` |
| Prompt each launch (no token file) | `… \| bash -s -- --backend bitwarden --auth-mode prompt` |
| Shared host | `… \| bash -s -- --user agent --allow-user alice` |

`curl … \| bash` can still prompt on a real terminal (answers are read from
`/dev/tty`). In CI or non-TTY environments, pass `--backend` / `--auth-mode`
explicitly.

More flags, shared-host setup, and uninstall detail:
[Install details](#install-details) · [Uninstall](#uninstall)

## How it works

```
you $ va claude --resume <session-id>
      │
      │  first argument selects the harness; rest → agent
      ▼
  /usr/local/bin/vaulted-agent   (alias: va)
      │
      ├─ optional sudo -u <service>       become the service account
      ├─ cd workdir                       caller cwd by default (sessions / resume)
      ├─ scrub environment                allowlist only; nothing inherited rides along
      ├─ load vault auth                  op.env / bws.env, or prompt (auth_mode)
      ├─ resolve manifest refs            op inject / bws secret get / …
      ├─ unset vault token                the agent must not inherit the master key
      └─ exec claude … --resume <id>
             │
             └─ secrets live here, in this process, until it exits
```

**Thesis:** treat the agent as the unit of authorization. Manifests are
blast-radius control, not containment.

Writeup: [One vault, three agents](https://stephens.page/blog/one-vault-three-agents-writing-the-pattern-down-found-five-bugs/) ·
Latest: [v0.3.0](https://github.com/JacobStephens2/vaulted-agent-launcher/releases/tag/v0.3.0)

## The honest claim

This is **not** automatically "no secrets on disk." With `auth_mode=file`, one
credential stays on disk: the vault service-account token in `op.env` or
`bws.env` (mode `0640`, readable by the service account). With
`auth_mode=prompt`, the launcher never writes that token either - you paste it
each launch. **Resolved secrets** (API keys, DB passwords) are never written by
the launcher in either mode; they live only in the child process environment.

What you get for that trade:

- **One credential on disk instead of thirty** (or zero manager tokens on disk
  with prompt auth). A backup, a stray `tar`, a misconfigured sync, or a
  readable dotfile exposes one token, not the fleet.
- **Central revocation.** Rotate in the vault and every future launch picks it
  up. There is no scavenger hunt through `.env` files.
- **A written answer to "which agent could reach what."** Manifests are the
  answer, and they are diffable and reviewable.
- **Nothing on the command line**, so `ps` shows nothing to any user on the box.
- **`va run`** for tools and scripts without inventing a harness per binary.
- **Fail-closed manifests** - placeholders and bad UUIDs never reach the vault.

What it does **not** protect against, stated plainly because a repo about
credential handling should not leave you to discover these:

- **The agent can read its own environment**, and so can anything running as
  the same user, via `/proc/<pid>/environ`. This is unavoidable: the agent
  needs the credentials to do the work. The mitigations are a dedicated
  service account with no other processes, and a narrow manifest.
- **The agent can exfiltrate what it holds.** It has a shell. A prompt
  injection that reaches a tool call can use every credential in its manifest.
  A narrow manifest limits how much that costs you; nothing here prevents it.
- **A harness can read past its own manifest** when the vault token is on disk
  (`auth_mode=file`). The launcher runs as the same account it hands off to;
  that account can read `bws.env` / `op.env` and query the vault directly.
  Dropping the token before `exec` stops it being *inherited*, which rules out
  accidents and casual reuse by tools that read `OP_SERVICE_ACCOUNT_TOKEN` or
  `BWS_ACCESS_TOKEN` on sight - but it is not a wall against an agent that goes
  looking. Treat manifests as blast radius control, not as containment. Making
  them containment needs privilege separation; see below. Prompt auth removes
  the on-disk token file but does not stop an agent that already holds resolved
  secrets.
- **No TTY for a token prompt** when one agent shells out to another. Use
  `auth_mode=file`, or export the vault token in the parent before
  `va …`. The launcher’s error text says this explicitly.
- **The vault token is a master key** for whatever it can read. Scope the
  service account to a single vault, and only the items an agent needs.
- **Root can read everything.** Nothing here defends against a compromised
  host.

## Install details

If you already have the tree (clone, release tarball, or the remote
bootstrap's temp dir), the real installer is:

```bash
sudo ./install.sh
```

By default agents run as **you** - the user who invoked `install.sh` - and the
command is symlinked into your `~/.local/bin` so it is on your PATH. That is
the right default on a personal machine and needs no setup.

**On a shared host, use a dedicated account instead:**

```bash
sudo useradd --system --home-dir /srv/agent --create-home --shell /bin/bash agent
sudo ./install.sh --user agent --allow-user alice
```

The reason is the threat model above: everything running as the agent's user
can read the agent's environment through `/proc/<pid>/environ`. When that user
is you, that is your shell, your editor, and anything else you happen to be
running. A dedicated account with nothing else in it makes "the same user" as
small a set as possible, and makes the audit trail say "the agent did this"
rather than naming a person. Running as root is refused outright.

`install.sh` rewrites the constants at the top of the launcher for this host,
refuses to install a launcher that no longer parses, and never overwrites a
config file you have edited. Useful flags:

| flag | |
|---|---|
| `--user NAME` | the service account to run agents as; defaults to you |
| `--no-link` | skip the default `~/.local/bin` symlink |
| `--no-va` | skip the short `va` alias (default is to install it) |
| `--no-auto-harness` | do not detect claude/codex/grok/kimi or write live harnesses |
| `--no-setup` | skip interactive vault backend questions |
| `--backend NAME` | `onepassword`, `bitwarden`, `pass`, `sops`, or `skip`. Also patches the installed launcher’s `DEFAULT_BACKEND` and the summary’s token path (`bws.env` vs `op.env`) |
| `--auth-mode MODE` | `file` (token on disk) or `prompt` (paste each launch; default `file`) |
| `--op-token-file PATH` | write OP_SERVICE_ACCOUNT_TOKEN from this file (not argv); ignored when `--auth-mode prompt` |
| `--bws-token-file PATH` | write BWS_ACCESS_TOKEN from this file; ignored when `--auth-mode prompt` |
| `--workdir DIR` | working directory; defaults to that account's home |

| `--op-env FILE` | reuse a backend credential that already exists elsewhere |
| `--links a,b,c` | also create `a-conductor`, `b-conductor`, … symlinks |
| `--allow-user NAME` | write a sudoers rule letting NAME launch any harness |
| `--link-user NAME` | symlink into NAME's `~/.local/bin`, so the command is on their PATH |
| `--force` | replace a pre-existing path that is not our symlink |
| `--dry-run` | print what it would do |

If a symlink path is already taken by something that is not ours, it stops
rather than replacing it. A box that already has launchers of its own using
those names keeps them unless you pass `--force`.

**If `vaulted-agent` comes back "command not found" afterwards**, `/usr/local/bin`
is not on your PATH - which is common enough to be worth expecting. Either
re-run with `--link-user <you>`, or link it yourself:

```bash
mkdir -p ~/.local/bin && ln -s /usr/local/bin/vaulted-agent ~/.local/bin/vaulted-agent
```

The link can live in any directory on your PATH. The sudo re-exec always
rebuilds the path as `/usr/local/bin/vaulted-agent`, so your sudoers rule
matches either way.

`install.sh` warns when it can prove the command is unreachable, but it cannot
prove the opposite: `$PATH` under sudo is root's `secure_path`, and `su -l`
synthesizes one from `/etc/login.defs`. Both routinely contain `/usr/local/bin`
when your interactive shell does not. So it also prints `command -v
vaulted-agent` for you to run in your own shell, where the answer is real.

That is enough to run it as the service account:

```console
$ sudo -u agent vaulted-agent            # lists the configured harnesses
$ sudo -u agent vaulted-agent claude
```

Or choose one interactively:

```console
$ vaulted-agent pick

   1) claude           claude --permission-mode auto           full.env.tpl
   2) claude-ro        claude --permission-mode auto           readonly.env.tpl
   3) codex            codex -s danger-full-access -a on-r...  limited.env.tpl
   4) grok             grok                                    readonly.env.tpl

harness [1-4, q to quit]: 2
```

Picking resolves to a concrete harness and then re-execs as though you had
typed `vaulted-agent claude-ro`, so per-harness sudoers rules still apply and
you are never authorized for more by choosing from a menu. `pick` is reserved
unless a harness of that name genuinely exists.

### Letting people launch without a password prompt

Two ways, and the choice is really about how precisely you need to authorize.

**If everyone who can launch an agent may launch every harness**, one rule is
enough:

```sudoers
# /etc/sudoers.d/vaulted-agent
alice ALL=(agent) NOPASSWD: /usr/local/bin/vaulted-agent
```

Then `vaulted-agent claude` and `vaulted-agent codex` both work, and adding a
harness needs no sudoers change. Note what this grants: *any* harness,
including ones added later.

**If different people get different harnesses**, install a symlink per harness
and name each path:

```bash
sudo ln -s /usr/local/bin/vaulted-agent /usr/local/bin/claude-conductor
sudo ln -s /usr/local/bin/vaulted-agent /usr/local/bin/codex-conductor
sudo ln -s /usr/local/bin/vaulted-agent /usr/local/bin/grok-conductor
```

```sudoers
alice ALL=(agent) NOPASSWD: /usr/local/bin/claude-conductor
alice ALL=(agent) NOPASSWD: /usr/local/bin/codex-conductor
bob   ALL=(agent) NOPASSWD: /usr/local/bin/grok-conductor
```

Invoked through a link the link name is authoritative and `-H` is refused, so
Bob cannot reach Alice's harnesses. This is the form to prefer, because it
needs no argument matching: each rule is a plain path.

You *can* authorize the positional form per harness instead, and the launcher
refuses `vaulted-agent grok -H claude` specifically so that this holds:

```sudoers
bob ALL=(agent) NOPASSWD: /usr/local/bin/vaulted-agent grok
bob ALL=(agent) NOPASSWD: /usr/local/bin/vaulted-agent grok *
```

Both lines are needed, since the first matches only the bare invocation. Two
rules with a wildcard is more to get right than one path, which is why the
symlinks stay the recommendation for this case.

Finally, resist giving the service account broad sudo. It is the account your
agent runs as, and `agent ALL=(ALL) NOPASSWD: ALL` makes every manifest
boundary above it decorative.

## Uninstall

Remove it the same way you run agents - uninstall lives **in the installed
binary**, so you do not need the git tree (works after a `curl | bash` install):

```bash
sudo vaulted-agent uninstall              # interactive; keeps config
sudo vaulted-agent uninstall --purge      # also remove config
sudo vaulted-agent uninstall --dry-run    # show the plan only
sudo vaulted-agent uninstall --yes        # no prompts (scripts/cron)
# short alias:
sudo va uninstall --purge
```

It prompts when a terminal is present, lists the exact paths it would remove,
and asks once more before deleting. A symlink is only removed when it resolves
to this launcher; anything else at those paths is left alone (“not ours”).

Config is kept without `--purge`, since harness files are usually hand-written.
**Backend credentials are never removed** - `op.env`, `bws.env` and `age.key`
may be shared with other tooling. Delete those yourself if you want them gone.

Add `--link-user NAME` to also remove that user's `~/.local/bin` symlink; the
user who invoked sudo is checked automatically.

From a checkout (no installed binary yet), the same logic is also reachable as
`sudo ./install.sh --uninstall …`.

## Configuration

One file per harness in `harnesses.d/`, named for the harness. `claude.conf`
is what `claude-conductor` launches:

```ini
# /etc/vaulted-agent/harnesses.d/claude.conf
bin      = $HOME/.local/bin
manifest = full.env.tpl
labels   = yes
command  = claude --permission-mode auto
```

| key        | meaning                                                            |
|------------|--------------------------------------------------------------------|
| `backend`  | `onepassword`, `bitwarden`, `sops`, `pass`, or `plainfile`          |
| `manifest` | the secrets to load. **This is the blast radius.**                  |
| `bin`      | prepended to `PATH` before exec; `$HOME` expands                    |
| `workdir`  | agent cwd: unset → install default; `caller` → your shell’s directory (needed for `--resume` / project sessions); or an absolute/`$HOME` path |
| `labels`   | map non-UUID `--resume`/`--session-id` values to a stable UUIDv5    |
| `keep`     | extra variables surviving the environment scrub, comma separated    |
| `command`  | the command line, split on whitespace                               |
| `arg`      | one further argument, verbatim. Repeatable, and the only way to pass one containing a space |

See [Resume sessions](#resume-sessions) above for `va claude|codex|grok|kimi`
resume examples. Native CLIs still differ without `va`: Claude/Grok use
`--resume`; Codex uses the `resume` subcommand; Kimi Code uses `--continue` /
`--session` (and accepts `--resume` as an alias).

Whitespace around the key, the `=`, and the value is ignored, so align them
however you like. Your own arguments are appended after the configured ones.

Manifests say what each harness may reach. **1Password** (`op://` refs):

```
APP_DB_HOST=op://AgentVault/app-database/hostname
APP_DB_USER=op://AgentVault/app-database/mysql/username
APP_DB_PASS=op://AgentVault/app-database/mysql/password
GH_TOKEN=op://AgentVault/github/fine-grained-token
```

**Bitwarden** (UUID / `name:` / `project:`; see [Bitwarden Secrets Manager](#bitwarden-secrets-manager)):

```
OPENAI_API_KEY=name:openai-api-key
GH_TOKEN=project:tools/github-token
```

A refs manifest holds references, never values, so it is safe to commit and
safe to leave world-readable. Adding a secret is one line plus a vault entry;
the next launch has it. Syntax is checked before resolve
(`va secrets validate`, `va doctor`, every launch).

The same agent can appear more than once: `claude.conf` and `claude-ro.conf`
run the identical command against different manifests. Separate files and
separate symlinks are what let the sudoers file distinguish who may launch it
with credentials that can change production and who gets the read-only set.

**Why this format.** Config is *parsed*, never sourced. That is the whole of
the safety argument, and it would hold just as well for JSON or a
whitespace-aligned table. Sourcing is what would be unsafe - it turns the
config file into arbitrary shell executed as the account holding the vault
token - and it is what most shell projects do.

Given that, the choice among safe formats is about editing failure modes, and
drop-in `key = value` files win on three:

- A structured format (JSON, YAML, TOML) needs a parser. In bash that means
  shelling out to `python3` or `jq` in the launch path, then getting values
  back into the shell without `eval`. It is doable, but adding an interpreter
  to the critical path of a credential launcher is a poor trade for syntax.
  JSON also has no comments, and the config deserves them.
- An aligned table makes column position load-bearing. Someone tidying the
  alignment can shift a field, and a value can never contain a space.
- Drop-in files make adding a harness a new file rather than an edit to a
  shared one, which is how `sudoers.d` and `systemd` units already work, and
  they map one-to-one onto the symlink and the sudoers line.

So: yes, the spacing in the examples is purely cosmetic, and no, the
free-form-ness was never what made it safe.

## Backends

Set per harness with `backend =`, or change `DEFAULT_BACKEND` in the launcher.

| backend | manifest is | on-disk credential | resolves |
|---|---|---|---|
| `onepassword` | `VAR=op://vault/item/field` | `op.env` (`OP_SERVICE_ACCOUNT_TOKEN`) when `auth_mode=file` | whole file, one `op inject` |
| `bitwarden` | `VAR=<uuid\|uuid:…\|name:KEY\|project:P/KEY>` | `bws.env` (`BWS_ACCESS_TOKEN`) when `auth_mode=file` | one `bws secret get` per line (names resolved via `bws secret list`) |
| `pass` | `VAR=store/entry/path` | the service account's GPG key | one `pass show` per line |
| `sops` | a sops-encrypted dotenv | `age.key` | whole file, one `sops --decrypt` |
| `plainfile` | a plain dotenv | the manifest itself | nothing to resolve |

### Auth mode (`file` vs `prompt`)

Machine-wide default lives in `/etc/vaulted-agent/defaults.conf`
(`auth_mode = file|prompt`). This controls **where the vault manager token
comes from**, not where resolved secrets are stored (those are never written).

| mode | Token provision | On disk |
|---|---|---|
| `file` | Read from dotenv at launch | 1Password: `/etc/vaulted-agent/op.env` (`OP_SERVICE_ACCOUNT_TOKEN=…`). Bitwarden: `/etc/vaulted-agent/bws.env` (`BWS_ACCESS_TOKEN=…`). Mode `0640`, root + service-user group. |
| `prompt` | Paste on a TTY each launch (or inherit if already exported) | **Nothing** written by the launcher. |

Set at install (interactive question, or `--auth-mode`), or later:

```bash
vaulted-agent auth-mode              # interactive (TTY) or print current
vaulted-agent auth-mode prompt       # nothing on disk
vaulted-agent auth-mode file         # use op.env / bws.env
va claude -p                         # force prompt for this launch only
```

**How the token is chosen on a single launch** (first match wins for “prompt
this launch”):

1. `-p` / `--prompt-auth`  
2. `VAULTED_AGENT_PROMPT_AUTH=1`  
3. `VAULTED_AGENT_AUTH_MODE=prompt|file`  
4. `defaults.conf` `auth_mode`  
5. built-in default `file`  

Within a launch, if the token is already in the environment, that wins over
file and prompt. If `auth_mode=file` but the file is missing and a TTY exists,
the launcher offers a one-shot “this launch only” paste.

**`va setup` and the token file.** Choice 1 (1Password) writes `op.env`. Choice
2 (Bitwarden) writes `bws.env` **only when** `auth_mode=file`. Under
`auth_mode=prompt`, Bitwarden setup exports the token in the setup process for
`bws secret list` and the optional refs-file builder, then exits - nothing
persisted. It prints:

```text
auth_mode=prompt — token not written to disk (good).
  To store it anyway: vaulted-agent auth-mode file, then re-run setup.
```

The split that matters is not which vendor, it is **reference versus payload**.

With `onepassword`, `bitwarden` and `pass`, the manifest names secrets it does
not contain. It is safe to commit, safe to leave world-readable, and reviewing
a change to it tells you exactly which credentials an agent gained or lost.
Rotation happens in the vault and the next launch picks it up.

With `sops` and `plainfile`, the manifest *is* the secrets. Per-harness
scoping then means maintaining a separate encrypted file per harness, and
rotation means re-encrypting and redeploying every one of them. `sops` at
least keeps them encrypted at rest and diffable in git; `plainfile` is a
0600 dotenv with none of the benefits this repo argues for, included so the
pattern can be demonstrated without signing up for anything. Do not reach for
it in production.

Per-key backends cost a round trip per variable, which is slower on a large
manifest. They buy something in return: a value containing a newline cannot
run over into the next variable, because each one is fetched and exported on
its own rather than parsed out of a shared document.

Adding a sixth backend is one `case` arm in `resolve`, which is also how you
would swap in `vault`, `chamber`, `aws-vault`, or `gopass`.

### Bitwarden Secrets Manager

The `bitwarden` backend is **Secrets Manager** (`bws`), not the personal vault
CLI (`bw`).

| | |
|---|---|
| Credential | `BWS_ACCESS_TOKEN` - a **Machine Account access token** (Machine Accounts → Access Tokens) |
| Not valid | personal vault master password, login API key, session tokens |
| On disk (`auth_mode=file`) | `/etc/vaulted-agent/bws.env` → `BWS_ACCESS_TOKEN=…` (`0640`) |
| On disk (`auth_mode=prompt`) | none - paste each launch |

Wrong token types fail with errors such as “Doesn't contain a decryption key.”

**Reference forms** in a refs manifest (no secret values in the file):

| Form | Example |
|---|---|
| UUID | `OPENAI_API_KEY=6a1c0e94-…` |
| `uuid:` | `OPENAI_API_KEY=uuid:6a1c0e94-…` |
| `name:` | `OPENAI_API_KEY=name:openai-api-key` |
| `project:/` | `OPENAI_API_KEY=project:tools/openai-api-key` |

Names resolve via `bws secret list` once per process. Prefer
`vaulted-agent secrets list` / `vaulted-agent setup` over raw `bws` so auth
matches launches.

**Refs file (what setup / refresh write).** After listing secrets, setup (or
`va refresh`) can write a **refs file** under `/etc/vaulted-agent/manifests/`
(default name `openai.env.refs`). That is only a filename for lines like
`OPENAI_API_KEY=name:…` - not a secret, not the access token. Point a harness
at it with `backend = bitwarden` and `manifest = openai.env.refs`, or:

```bash
va run -m openai.env.refs --backend bitwarden -p -- your-command
```

When you **add** secrets in Secrets Manager later:

```bash
va refresh openai.env.refs          # pick which to include
va refresh openai.env.refs --all    # every secret the token can see
```

Rotating a secret’s **value** in SM needs no refresh - the next launch fetches
it live. Placeholder values (`REPLACE_…`, all-zero UUIDs, …) are rejected by
`secrets validate`, `doctor`, and every launch before talking to the vault.

## Making the manifest a real boundary

As shipped, the launcher runs as the service account, reads the backend
credential as that account, and `exec`s the agent as that same account. The
agent can therefore read the credential file itself. Manifests bound what each
harness is *handed*, not what it can *obtain*.

If you need the stronger property, separate the two roles:

```
  you  --sudo-->  root  reads the token (0600 root:root)
                        resolves the manifest into its own environment
                        drops the token, scrubs the environment
                        setpriv --reuid=agent --regid=agent --init-groups
                          --> exec the agent, which now cannot read the token
```

`setpriv` from util-linux preserves the environment across the privilege drop,
which is what makes this work: the resolved secrets survive, the credential
that produced them does not, and `agent` never had permission to read it in
the first place.

The cost is that the launcher briefly runs as root, so a bug in it is worth
more. That is the usual privilege-separation trade, and it is why the launcher
is small enough to read in one sitting.

This is not wired up here yet. If you adopt the pattern and need containment
rather than blast-radius control, this is the shape to build.

## Seven, actually

**7. Exported shell functions survive a variable scrub.** Removing every
exported variable not on an allowlist looks like it produces a clean
environment. It does not. Bash carries exported functions in the environment
as `BASH_FUNC_name%%=() { ... }` and rebuilds them in the child, and they are
invisible to `compgen -e`, so a loop over exported *variables* never sees
them and `unset NAME` would not remove them anyway:

```console
$ vaulted-agent claude          # before the fix
BASH_FUNC_which%%   BASH_FUNC_module%%   BASH_FUNC_scl%%   BASH_FUNC_ml%%
```

Harmless-looking, and on most systems those come from `/etc/profile.d`. But
the mechanism is the point: a caller can export a function named `git`,
`curl`, or `ssh`, and the agent calls it instead of the binary it meant to
run. The fix is a second pass with `declare -Fx` and `unset -f`.

This one is easy to miss if you only inspect `compgen -e` or a success banner:
inspect what the agent process actually received (`/proc/<pid>/environ`, or a
one-shot harness that prints env) after a scrub.

## Dependencies

The launcher is bash and coreutils, and staying there is a deliberate choice
rather than an accident of how it started. It runs as the account holding
vault access, in the moment before the agent starts, so a surface small enough
to audit in one sitting is worth more than expressiveness. There is no build
step, no interpreter version to drift, and nothing to install on a minimal
box. The work it does - read a config file, fetch some secrets, scrub the
environment, `exec` - genuinely does not need a language.

Two optional features reach outside that, and both are avoidable:

| feature | needs | avoid it with |
|---|---|---|
| `labels = yes` | `python3`, for UUIDv5 | `labels = no`, and pass real UUIDs |
| `backend = bitwarden` | `python3`, to parse JSON | any other backend |

Everything else - config parsing, the environment scrub, injection, and the
interactive picker - is bash builtins plus `sed`.

`pick` is intentionally not `fzf`: a dependency that may be absent is a poor
trade for arrow keys, and the whole picker is about thirty lines of `printf`
and `read`. The bar for adding a language here should be a feature that
genuinely cannot be done this way - a real TUI with filtering and preview
panes would qualify; a numbered menu does not.

## Six things that are easy to get wrong

These are the bugs this launcher exists to not have. Each one was found in a
working implementation of this pattern.

**1. `<<<` writes your secrets to `/tmp`.** The natural way to walk the
resolved output is a here-string:

```bash
injected=$(op inject -i "$manifest")
while IFS= read -r line; do export "$line"; done <<< "$injected"   # DO NOT
```

Bash serves a here-string from a pipe only while it fits in the pipe buffer,
and spills to a `/tmp/sh-thd.XXXXXX` file above it. On Linux that threshold is
64 KiB, and the pipe optimisation only arrived in bash 5.1 - earlier versions
write the file unconditionally. So this code is correct until your manifest
grows, and then it silently writes every secret to disk. Check for yourself:

```console
$ bash -c 'readlink /proc/self/fd/0' <<< "small"
pipe:[112050729]
$ big=$(head -c 100000 /dev/zero | tr '\0' a)
$ bash -c 'readlink /proc/self/fd/0' <<< "$big"
/tmp/sh-thd.PJd9QD (deleted)
```

`vaulted-agent` walks the string with parameter expansion instead. It never
leaves memory, it keeps `op inject`'s exit status, and it runs in the current
shell so the exports survive.

**2. The vault token rides along into the agent.** Sourcing the token file
with `set -a` exports it, and `exec`ing the agent hands it over:

```bash
set -a; . op.env; set +a                         # exports OP_SERVICE_ACCOUNT_TOKEN
...
exec claude                                        # which now inherits it
```

The agent is now holding the credential that unlocks the whole vault, so it
can read every item, not just the ones in its manifest. Per-harness manifests
are decorative until you `unset OP_SERVICE_ACCOUNT_TOKEN` before the handoff.

**3. Injection only adds; you must also subtract.** A narrow manifest
constrains nothing if the process inherits a wide environment. `sudo` resets
the environment on the cross-user hop, which makes this look handled - but the
launcher also runs with no sudo hop at all: from cron as the service account,
from a service-account login shell, and above all when **one agent shells out
to another**, which is the whole point of running several. In that path the
child inherits the parent's full set and the manifest describes a boundary
that does not exist. `vaulted-agent` scrubs to an allowlist before injecting,
so the agent receives exactly its manifest plus `PASSTHROUGH_VARS`.

**4. `readlink -f "$0"` breaks per-path sudoers.** With symlink dispatch, the
reflex when re-execing under `sudo` is to resolve `$0` to the real script. Do
that and every invocation re-execs as `/usr/local/bin/vaulted-agent`, matching
none of the per-harness sudoers rules, and quietly requiring the caller to be
entitled to the launcher itself. Re-exec through the path that was *invoked*.

**5. `eval` mangles perfectly legal secrets.** Passwords contain `$`,
backticks, quotes and spaces. `eval "$line"` re-expands them, which corrupts
some values and executes others. `export "$line"` assigns the whole string as
`name=value` with no further expansion.

**6. Your comments come back through `op inject`.** The manifest is a template,
so comment lines survive substitution and land in the loop with everything
else. A documentation line like

```
#   KEY=op://<vault>/<item>/<field>
```

contains an `=`, and a skip test that only rejects blank lines will hand it to
`export`, which fails with `not a valid identifier` and takes the launch down
with it. Beware also that in bash, `[[ "$line" == [[:space:]]*"#"* ]]` does
*not* match a line that starts with `#` at column one. Trim the line first,
then test its first character.

## Non-interactive use

The same pattern works for a daemon that needs vault secrets, with one
difference: there is no process to inject into until systemd starts it, so the
resolved values have to land somewhere the unit can read.

Render them into a tmpfs under `RuntimeDirectory=`, never onto persistent
disk, and let the token stay in the `ExecStartPre` script rather than the
service environment:

```ini
[Service]
RuntimeDirectory=myservice
RuntimeDirectoryMode=0750
ExecStartPre=/usr/local/bin/render-env
EnvironmentFile=/run/myservice/env
```

`/run` is tmpfs, so the file is gone on reboot and never hits the block
device. It is a genuine step down in protection from the interactive case -
the values exist as a file, readable by that unit's user, for the lifetime of
the service. Prefer the launcher where you can.

## Prior art, and what this is not

Runtime secret injection is not new: `op run`, `sops exec-env`,
`vault agent`, `chamber exec`, and `aws-vault exec` all do a version of it,
and any of them drops into the `case` statement alongside the five here.

What is specific to this repo is treating **the agent as the unit of
authorization**. An AI agent holding a shell is not a normal program: it
improvises, it acts on text handed to it by other systems, and you may not
extend the same trust to every vendor's. This is a way to give several of them
credentials from one vault while writing down, per agent, exactly which
credentials those are.

## Provenance

Generalized from a production setup where agents from three vendors share one
vault, each carrying its own manifest.

Paths, account names, and vault layout in this repo deliberately differ from
that deployment. Adapt the examples rather than copying them as a working
configuration.

## License

MIT.
