# ADR 0002 — Rendering resolved secrets into an ephemeral file

**Status:** proposed (design only; nothing implemented) — issue #68

## Problem

The launcher's delivery mechanism is the child environment: resolve the
manifest, inject, `exec`. That works because claude, codex and grok all read
credentials from environment variables.

A large family of tools does not. They read credentials only from a config file:

| Tool | Where it looks | How the path is overridden |
|---|---|---|
| AWS CLI / SDKs | `~/.aws/credentials` | `AWS_SHARED_CREDENTIALS_FILE` |
| npm | `~/.npmrc` | `NPM_CONFIG_USERCONFIG` |
| curl, ftp | `~/.netrc` | `NETRC` |
| rclone | `~/.config/rclone/rclone.conf` | `RCLONE_CONFIG` |

For these, a manifest is not merely unhelpful, it is **invisible**. Every
variable resolves, injects, and is ignored. Nothing errors, every syntax check
passes, and `va doctor` reports healthy — the only symptom is the agent's own
auth failure, which looks nothing like a launcher problem.

**Kimi Code is not one of these tools.** This ADR was drafted (issue #68,
v0.4.16) believing it was. Issue #70 disproved that with a live end-to-end
test: kimi *does* read OpenAI-compatible provider keys from the process
environment, selecting by provider **type**, and the 0.33–0.34 failures came
from an upstream gate regression ([kimi-code#2745](https://github.com/MoonshotAI/kimi-code/issues/2745)).
The classification was retracted in v0.4.17 and `etc/env-blind-agents` records
that kimi must not be re-added. The motivating example is gone; the tools in
the table above remain genuinely config-file-only, so the design question this
ADR asks is still open — it just has no urgent case driving it.

Today the only honest answer is "paste the key into the tool's config file,"
which is precisely the pile of secrets on disk this project exists to remove.

## Decision (proposed)

A harness may declare one or more **renders**. A render substitutes resolved
manifest variables into a template and writes the result into a private
per-launch directory, then points the child at it with an environment variable.

The examples below are written against kimi because that is the tool this was
drafted for. They are now **hypothetical** — kimi reads the environment fine
(see Problem). Re-basing them onto a tool that really is config-file-only (AWS
CLI, rclone) is open work; the shape of the keys is what is being proposed, not
the choice of agent.

```ini
# harnesses.d/kimi.conf — hypothetical; kimi does not need this
backend        = bitwarden
manifest       = kimi.refs
render         = config.toml = kimi.config.toml.tpl
render_dir_env = KIMI_CODE_HOME
command        = kimi --auto
```

```toml
# manifests/kimi.config.toml.tpl — no secrets, only names
[providers.fireworks]
type    = "openai"
api_key = "${FIREWORKS_API_KEY}"
```

- `render` is repeatable (the `arg` precedent), `DEST = TEMPLATE`, where `DEST`
  is a bare filename inside the render directory.
- `render_dir_env` names a variable set to the render directory. For tools that
  want a file rather than a directory, `render_file_env = VAR = DEST` sets `VAR`
  to one rendered file's full path.
- Substitution uses the resolved manifest variables and nothing else. A
  reference to a name the manifest does not define **fails the launch**, matching
  how `alias` already refuses a missing source rather than shipping a wrong key.

Some tools want the override directory to hold non-secret state too — kimi keeps
sessions, logs and `device_id` beside `config.toml`, and a bare render directory
silently breaks `--resume`. Two further keys cover it, both non-secret by
construction:

```ini
render_link = sessions  = $HOME/.kimi-code/sessions
render_copy = device_id = $HOME/.kimi-code/device_id
```

## The exec problem

This is the part that actually costs something, and it should be settled before
any of the above is built.

The launcher's current shape is `exec` — it replaces itself with the agent and
is gone. That is a real property, not an accident: no supervisor process, no
signal forwarding to get wrong, nothing holding the vault token while the agent
runs. Rendering breaks it, because **something has to delete the file when the
agent exits**, and after `exec` there is no launcher left to do it.

Options considered:

- **Fork and wait when (and only when) a harness declares a render.** The
  launcher stays as a thin parent, waits, then removes the directory. Costs an
  extra process, signal forwarding, and exit-status propagation — all of which
  must be got exactly right or `va <agent>` stops behaving like the agent. Harnesses
  without renders keep the current `exec` path untouched.
- **`exec` a shell wrapper that traps EXIT.** Cheap, but reintroduces a shell
  into the launch path, and `install.sh` deliberately writes no shell for the
  runtime to source. A `kill -9` defeats the trap anyway.
- **Leave the directory and reap it on the next launch.** Weakest: the window is
  unbounded, and "next launch" may be never.

Preferred: fork-and-wait, gated on the harness declaring a render, so the
property is only given up by harnesses that cannot work without it.

## Threat model change

This is the reason the ADR exists. The README's honest-claim section currently
states, without qualification:

> **Resolved secrets** (API keys, DB passwords) are never written by the
> launcher in either mode; they live only in the child process environment.

A render makes that false for harnesses that use one. The claim has to be
rewritten, not quietly narrowed — a security invariant stated that plainly is
one people rely on.

What the design can honestly offer instead:

- The file lives in a `mkdtemp` directory, mode `0700`, owned by the account the
  agent runs as; the file itself is `0600`. Never in the repo, never in `$HOME`,
  never at a path another user can predict.
- Prefer `/dev/shm` when it exists (Linux) so the bytes need never reach a disk.
  macOS has no tmpfs equivalent, so there the file is on disk and the claim must
  say so.
- Removed when the agent exits. A `kill -9` or a panic leaves it; the next
  launch of the same harness sweeps stale directories it owns.
- Unchanged: the manager token still never reaches the child, and the manifest
  is still the blast radius.

What it does **not** offer: this is not containment. An agent that can read its
own config file can exfiltrate the credential in it, exactly as it can already
exfiltrate its own environment.

## Alternatives rejected

- **FIFO / named pipe at the config path.** No bytes at rest, which is the
  attraction. Rejected as too fragile to depend on: a pipe can be read once,
  cannot be `stat`'d for size, and cannot be seeked. Config loaders routinely do
  all three, and several re-read the file after a reload. The failure mode is a
  hang, not an error.
- **`/dev/fd/N` passed to the child.** Same seek and re-open problems, plus it
  needs the tool to accept a path it will not recognise as its own config.
- **Teach each tool to read the environment.** Not ours to do, and the tools are
  not wrong: a config file is a reasonable place for a credential. The gap is in
  what this launcher can express.
- **Document "paste it in the config file" and stop.** What we do today. It is
  the one answer that guarantees a long-lived plaintext secret on disk, which is
  the thing the project exists to remove.

## Consequences for existing code

- `config::env_blind_agent` (added with the #68 doctor warning) becomes the seed
  of a capability table: today it answers "warn, this cannot work," and after
  this lands it answers "this agent needs a render, here is its shape."
- `va doctor` gains a render check — template exists, every `${…}` in it is
  defined by the manifest, `render_dir_env` is set when the tool needs a
  directory — and the #68 warning fires only when a harness is env-blind *and*
  declares no render.
- `va secrets validate` should resolve template references too, or a manifest
  can pass while the render that consumes it cannot.
