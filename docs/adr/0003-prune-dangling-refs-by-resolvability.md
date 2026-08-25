# ADR 0003 — Pruning dangling refs by resolvability, not by provenance

**Status:** accepted (implemented in `refresh --prune`)

## Problem

`refresh` could add mappings to a refs file but never remove one. Merge appends;
replace regenerates the whole file. There was nothing in between, so a secret
renamed in the vault left its old mapping behind forever:

```
ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY        # renamed away in Bitwarden
ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY  # the same secret, ea6db86f-…
```

The first line resolves to nothing. Every launch through that manifest fails
closed on `no secret matched name:ASSEMBLY_API_KEY`, and the only fixes were to
hand-edit a root-owned file or run `--replace`, which also rewrites mappings the
operator wrote by hand.

We call such a mapping a **dangling ref**, and its removal **prune** (`CONTEXT.md`).

## Decision

**A ref is prunable when it does not resolve — regardless of who wrote it.**

`refresh` classifies each existing line against the secret listing it already
fetched. A line whose reference parses as a known Bitwarden form and matches
nothing in that listing is dangling and may be removed. A line whose reference
does not parse is reported but never removed.

Removal is surgical: the file keeps every byte it did not have to change —
comments, blank lines, ordering, and UUID-form refs all survive. It is never
silent (dangling refs are reported on every run) and never automatic (removal
requires `--prune` or an interactive confirmation, defaulting to no).

## The tension this record exists for

Story #14 established the opposite instinct. `write_refs_merge` deliberately
refuses to append a second mapping under a VAR the operator already pinned, and
`text_has_var` exists for no other reason. Read quickly, #14 says *operator lines
are not refresh's to touch*, and this ADR says refresh may delete one.

They do not actually conflict, and the distinction is the whole decision:

- **#14 protects a mapping that works.** Overwriting a working hand-pinned VAR
  silently changes which secret an agent receives. That remains forbidden — prune
  never touches a line that resolves.
- **This ADR removes a mapping that cannot work.** A dangling ref is already
  fatal to every launch through the manifest. "Protecting" it protects nothing;
  it only preserves the failure and hides where it came from.

Provenance is the wrong axis here. It is also unavailable: refs files carry no
per-line ownership. The `# --- appended by vaulted-agent refresh ---` banners are
separators, not ownership marks, and real installs have operator-written lines
sitting above all of them. A provenance rule would have to start recording
ownership now and would leave every line already on disk permanently unprunable —
including the dangling one that motivated the work.

## Rejected alternatives

**Tell operators to use `--replace`.** It already prunes, by regenerating. But it
converts UUID-form refs to `name:` form, drops operator headers, and reorders the
file. Surviving a prune untouched is precisely what makes an operator willing to
run it.

**Track provenance per line.** Prune only what refresh generated. Rejected above:
wrong axis, and it cannot see the existing corpus.

**Detect renames.** The motivating case is a rename — UUID `ea6db86f-…` kept its
identity and changed its key — so `refresh` could rewrite that one line and report
"renamed" rather than "removed, added". It cannot: a `name:KEY` line carries no
UUID, so once the vault-side key changes the line has no identifier that matches
anything. Making it possible means writing a trailing `# uuid:…` on generated
lines, which changes the manifest format and touches the resolve path. Deferred
to its own issue; guessing a rename from "one out, one in" was rejected because a
wrong label is worse than no label.

**Prune in `setup` too.** `setup` also writes refs and can run against a
configured host. It must never delete mappings there. Pruning is maintenance, and
`refresh` is the maintenance verb.

## Consequences

- `refresh` is no longer append-only. The prune path writes via temp-file-plus-
  rename, because it can now remove lines nothing can regenerate — a truncated
  manifest would be an install that launches nothing.
- Removed lines print verbatim, so scrollback is the recovery path. No `.bak`
  files accumulate in the root-owned manifest directory.
- `refresh` exits `0` when it finds dangling refs it did not remove. It is not a
  gate; `secrets validate` is (invariant 5), and it already fails on a dangling
  ref. Two commands reporting "broken" would blur which one blocks a launch.
- `refresh` warns, without blocking, when a harness `alias =` names a VAR about to
  be pruned — the one piece of cleanup prune cannot do itself.
- A placeholder reference is never pruned, even though an all-zero UUID parses
  as a form and matches nothing. Invariant 4 makes placeholders fail closed, and
  they are `secrets validate`'s to report; removing one would take the variable
  out of the manifest altogether, turning a loud misconfiguration into a secret
  that quietly stops being injected.
- Bitwarden only for now. 1Password refs carry recorded `--exclude` patterns, so
  "does not resolve" has more shapes there; deferred to its own issue.
