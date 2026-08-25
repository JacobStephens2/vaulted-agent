# ADR 0005 — Pruning 1Password refs: exclusion is not resolvability

**Status:** accepted (implemented in `refresh --prune`; issue #81)

## Problem

ADR-0003 gave `refresh` a prune, and shipped it for Bitwarden only. 1Password
refs files have the same disease: `refresh_onepassword` merged and never
removed, so an item renamed or deleted in the vault left a
`VAR=op://VAULT/ITEM/FIELD` line resolving to nothing, and `op inject` fails the
**whole manifest** on one such reference — every launch through it, not just the
variable that went bad.

The rule from ADR-0003 carries over unchanged: **a ref is prunable when it does
not resolve, regardless of who wrote it.** Two things did not carry over, and
are what this record settles.

**"Does not resolve" has more shapes.** A Bitwarden reference names a secret. An
`op://` reference names a vault, an item, optionally a section, and a field, so
the item can be gone while the field is fine, or the item can be there and the
field gone. And a 1Password manifest records `# exclude:` patterns which later
runs honour, so a mapping can be one the operator has since said not to map —
a fourth state Bitwarden simply does not have.

**Detection is not free.** Bitwarden classifies against a listing `refresh`
already holds. 1Password knows items from one `op item list`, but fields only
after a per-item `op item get` — which is why selection is at item level in the
first place (~50s on a 60-item vault).

## Decision

**1. An exclusion is not a dangling ref.** A mapping whose variable now matches
a recorded `# exclude:` pattern, and which still resolves, is reported under its
own heading and kept.

Exclusion governs what `refresh` **adds**. The line still works, and removing a
line that works is the one thing prune promises not to do — the story #14
protection ADR-0003 was careful to preserve. The argument for the other answer
is real (a recorded pattern is standing intent in a way a menu answer is not),
but acting on it would mean prune removes by *intent* as well as by
*resolvability*, and the operator who added `--exclude '*_USERNAME'` to stop
mapping new usernames would silently lose the one an agent is running on today.
Deleting the line by hand is one `edit-manifest` away, and the report names the
file, so the state is visible rather than mysterious.

Only a mapping shown to **resolve** is reported this way. Every other fate has a
heading of its own that says something this one would contradict — a dangling
line is about to go, and an unchecked or unjudged line was never shown to
resolve at all. One line, one heading, one fate.

**2. `refresh` judges what it already fetched, and says so where it did not.**
The item listing is one call and covers every item, so a reference into an item
that is not in the listing is dangling. Fields are known only for the items this
run expanded, so:

- item expanded → judged down to the field;
- item in the listing, not expanded (not selected, or a per-item read that
  failed) → an **unchecked ref** (`CONTEXT.md`): reported under "Refs this run
  did not check", never pruned;
- shape `op` itself cannot read, a placeholder, or a plain literal →
  `Unjudged`, exactly as on the Bitwarden side.

`refresh --all --prune` therefore gives complete field-level coverage at no
extra vault cost, and a narrow selection prunes narrowly. No run pays a round
trip it was not already paying.

**3. Field existence is judged against every field, not the mappable ones.**
`refresh` skips OTP, notes, and empty-valued fields when generating. All three
still resolve through `op`, so an operator's `op://…/one-time` line is a working
mapping. Judging against the generator's filtered view would call it dangling
and delete it, which is why the item JSON is now read twice from one call: the
fields worth mapping, and every field identity a reference may name.

Every remaining uncertainty resolves toward "not dangling": vault, item title,
section and field label match case-insensitively (as `op` resolves them), the
vault may be named by id as well as by name and the item by id as well as by
title, a field id counts as a name, and an unqualified reference matches a field
in any section — because `op` will find it there.

A placeholder in **any** component leaves the line unjudged. `is_placeholder_ref`
anchors most of its spellings at the start of the string, which behind an
`op://` prefix is the scheme, so the components are offered to it one at a time.
Invariant 4 keeps placeholders loud and ADR-0003 keeps prune off them: removing
one would take the variable out of the manifest altogether, turning a loud
misconfiguration into a secret that quietly stops being injected.

## Rejected alternatives

**Prune a now-excluded mapping.** Above: it trades ADR-0003's single rule for a
second axis, and can remove a credential an agent is using.

**Verify every mapped item's fields.** An extra `op item get` per item the
manifest maps, on every `refresh`, so that a field-level dangler is found even
when the operator expanded one item. Complete, and it puts a minute of vault
round trips on a run that asked for one item. The cheap path already reaches the
same coverage under `--all`.

**Item level only.** Prune when the whole item is gone, never look at fields.
Cheapest, and it leaves the likeliest case — a field renamed inside a live item
— undetected forever.

**Detect renames, as ADR-0004 does for Bitwarden.** An `op://` line records no
source id, and there is nowhere obvious to put one: a trailing `# uuid:…` on a
1Password refs line sits in a file `op inject` reads whole. So a renamed item is
indistinguishable from a deleted one, and both are dangling. If that becomes
painful, it is its own issue.

## Consequences

- `refresh --prune` now applies to both backends; the error saying it is
  Bitwarden-only is gone. The gate (`--prune`, an interactive `[y/N]` defaulting
  to no, `--replace` regenerating instead) and the surgical atomic write are
  shared code — only classification differs.
- `refresh` reports up to four groups on a 1Password manifest: dangling,
  unchecked, unjudged, and mapped-but-excluded. Exit stays `0` for all of them;
  `secrets validate` is the gate (invariant 5).
- A per-item read failure (a 502 mid-run) leaves that item's mappings unchecked,
  and is reported as a read failure rather than passed over. A transient vault
  error must never read as "the secret is gone".
- The prune runs before the merge writes, so a dangling line is out of the file
  before `refresh` decides what to append into it.
- `CONTEXT.md` gains **unchecked ref**; **dangling ref** and **prune** keep the
  meanings ADR-0003 gave them.
