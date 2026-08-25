# ADR 0004 — Recording the source UUID on generated refs lines

**Status:** accepted (implemented in `refresh`; issue #82)

## Problem

ADR-0003 gave `refresh` the ability to remove a mapping that resolves to
nothing. It could not do better than that for the case which motivated the
work, which was not a deletion but a **rename**: Bitwarden secret
`ea6db86f-…` kept its identity and changed its key from `ASSEMBLY_API_KEY` to
`ASSEMBLY_AI_API_KEY`. The best `refresh` could say was "1 dangling, 1 new" —
two unrelated-looking facts about one secret — and the best it could do was
delete the old mapping and append a new one under a new variable name, silently
breaking any harness `alias =` pinned to the old one.

It could not do better because a `name:KEY` line carries no identity:

```
ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY
```

Once the vault-side key changes, that line's only identifier is a string
matching nothing. Guessing — "one went dangling, one appeared, same run, must be
a rename" — was rejected in #80: it will eventually mislabel two unrelated
changes, and a wrong label is worse than none.

## Decision

**A line `refresh` generates records the secret it was generated from**, as a
trailing comment:

```
ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:ea6db86f-e103-4153-a71e-b4b100c30b65
```

The reference stays in `name:` form. Readability is why that form was chosen,
and the UUID is metadata about the line rather than the thing being resolved.

`setup` and `refresh` both generate lines, so both write recordings. Only
`refresh` ever acts on one: fixing a manifest is maintenance, and `refresh` is
the maintenance verb (ADR-0003).

Three consequences follow, and they are the whole feature:

1. **Merge stops double-mapping a renamed secret.** `text_has_secret` counts a
   recorded UUID as "this secret is already mapped", so the new key does not get
   a second line.
2. **The scan gains a verdict between resolvable and dangling.** A reference
   matching nothing whose recorded UUID *is* in the listing is `Renamed`, and it
   carries the key that secret has now.
3. **A rename is repaired, not pruned.** `refresh` rewrites the one line's
   reference and reports `renamed`.

**The repair keeps the variable name.** `ASSEMBLY_API_KEY` continues to name the
secret; only the reference changes. The variable is the contract with the agent
and with any harness `alias =` reading it, while the vault-side key is merely how
the secret is addressed. Rewriting the variable would break the consumer
silently — the exact failure this record exists to remove.

## The three questions this was deferred on

**Trailing comment, or UUID-form refs with the name as the comment?** Trailing
comment. UUID-form is rename-proof by construction and needs no listing lookup,
but a manifest of bare UUIDs cannot be read, and being readable is what makes an
operator willing to hand-edit and hand-pin lines in it.

**Does `validate` check that a recorded UUID and its `name:` still agree?** No.
`secrets validate` is the pre-flight gate (invariant 5) and must not fail a line
that resolves. A disagreement is not a misconfiguration; it is exactly the
rename signal, and reporting it belongs to `refresh`, the maintenance verb. Two
commands reporting the same thing would blur which one blocks a launch — the
same reasoning ADR-0003 used for its exit status.

**Do existing lines get UUIDs backfilled?** No. This was the sharpest question,
because a backfill looks like a direct tension with ADR-0003's surgical-write
promise, and it is one: annotating a line that already works is rewriting a
mapping `refresh` was not asked to touch. The corpus migrates as `refresh` adds
mappings, and until then those lines behave exactly as ADR-0003 left them —
a rename in an un-annotated line is still reported as a dangling ref and still
pruned. Paying for the migration is not worth breaking the promise that makes
prune safe to run. A future `--backfill-uuids`, opt-in and separate, remains
available if the slow migration proves too slow.

## Deliberately not done: disambiguation

Issue #82 lists a third payoff this record does **not** deliver:

> `name:` refs are ambiguous when two secrets share a key (`parse_bws_ref`
> already errors with "multiple secrets named X; use project:PROJECT/X"). A
> recorded UUID disambiguates without the operator rewriting anything.

It would work — where the reference is ambiguous the launch fails closed today,
so resolving to the recorded UUID could only turn an error into a secret. It is
left out because it would change what the recording *is*. Everywhere else the
recording is metadata, stripped before resolve and unable to affect which secret
an agent receives; a stale comment is harmless. Make it authoritative for
ambiguous references and a hand-edited comment silently decides which of two
secrets gets injected — on the launch path, which is the part kept small and
auditable (story #44).

That is a separate decision about the trust placed in a comment, and it wants
its own record. Meanwhile the recording still helps here, just not by itself: the
UUID is now visible in the file, so an operator resolving the ambiguity can copy
it into `uuid:` form instead of hunting for it in `bws secret list`.

## Cost on the launch path

The launch path is deliberately small and auditable (story #44), and this puts a
new obligation on it: a reader of a Bitwarden refs value must strip the trailing
comment before resolving. That happens **once**, in `validate_manifest_text`,
the single seam both `resolve_bitwarden` and `secrets validate` already pass
through. `resolve_bitwarden` never learns the format changed.

The split requires whitespace before the `#`. No Bitwarden reference form
contains whitespace, so ` #` unambiguously ends one, while a bare `#` may sit
inside a secret key and treating that as a comment would send a truncated
reference to the vault. The strip is Bitwarden-only: a plainfile or sops
manifest holds secret *values*, where a `#` is material and dropping the tail
would silently truncate a password.

## Consequences

- `refresh` can now change a line rather than only add or remove one. Removals
  and repairs share one gate (`--prune` or an interactive yes) and one write, so
  a run cannot leave the file half-corrected. The prompt names which kinds it is
  about to do, because a removal and a repair are not the same act.
- A placeholder UUID records nothing. Invariant 4 keeps placeholders loud, and a
  zero UUID must never be the evidence that turns a line into a rename.
- A recorded UUID is consulted only for a reference that already failed to
  match. A working mapping is never reclassified on the strength of a stale
  recording, so a hand-edited line whose comment went out of date stays working
  and stays untouched.
- Deletion is still prune's case. The recording proves a rename only while the
  secret is still visible to the manager token.
- A repair cannot introduce a duplicate variable, because it keeps the variable
  it found. If the renamed secret's new key already has a line of its own, the
  result is one secret reachable under two names — which a refs file has always
  allowed, and which injects the same value either way.
- Edits are keyed by the physical line, so a manifest that already lists one
  line twice has both copies repaired. That file was already reported by
  `manifest_problems` as setting a variable more than once; the repair leaves it
  no worse, and does not create the duplicate.
- `--replace` does not repair — it regenerates from the listing, so a renamed
  secret comes back under its **new** key and the old variable does go. That is
  the one case where a rename can break a harness `alias =`, so `refresh` warns
  about it there. It is the same warning ADR-0003 kept for prune, and the reason
  the repair path needs no warning of its own.
- Refs files still carry no secret material. A UUID is a reference, and the file
  was already full of them.
- Bitwarden only, like ADR-0003. 1Password references are structural (`op://`)
  and carry their own identity, so there is nothing to record.
