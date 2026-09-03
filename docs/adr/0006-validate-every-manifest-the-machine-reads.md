# ADR 0006 — `secrets validate` covers every manifest the machine reads

**Status:** accepted (implemented as `extra_manifest` in defaults.conf)

## Problem

`secrets validate` is invariant 5: the pre-flight gate that must not fail open.
It walked the harness profiles — every `harnesses.d/*.conf`, resolving the
manifest each one launches from — and stopped there.

A machine reads more manifests than it launches from. On the host this record
comes from, six harnesses share one refs file under `/etc/vaulted-agent`, and a
*second* refs file at `/srv/orchestration/env.tpl` is read by the box's systemd
units, its status dashboard, and its deploy verifier. Nothing launches from it,
so no harness names it, so validate never looked at it.

On 2026-09-03 an item was deleted from that vault. `op inject` resolves a
manifest whole or not at all, so every non-interactive consumer of `env.tpl`
fail-closed at once: 39 failures and four dead units, from 09:00 until a human
noticed at 15:00 through an unrelated error. The documented remedy — "after a
change in the vault itself, run `secrets validate`; that names the variables
that broke" — was run and printed six green lines.

That is the worst possible shape for a check. It is the documented gate for
exactly this fault, it is cheap, the fault class is one that is invisible
offline (a deleted or renamed item leaves a perfectly well-formed reference),
and an operator who ran it was told everything was fine.

## Decision

**1. The validated set is "every manifest this machine reads", not "every
manifest a harness launches from".** A machine records the rest in
`defaults.conf`, repeatably:

```
extra_manifest = /srv/orchestration/env.tpl
extra_manifest = /etc/other/refs.env = plainfile
```

Relative paths resolve against the manifest directory, like a harness
`manifest =`. The backend defaults to the machine default and may be named per
entry, because a second manifest need not share the first one's backend.

**2. An extra manifest is a first-class member of that set, not a harness with
a fake command.** Modelling it as a seventh profile would be less code and
worse: it would appear in `secrets which`, in `va` and `va pick`, and would sit
one `-H` away from being launched. Nothing launches an extra manifest — the
concept is deliberately inert everywhere except validation.

**3. Every line names its manifest, pass or fail.** Six harnesses over one file
previously printed six names and no files, so "green" could not be read as
coverage — which is the operator's actual question after a vault change, and
the question the outage turned on. Failures need it for a second reason: the
remedy differs by file (a `va` manifest edit versus `env.tpl`), so a blamed
variable without its manifest is half an answer.

**4. Fail closed on an entry that cannot be checked.** A missing file, an
unparseable `extra_manifest` line, an unknown backend name — each is an error,
not a skip. An operator who has recorded a file believes it is being checked;
silently not checking it recreates the defect exactly.

**5. `--offline` covers the same set** for the faults it can see without a
vault. It is a weaker check, not a narrower one.

## Consequences

- Output format changed: harness lines now read `claude (/etc/…/x.env.tpl): ok
  (252 variable(s) resolved)`. Anything parsing the old `name: ok` shape needs
  updating; see MIGRATION.md.
- Cost scales with manifests, and a shared file is still resolved once per
  harness that names it. Deduplicating by path would be a behaviour change of
  its own (a per-harness backend can differ), and validation is not on a hot
  path, so it is left alone.
- `doctor` stays harness-scoped. It reports launch-readiness for the account it
  runs as, which is a different question from vault consistency, and it is
  offline by design — the fault here is invisible offline.
- References that live outside any manifest — a script calling `op read`
  directly — are still uncovered by this. That is a real gap (the same host had
  a renamed item break four such scripts for thirteen days), but it is a
  repository-scanning problem, not a launcher-config one: the launcher cannot
  know which files on a box contain references.
