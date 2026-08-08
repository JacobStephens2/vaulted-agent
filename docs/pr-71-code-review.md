# PR #71 code review

- **Pull request:** [#71 — kimi is not env-blind: retract #69; LEGACY flag for 0.33–0.34](https://github.com/JacobStephens2/vaulted-agent-launcher/pull/71)
- **Spec:** [Issue #70 — kimi is not env-blind: v0.4.16's classification stems from an upstream kimi regression (kimi-code#2745) with a fix pending](https://github.com/JacobStephens2/vaulted-agent-launcher/issues/70)
- **Reviewed comparison:** `git diff main...HEAD`
- **Base:** `5149a42690faf91d16322a2f57c875fbe275f8a5`
- **Head:** `f17b9a3fabb31a184e1d4b61130408295f076f3c`
- **Review date:** 2026-08-08
- **Method:** two-axis review (Standards, Spec) run as parallel sub-agents, aggregated without reranking.

## Outcome

The retraction of #69 is done cleanly in the Rust and registry layer, but the retraction is incomplete in `install.sh` and the interim `KIMI_CODE_LEGACY_FLAG` fix is broader than issue #70 asked for. Standards found one hard violation and four judgement calls; Spec found six findings, the sharpest being that the flag is keyed on the agent name rather than the version range the issue specified.

## Standards

### 1. Stale `#68` policy citations survive in the installer

**Hard violation — the diff retracts a claim it leaves in operator-facing output**

`etc/env-blind-agents` and the Rust doctor copy were scrubbed of the retracted claim, but `install.sh` was not:

- `install.sh:667` — comment: `# Env-blind agent basenames (issue #68).`
- `install.sh:686` — `# Exception: env-blind agents … wiring them to a vault manifest makes inject look useful while auth still fails in the agent (issue #68).`
- `install.sh:710` — the printed operator string: `left %s (env-blind agent %s — keep empty.env; credentials go where the tool reads them, not vault inject; see etc/env-blind-agents / issue #68)`

That printed line is the exact claim this PR retracts. It is currently unreachable because the registry is empty, which is why tests do not catch it, but it is the copy the next genuine env-blind agent will surface.

### 2. Child-env construction contradicts `CONTEXT.md:23`

**Judgement call — documented invariant vs. new code path**

`CONTEXT.md:23` defines the child environment as "Explicit allowlist construction (`build_child_env`): passthrough + keep + injected secrets (after aliases) **only**". `src/launch.rs:343-346` inserts a fourth category after `build_child_env` returns:

```rust
if agent_base == "kimi" {
    child_env
        .entry(OsString::from("KIMI_CODE_LEGACY_FLAG"))
        .or_insert_with(|| OsString::from("1"));
}
```

`AGENTS.md:183-193` "Launch path (invariants)" gains no corresponding step. There is precedent for a post-`build_child_env` insert (`bin` → `PATH` at `src/launch.rs:327`), so the cheap fix is to amend `CONTEXT.md:23` and the launch invariants, or move the insert inside `build_child_env`.

### 3. `KIMI_CODE_LEGACY_FLAG` is absent from the env-var registry

**Judgement call — table scope is arguable**

`AGENTS.md:199-211` is the documented environment-variable table and it already carries a launcher-*set* variable (`VAULTED_AGENT_CALLER_CWD` — "set by launcher"). The new flag is documented only as prose at `AGENTS.md:110-116`. The table is nominally launcher-namespaced (`VAULTED_AGENT_*` plus vault manager tokens), so this is a scope judgement rather than a clear breach, but a launcher-written variable that operators may need to override belongs in a table somewhere.

### 4. `env_blind_agent_reason` is now a Middle Man

**Judgement call — Middle Man / Speculative Generality**

With the per-agent `match` removed, `src/config.rs:334-345` reduces to `is_env_blind_agent(x).then_some(CONST)`. Its doc comment says "per-agent copy is below" and the body says "Per-agent copy only for names that appear in etc/env-blind-agents" — there is no per-agent copy left. Collapse it to one constant, or restore a real per-agent reason to justify the second function.

### 5. An empty registry leaves three languages of dead branch

**Judgement call — Speculative Generality, and a stated choice**

`etc/env-blind-agents` is now comments only. That makes `install.sh:709-712` and the doctor branch at `src/commands.rs:909-926` (including `note: empty manifest is expected`) unreachable in bash and Rust alike. `MIGRATION.md:13` states this is deliberate ("registry stays for genuine cases"), so it is a carrying cost rather than a breach — but see Standards 1 for what rots inside a dead branch.

### 6. Two of the three doctor tests can only assert absence

**Judgement call — weak assertions**

`tests/cli_doctor_env_blind.rs:74-84` asserts only `!out.contains("alias= is set on an env-blind agent")`, which cannot fail while the registry is empty; it would also pass if doctor printed nothing at all. The first two tests are better anchored (`assert!(out.contains("manifest syntax ok"))` at `:41-44` and `assert!(out.contains("WARN: manifest defines no variables"))` at `:62-65`), so this applies to the alias test specifically. Nothing covers the retained env-blind branch the file header at `:4` says is being kept ("The list may still gain real env-blind tools later") — a fixture that injects a fake name into the registry would.

### 7. A new per-agent quirk lands as a Rust literal

**Judgement call — Repeated Switches**

`agent_base == "kimi"` at `src/launch.rs:343` joins `src/resume.rs:136` and `src/commands.rs:633`. Finding 1 of `docs/pr-69-code-review.md` got one hardcoded agent name lifted out into a shared data file; this puts a new one back in Rust.

## Spec

### 1. Nothing tracks the follow-up after merge

Issue #70 asks: "Reopen #68, or track here, and pause further work on the env-blind path until kimi-code#2746 is resolved."

`#68` is still `CLOSED` (closed 2026-08-08T23:00:03Z) and PR #71's body says `Fixes #70`, so merging closes the only open tracker. `MIGRATION.md:19` promises "Remove that special case once min supported kimi includes #2746" — and kimi-code#2746 is still an unmerged upstream PR. After merge, no issue holds that follow-up.

### 2. The retraction misses `install.sh` and the #69 review doc

Issue #70 item 2: the file-render backend "should not be justified by this case."

`install.sh:667,686,710` still cite issue #68 as live authority (see Standards 1). `docs/pr-69-code-review.md:49,73` still endorses "the planned-but-unimplemented file-render backend" and records the `config.toml` resolution as correct. That review doc is now the one file in the tree asserting the retracted claim without a retraction note.

### 3. The flag is agent-scoped, not version-scoped

Issue #70 item 3: "scope it to a **version range** with a pointer to kimi-code#2746 … A `KIMI_CODE_LEGACY_FLAG=1` entry in the kimi **harness** would restore vault injection today."

`src/launch.rs:343` keys on `agent_base == "kimi"` for every version, with no version check and no harness-level entry. The issue describes the flag as an opt-out ("the `KIMI_CODE_EXPERIMENTAL_FLAG` opt-in became a `KIMI_CODE_LEGACY_FLAG` opt-out"), so this forces the legacy agent core on 0.32 and on post-#2746 builds — the exact versions `etc/harnesses.d/kimi.conf:23` says "work without that flag."

### 4. The documented opt-out does not work as written

`or_insert_with` lets an operator override the value but never remove the variable. Because `build_child_env(&harness.keep, &secrets)` (`src/launch.rs:319`) is an allowlist, overriding requires *both* a parent-shell export *and* a `keep = KIMI_CODE_LEGACY_FLAG` line. `AGENTS.md:115` describes only "exporting another value into `keep` / parent"; `kimi.conf` ships no `keep` line, and no test covers the override path.

### 5. Documentation claims outrun the issue's own caveats

Issue #70 Caveats: "Only print mode (`kimi -p`) was exercised. The interactive TUI was not tested." `README.md:6-9` makes an unqualified in-process claim while `etc/harnesses.d/kimi.conf:34` ships `command = kimi --auto`, an interactive mode.

Issue #70: "I did not reproduce the Fireworks provider specifically, so treat this paragraph as inference from the `oai` result." `AGENTS.md:98-106` and `MIGRATION.md:17` restore the Fireworks alias as verified guidance with no hedge.

The closed range "0.33–0.34" (`README.md:8`, `MIGRATION.md:5`, `etc/harnesses.d/kimi.conf:20`) implies 0.35 is fixed. kimi-code#2746 is unmerged, so no version is known-fixed yet.

### 6. The registry the PR says it keeps is untested

PR #71's body: "registry kept empty for real cases." `etc/env-blind-agents` now has zero entries, so `env_blind_agent_reason` and the doctor branch at `src/commands.rs:909-926` are dead code with no positive coverage. `tests/cli_doctor_env_blind.rs` and `src/config.rs:581` assert negatives only.

## Verification

The following checks passed at the reviewed head:

```text
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
bash -n install.sh
```

Note that `Cargo.toml:3` is still `0.4.16` and `AGENTS.md:14` still pins v0.4.16. That matches the repo's release flow, where a separate release commit bumps both, so it is not counted as a finding here — but v0.4.16 is the release whose behaviour this PR retracts, so the pin should not sit unbumped for long.

Two cross-axis observations that are *not* findings on either axis: `MIGRATION.md:1` omits the `(unreleased)` marker that every other pending section carries (`:29`, `:56`, `:86`, `:124`, `:159`), and the empty registry surfaces on both axes for different reasons (Standards 5 as carrying cost, Spec 6 as an untested claim).

## Finding summary

- **Standards:** 7 findings — 1 hard violation, 6 judgement calls. Worst: the retracted "credentials go where the tool reads them, not vault inject … issue #68" copy still printed by `install.sh:710`.
- **Spec:** 6 findings. Worst: `src/launch.rs:343` scopes the LEGACY flag to the agent name rather than the 0.33–0.34 version range issue #70 asked for, forcing the legacy agent core on versions the PR's own `kimi.conf` says do not need it.

## Addressed (follow-up commit)

| Finding | Fix |
|---------|-----|
| install.sh #68 copy | Scrubbed; operator line cites registry only, notes #70 |
| Child-env / CONTEXT | Launch path + CONTEXT include `env=` / PATH |
| LEGACY not in env table | AGENTS table documents `KIMI_CODE_LEGACY_FLAG` via harness `env=` |
| Middle Man reason fn | Collapsed to `is_env_blind.then_some(const)` |
| Agent-scoped LEGACY | Removed Rust `agent_base == "kimi"`; harness `env = …` on kimi.conf |
| Opt-out broken | Delete harness `env=` line (tested) |
| Follow-up tracker | Opened #72 for dropping LEGACY after #2746 releases |
| pr-69 review | Retracted section for #70 |
| Docs overclaim | Hedges on print-mode / Fireworks / unreleased #2746 |
| Weak alias doctor test | Positive `manifest syntax ok` assert |
| MIGRATION unreleased | Marker added |
