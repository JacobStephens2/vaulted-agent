# PR #69 code review

- **Pull request:** [#69 — docs+doctor: kimi is env-blind for vault inject](https://github.com/JacobStephens2/vaulted-agent-launcher/pull/69)
- **Spec:** [Issue #68 — kimi does not read credentials from the environment](https://github.com/JacobStephens2/vaulted-agent-launcher/issues/68)
- **Reviewed comparison:** `git diff main...HEAD`
- **Base:** `422c56d2c418ed054da5a40ae8edbb22c3222296`
- **Head:** `fc21fab69be0663bb728fdfc997d069373637bf5`
- **Review date:** 2026-08-08

## Outcome

The review found one partial spec mismatch and two maintainability smells. It found no hard violations of the repository's documented standards.

## Standards

### 1. Env-blind agent policy is duplicated

**Judgement call — Duplicated Code / Shotgun Surgery**

The identity of env-blind agents is maintained independently in two places:

- `install.sh:694` checks for `kimi` while deciding whether to wire a day-one harness to a vault manifest.
- `src/config.rs:316` matches `kimi` when deciding whether `va doctor` should report an env-blind-agent warning.

The `env_blind_agent_reason` documentation explicitly says to keep the Rust policy in sync with `wire_day_one_harnesses`. Adding or renaming an env-blind agent therefore requires coordinated edits. The policies already differ slightly because the installer also classifies a harness named `kimi.conf`, regardless of its command.

A shared policy source or generated list would remove this maintenance coupling.

### 2. Doctor test setup is repeated

**Judgement call — Duplicated Code**

`tests/cli_doctor_env_blind.rs` repeats substantially the same `CliSeam`, defaults, harness, and manifest setup in all three tests, beginning at lines 27, 57, and 83.

A small Kimi doctor fixture would let each test emphasize only the condition it varies: a non-empty manifest, an empty manifest, or an alias.

## Spec

### 1. The README retains an unqualified peer-agent claim

Issue #68 says that presenting Kimi alongside Claude, Codex, and Grok implies that all four consume vault credentials from the child process environment, even though Kimi custom OpenAI-compatible providers do not.

The quick-start example now distinguishes Kimi custom-provider credentials, but `README.md:6` still says:

> Give Claude Code, Codex, Grok, and Kimi Code real vault credentials **in-process**.

That unqualified headline preserves part of the product claim the issue asks the documentation to correct. It should qualify Kimi's built-in-provider exception or limit the headline to credential paths that can consume injected environment variables.

The shipped Kimi harness, installer exclusion, doctor warning, built-in-provider exception, and documentation of the planned-but-unimplemented file-render backend otherwise match the stated PR scope.

## Verification

The following checks passed at the reviewed head:

```text
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
bash -n install.sh
```

## Finding summary

- **Standards:** 2 judgement-call findings; 0 hard violations. The broader concern is the duplicated env-blind-agent policy.
- **Spec:** 1 finding. The README headline still makes an unqualified in-process credential claim for Kimi.

## Addressed (follow-up commit)

| Finding | Fix |
|---------|-----|
| Duplicated env-blind policy | Single source `etc/env-blind-agents`; Rust `include_str!` + install `is_env_blind_agent` |
| Doctor test setup repeated | Shared `seam_kimi` fixture |
| README unqualified claim | Headline limited to Claude/Codex/Grok; Kimi called out for config.toml / #68 |

## Retracted (issue #70 / PR #71)

Issue #70 showed kimi is **not** structurally env-blind; v0.4.16’s
classification came from kimi-code#2745. The README “config.toml only” claim
and the planned file-render justification **from this kimi case** are
superseded by PR #71. Keep `etc/env-blind-agents` for genuine env-blind tools;
do not re-list kimi without re-checking #70.
