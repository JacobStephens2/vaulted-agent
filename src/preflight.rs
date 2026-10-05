//! The Pre-flight report: what one `secrets validate` run found.
//!
//! `secrets validate` is the pre-flight gate of invariant 5. This module owns
//! it: validate targets and a mode in, a [`PreflightReport`] out, built in full
//! before anything prints. Each target gets one verdict. A target whose
//! Harness conf or `extra_manifest` line will not load fails on its own row,
//! and every other target is still checked.
//!
//! Live mode resolves through a [`Probe`]. The production adapter,
//! [`VaultProbe`], resolves exactly as a launch does and loads each Manager
//! token kind at most once per run. Tests pass an in-memory fake. Offline mode
//! never probes.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::auth::{TokenCache, TokenSource};
use crate::backend;
use crate::config::{Backend, Paths};
use crate::error::{Error, Result};
use crate::inventory::ValidateTarget;
use crate::validate::validate_manifest_file;

/// Resolves one Manifest on one Backend and says how many variables it
/// produced. The values are never kept.
pub trait Probe {
    fn resolve(&mut self, backend: Backend, manifest: &Path) -> Result<usize>;
}

/// How a run judges each Manifest: by shape alone, or by shape then a live
/// resolve through the probe.
pub enum Mode<'p> {
    Offline,
    Live(&'p mut dyn Probe),
}

/// Why a row failed: the error's display text and the blame lines of a
/// Resolve failure (empty for anything else). Text, not the `Error`, so a
/// verdict can be reused on every row that shares its Manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub error: String,
    pub blame: Vec<String>,
}

impl Failure {
    fn from_error(e: &Error) -> Self {
        let blame = match e {
            Error::Resolve(failure) => failure.blame_lines(),
            _ => Vec::new(),
        };
        Self {
            error: e.to_string(),
            blame,
        }
    }
}

/// One target's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Offline: the shape check passed; the vault was not asked.
    SyntaxOk,
    /// Live: the Manifest resolved to this many variables.
    Resolved(usize),
    Fail(Failure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub label: String,
    pub verdict: Verdict,
}

/// Which `secrets validate` form a report renders as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// No target: one stdout line per row, blame indented beneath it.
    All,
    /// One named Harness or Manifest: ok on stdout, blame on stderr, and the
    /// error itself for main to print.
    Single,
}

/// What the operator sees: each stream's text, printed as is.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Rendered {
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug)]
pub struct PreflightReport {
    rows: Vec<Row>,
}

/// Judge every target. A (Manifest path as bound, Backend) pair is judged once
/// per run and its verdict repeated on each row that shares it.
pub fn run(targets: &[ValidateTarget<'_>], mut mode: Mode<'_>) -> PreflightReport {
    let mut judged: HashMap<(PathBuf, Backend), Verdict> = HashMap::new();
    let rows = targets
        .iter()
        .map(|target| {
            let verdict = match target.check {
                Err(e) => Verdict::Fail(Failure::from_error(e)),
                Ok(b) => judged
                    .entry((b.manifest.clone(), b.backend))
                    .or_insert_with(|| judge(b.backend, &b.manifest, &mut mode))
                    .clone(),
            };
            Row {
                label: target.label.clone(),
                verdict,
            }
        })
        .collect();
    PreflightReport { rows }
}

fn judge(backend: Backend, manifest: &Path, mode: &mut Mode<'_>) -> Verdict {
    let checked = validate_manifest_file(manifest, backend).and_then(|_| match mode {
        Mode::Offline => Ok(Verdict::SyntaxOk),
        Mode::Live(probe) => probe.resolve(backend, manifest).map(Verdict::Resolved),
    });
    checked.unwrap_or_else(|e| Verdict::Fail(Failure::from_error(&e)))
}

impl PreflightReport {
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// False when any row fails: the gate never fails open.
    pub fn passed(&self) -> bool {
        !self
            .rows
            .iter()
            .any(|r| matches!(r.verdict, Verdict::Fail(_)))
    }

    /// The text each form has always printed.
    pub fn render(&self, form: Form) -> Rendered {
        let mut out = Rendered::default();
        for row in &self.rows {
            let label = &row.label;
            match (&row.verdict, form) {
                (Verdict::SyntaxOk, _) => {
                    out.stdout += &format!("{label}: ok (syntax only; vault not probed)\n");
                }
                (Verdict::Resolved(n), _) => {
                    out.stdout += &format!("{label}: ok ({n} variable(s) resolved)\n");
                }
                (Verdict::Fail(f), Form::All) => {
                    out.stdout += &format!("{label}: FAIL ({})\n", f.error);
                    for b in &f.blame {
                        out.stdout += &format!("    {b}\n");
                    }
                }
                (Verdict::Fail(f), Form::Single) => {
                    if !f.blame.is_empty() {
                        out.stderr += &format!("{label}: could not resolve:\n");
                        for b in &f.blame {
                            out.stderr += &format!("    {b}\n");
                        }
                    }
                }
            }
        }
        out
    }

    /// The command's result once the rendering has printed. The no-target
    /// form says only that validation failed; the single-target form fails
    /// with the row's own error text.
    pub fn outcome(&self, form: Form) -> Result<()> {
        if self.passed() {
            return Ok(());
        }
        match form {
            Form::All => Err(Error::Message("validation failed".into())),
            Form::Single => {
                let error = self.rows.iter().find_map(|r| match &r.verdict {
                    Verdict::Fail(f) => Some(f.error.clone()),
                    _ => None,
                });
                Err(Error::Message(error.unwrap_or_default()))
            }
        }
    }
}

/// The production probe: resolves through the Backend resolve a launch uses,
/// so validate agrees with a launch by construction. Manager tokens come from
/// one cache, so each kind is loaded at most once per run and dropped with the
/// probe.
///
/// The resolved values are counted and dropped. They are never printed, logged
/// or returned: a validate command that wrote secrets to a terminal would be a
/// worse bug than a gate that failed open.
pub struct VaultProbe<'a> {
    paths: &'a Paths,
    tokens: TokenCache<'a>,
}

impl<'a> VaultProbe<'a> {
    pub fn new(paths: &'a Paths, token_source: TokenSource) -> Self {
        Self {
            paths,
            tokens: TokenCache::new(paths, token_source),
        }
    }
}

impl Probe for VaultProbe<'_> {
    fn resolve(&mut self, backend: Backend, manifest: &Path) -> Result<usize> {
        let resolved = backend::resolve_with(backend, manifest, self.paths, &mut self.tokens)?;
        Ok(resolved.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ResolveCause, ResolveFailure};
    use crate::inventory::Binding;
    use std::fs;

    /// In-memory probe: a fixed answer per Manifest, every call recorded.
    #[derive(Default)]
    struct FakeProbe {
        calls: Vec<(PathBuf, Backend)>,
        inject_failure: Option<PathBuf>,
    }

    impl Probe for FakeProbe {
        fn resolve(&mut self, backend: Backend, manifest: &Path) -> Result<usize> {
            self.calls.push((manifest.to_path_buf(), backend));
            if self.inject_failure.as_deref() == Some(manifest) {
                return Err(Error::Resolve(ResolveFailure {
                    manifest: manifest.to_path_buf(),
                    cause: ResolveCause::Inject {
                        message: "could not find item gone".into(),
                        implicated: vec![("GHOST".into(), "op://V/gone/f".into())],
                    },
                }));
            }
            Ok(2)
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        good: Binding,
        other: Binding,
        load_error: Error,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str| {
            let p = dir.path().join(name);
            fs::write(&p, "A=op://V/item/a\nB=op://V/item/b\n").unwrap();
            p
        };
        Fixture {
            good: Binding {
                backend: Backend::OnePassword,
                manifest: write("good.env.tpl"),
            },
            other: Binding {
                backend: Backend::OnePassword,
                manifest: write("other.env.tpl"),
            },
            load_error: Error::UnknownBackend("vaultish".into()),
            _dir: dir,
        }
    }

    fn target<'a>(label: &str, b: &'a Binding) -> ValidateTarget<'a> {
        ValidateTarget {
            label: label.into(),
            check: Ok(b),
        }
    }

    fn broken<'a>(label: &str, e: &'a Error) -> ValidateTarget<'a> {
        ValidateTarget {
            label: label.into(),
            check: Err(e),
        }
    }

    #[test]
    fn a_target_that_will_not_load_fails_closed_without_hiding_the_rest() {
        let f = fixture();
        let mut probe = FakeProbe::default();
        let report = run(
            &[
                broken("bad (/etc/va/harnesses.d/bad.conf)", &f.load_error),
                target("a", &f.good),
            ],
            Mode::Live(&mut probe),
        );
        assert_eq!(
            report.rows()[0].verdict,
            Verdict::Fail(Failure {
                error: f.load_error.to_string(),
                blame: vec![],
            })
        );
        assert_eq!(report.rows()[1].verdict, Verdict::Resolved(2));
        assert!(!report.passed());
    }

    #[test]
    fn one_resolve_failure_does_not_hide_the_other_rows() {
        let f = fixture();
        let mut probe = FakeProbe {
            inject_failure: Some(f.good.manifest.clone()),
            ..Default::default()
        };
        let report = run(
            &[target("a", &f.good), target("b", &f.other)],
            Mode::Live(&mut probe),
        );
        assert!(matches!(report.rows()[0].verdict, Verdict::Fail(_)));
        assert_eq!(report.rows()[1].verdict, Verdict::Resolved(2));
        assert!(!report.passed());
    }

    #[test]
    fn passes_only_when_every_row_passes() {
        let f = fixture();
        let mut probe = FakeProbe::default();
        let report = run(
            &[target("a", &f.good), target("b", &f.other)],
            Mode::Live(&mut probe),
        );
        assert!(report.passed());
        assert!(report.outcome(Form::All).is_ok());
    }

    #[test]
    fn offline_never_probes() {
        let f = fixture();
        let report = run(
            &[target("a", &f.good), target("b", &f.other)],
            Mode::Offline,
        );
        assert!(report.rows().iter().all(|r| r.verdict == Verdict::SyntaxOk));
        assert!(report.passed());
    }

    #[test]
    fn a_shape_problem_fails_without_probing() {
        let f = fixture();
        fs::write(&f.good.manifest, "1BAD=op://V/item/a\n").unwrap();
        let mut probe = FakeProbe::default();
        let report = run(&[target("a", &f.good)], Mode::Live(&mut probe));
        assert!(matches!(report.rows()[0].verdict, Verdict::Fail(_)));
        assert!(probe.calls.is_empty());
    }

    #[test]
    fn a_shared_manifest_is_probed_once_and_its_verdict_repeated() {
        let f = fixture();
        let mut probe = FakeProbe::default();
        let report = run(
            &[
                target("claude", &f.good),
                target("codex", &f.good),
                target("grok", &f.good),
                target("other", &f.other),
            ],
            Mode::Live(&mut probe),
        );
        assert_eq!(probe.calls.len(), 2, "{:?}", probe.calls);
        let labels: Vec<_> = report.rows().iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, ["claude", "codex", "grok", "other"]);
        assert!(report
            .rows()
            .iter()
            .all(|r| r.verdict == Verdict::Resolved(2)));
    }

    #[test]
    fn the_same_manifest_on_another_backend_is_judged_again() {
        let f = fixture();
        let bws = Binding {
            backend: Backend::Bitwarden,
            ..f.good.clone()
        };
        let mut probe = FakeProbe::default();
        run(
            &[target("a", &f.good), target("b", &bws)],
            Mode::Live(&mut probe),
        );
        // The bitwarden shape check refuses op:// refs before any probe; what
        // matters is that the onepassword verdict was not reused for it.
        assert_eq!(probe.calls.len(), 1);
    }

    #[test]
    fn the_no_target_rendering_matches_todays_text() {
        let f = fixture();
        let mut probe = FakeProbe {
            inject_failure: Some(f.other.manifest.clone()),
            ..Default::default()
        };
        let report = run(
            &[
                target("claude (/m/good)", &f.good),
                broken("bad (/h/bad.conf)", &f.load_error),
                target("/m/other", &f.other),
            ],
            Mode::Live(&mut probe),
        );
        let other = f.other.manifest.display();
        assert_eq!(
            report.render(Form::All),
            Rendered {
                stdout: format!(
                    "claude (/m/good): ok (2 variable(s) resolved)\n\
                     bad (/h/bad.conf): FAIL (unknown backend 'vaultish' \
                     (want bitwarden, onepassword, pass, sops, plainfile))\n\
                     /m/other: FAIL (op inject -i {other} failed: could not find item gone)\n    \
                     GHOST\n      op://V/gone/f\n"
                ),
                stderr: String::new(),
            }
        );
        assert_eq!(
            report.outcome(Form::All).unwrap_err().to_string(),
            "validation failed"
        );
        let offline = run(&[target("claude (/m/good)", &f.good)], Mode::Offline);
        assert_eq!(
            offline.render(Form::All).stdout,
            "claude (/m/good): ok (syntax only; vault not probed)\n"
        );
    }

    #[test]
    fn the_single_target_rendering_matches_todays_text() {
        let f = fixture();
        let good = f.good.manifest.display().to_string();
        let mut probe = FakeProbe::default();
        let ok = run(&[target(&good, &f.good)], Mode::Live(&mut probe));
        assert_eq!(
            ok.render(Form::Single),
            Rendered {
                stdout: format!("{good}: ok (2 variable(s) resolved)\n"),
                stderr: String::new(),
            }
        );
        assert!(ok.outcome(Form::Single).is_ok());

        let mut probe = FakeProbe {
            inject_failure: Some(f.good.manifest.clone()),
            ..Default::default()
        };
        let failed = run(&[target(&good, &f.good)], Mode::Live(&mut probe));
        // A Resolve failure's blame reaches the operator on stderr; main then
        // prints the error itself.
        assert_eq!(
            failed.render(Form::Single),
            Rendered {
                stdout: String::new(),
                stderr: format!("{good}: could not resolve:\n    GHOST\n      op://V/gone/f\n"),
            }
        );
        assert_eq!(
            failed.outcome(Form::Single).unwrap_err().to_string(),
            format!("op inject -i {good} failed: could not find item gone")
        );
    }
}
