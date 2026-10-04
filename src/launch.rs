//! Launch adapter: manifest check → resolve → drop tokens → Workdir preflight
//! → pure Launch plan (`launch_plan.rs`) → exec (or spawn for tests).

use std::collections::HashMap;
use std::env;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::auth::TokenSource;
use crate::backend;
use crate::config::{load_default_backend, load_service_user, Backend, Harness, Paths};
use crate::env_scrub::{parent_env_snapshot, MANAGER_TOKEN_VARS};
use crate::error::{Error, Result};
pub use crate::launch_plan::LaunchPlan;
use crate::launch_plan::{self, LaunchFacts};
use crate::secret::SecretValue;
use crate::workdir::{self, CallerContext};

/// How to hand off to the agent process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandoffMode {
    /// Replace the launcher process (production).
    #[default]
    Exec,
    /// Spawn and wait (CLI acceptance tests).
    Spawn,
}

impl HandoffMode {
    /// Prefer explicit opts; fall back to tests-only env for compatibility.
    pub fn from_env() -> Self {
        match env::var("VAULTED_AGENT_HANDOFF").as_deref() {
            Ok("spawn") | Ok("test") => Self::Spawn,
            _ => Self::Exec,
        }
    }
}

pub struct LaunchOpts {
    /// How this invocation obtains the Manager token, if the Backend needs one.
    pub token_source: TokenSource,
    pub extra_args: Vec<String>,
    /// When set, overrides env-based handoff.
    pub handoff: Option<HandoffMode>,
}

/// The launch adapter: every piece of launch I/O in order, then the pure
/// Launch plan (`launch_plan::plan`) from what it gathered.
pub fn build_launch_plan(
    paths: &Paths,
    harness: &Harness,
    opts: &LaunchOpts,
) -> Result<LaunchPlan> {
    let manifest = harness.resolve_manifest_path(paths);
    if !manifest.is_file() {
        return Err(Error::Io {
            path: manifest,
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "manifest not found"),
        });
    }

    let backend_name = harness
        .backend
        .unwrap_or_else(|| load_default_backend(paths));

    // A resolver failure names what the vault could not find — an item title,
    // or a reference its scanner could not read — and the operator needs the
    // variable, which is what they will grep the manifest for. `op inject`
    // also fails the whole file at the first bad reference, so the message
    // alone gives no sense of how much is broken. Say which entries are at
    // fault and name the command that confirms a fix, then fail as before.
    //
    // The common cause is an item renamed in the vault since the manifest was
    // written: the reference stays well-formed and stops resolving, so nothing
    // offline can catch it.
    let secrets: HashMap<String, SecretValue> =
        match backend::resolve(backend_name, &manifest, paths, opts.token_source) {
            Ok(s) => s,
            Err(e) => {
                let blamed = match &e {
                    Error::Resolve(failure) => failure.blame_lines(),
                    _ => Vec::new(),
                };
                if !blamed.is_empty() {
                    eprintln!(
                        "vaulted-agent: could not resolve {} reference(s) in {}:",
                        blamed.len(),
                        manifest.display()
                    );
                    for b in &blamed {
                        eprintln!("    {b}");
                    }
                    eprintln!(
                        "  An item may have been renamed or removed in the vault. \
                         Confirm with: vaulted-agent secrets validate"
                    );
                }
                return Err(e);
            }
        };

    // `resolve` already dropped the token it loaded. Clear the manager-token
    // vars from the launcher process env too so they are not ambient.
    // Residual plaintext in this process's heap is out of scope for the threat
    // model (explicit child env is the boundary that matters).
    for &name in MANAGER_TOKEN_VARS {
        env::remove_var(name);
    }

    // After the privilege hop (if any) this process *is* the effective launch
    // account. Fail here with a clear remedy rather than a bare exec EACCES
    // (issue #56).
    let caller = CallerContext::from_env();
    let workdir = workdir::preflight(
        harness.workdir.as_deref(),
        &caller,
        load_service_user(paths).as_deref(),
    )?;

    // Snapshot after the token clear above, so the launcher holds no ambient
    // token; the plan strips manager tokens from the child regardless.
    launch_plan::plan(
        harness,
        secrets,
        LaunchFacts {
            workdir,
            home: caller.home,
            parent_env: parent_env_snapshot(),
            extra_args: opts.extra_args.clone(),
        },
    )
}

/// Run a plan via exec (production) or spawn (tests).
pub fn run_plan(plan: &LaunchPlan, handoff: HandoffMode) -> Result<()> {
    let mut cmd = Command::new(&plan.program);
    cmd.args(&plan.args)
        .current_dir(&plan.workdir)
        .env_clear()
        .envs(&plan.env)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    match handoff {
        HandoffMode::Spawn => {
            let status = cmd
                .status()
                .map_err(|e| Error::Message(format!("failed to spawn {}: {e}", plan.program)))?;
            if status.success() {
                Ok(())
            } else {
                Err(Error::Message(format!("command exited with {status}")))
            }
        }
        HandoffMode::Exec => {
            let err = cmd.exec();
            Err(Error::Message(format!("exec {}: {err}", plan.program)))
        }
    }
}

pub fn launch_harness(paths: &Paths, harness: &Harness, opts: &LaunchOpts) -> Result<()> {
    let plan = build_launch_plan(paths, harness, opts)?;
    let handoff = opts.handoff.unwrap_or_else(HandoffMode::from_env);
    run_plan(&plan, handoff)
}

pub fn launch_run(
    paths: &Paths,
    manifest: &Path,
    backend: Backend,
    workdir: Option<&str>,
    command: &[String],
    token_source: TokenSource,
) -> Result<()> {
    let h = Harness {
        name: "run".into(),
        backend: Some(backend),
        manifest: manifest.display().to_string(),
        bin_dir: None,
        workdir: workdir.map(|s| s.to_string()),
        labels: false,
        keep: vec![],
        aliases: vec![],
        env_sets: vec![],
        command: command.to_vec(),
    };
    launch_harness(
        paths,
        &h,
        &LaunchOpts {
            token_source,
            extra_args: vec![],
            handoff: None,
        },
    )
}
