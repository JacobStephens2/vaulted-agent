//! Launch path: resolve → scrub env → drop tokens → plan → exec (or spawn for tests).

use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::auth::TokenSource;
use crate::backend;
use crate::config::{
    expand_home, load_default_backend, load_service_user, Backend, Harness, Paths,
};
use crate::env_scrub::{apply_aliases, build_child_env, MANAGER_TOKEN_VARS};
use crate::error::{Error, Result};
use crate::resume;
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

/// Pure launch plan: everything needed to start the agent without executing yet.
#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub program: String,
    pub args: Vec<String>,
    pub workdir: PathBuf,
    pub env: HashMap<OsString, OsString>,
}

/// Build scrub → resolve → drop token → child env + argv (composition seam).
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
    let mut secrets: HashMap<String, SecretValue> =
        match backend::resolve(backend_name, &manifest, paths, opts.token_source) {
            Ok(s) => s,
            Err(e) => {
                let blamed = crate::validate::blame_manifest_lines(&manifest, &format!("{e}"));
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

    // Per-harness renames after inject (issue #66). Mutates the secrets map
    // only; values are still never logged. Fail closed if a source is missing.
    apply_aliases(&mut secrets, &harness.aliases)?;

    let mut child_env = build_child_env(&harness.keep, &secrets);

    // Harness `env = NAME = value`: non-secret child vars (e.g. temporary
    // KIMI_CODE_LEGACY_FLAG on kimi.conf until kimi-code#2746). Not for secrets.
    for (k, v) in &harness.env_sets {
        if MANAGER_TOKEN_VARS.contains(&k.as_str()) {
            return Err(Error::Message(format!(
                "harness env cannot set manager-token name '{k}'"
            )));
        }
        child_env.insert(OsString::from(k.as_str()), OsString::from(v.as_str()));
    }

    let home = &caller.home;
    let mut cmdline = harness.command.clone();
    if let Some(bin) = &harness.bin_dir {
        let bin = expand_home(bin, home);
        let path = child_env
            .get(OsStr::new("PATH"))
            .map(|p| format!("{bin}:{}", p.to_string_lossy()))
            .unwrap_or_else(|| bin.clone());
        child_env.insert(OsString::from("PATH"), OsString::from(path));
    }

    if cmdline.is_empty() {
        return Err(Error::Message("empty command".into()));
    }
    let program = expand_home(&cmdline.remove(0), home);
    let agent_base = Path::new(&program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&program);

    let mut extra = opts.extra_args.clone();
    extra = resume::normalize_argv(agent_base, &extra, harness.labels)?;

    let mut args = cmdline;
    args.extend(extra);

    Ok(LaunchPlan {
        program,
        args,
        workdir,
        env: child_env,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::SecretValue;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn build_plan_injects_secret_excludes_manager_token() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        fs::create_dir_all(&paths.manifest_dir).unwrap();
        fs::write(
            paths.manifest_dir.join("m.env"),
            "APP_DB_PASS=\"secret-value\"\n",
        )
        .unwrap();

        // Absolute command path — no PATH mutation required for plan build.
        let agent = tmp.path().join("agent");
        fs::write(&agent, "#!/bin/sh\n").unwrap();
        let mut perms = fs::metadata(&agent).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&agent, perms).unwrap();

        env::set_var("BWS_ACCESS_TOKEN", "should-not-reach-child");

        let h = Harness {
            name: "h".into(),
            backend: Some(Backend::Plainfile),
            manifest: "m.env".into(),
            bin_dir: None,
            workdir: None,
            labels: false,
            keep: vec![],
            aliases: vec![],
            env_sets: vec![],
            command: vec![agent.display().to_string()],
        };
        let opts = LaunchOpts {
            token_source: TokenSource::decide(None, None, false, crate::config::AuthMode::File),
            extra_args: vec![],
            handoff: None,
        };
        let plan = build_launch_plan(&paths, &h, &opts).unwrap();
        assert_eq!(
            plan.env
                .get(OsStr::new("APP_DB_PASS"))
                .map(|s| s.to_string_lossy().into_owned()),
            Some("secret-value".into())
        );
        assert!(!plan.env.contains_key(OsStr::new("BWS_ACCESS_TOKEN")));
        assert_eq!(plan.program, agent.display().to_string());
        assert!(env::var_os("BWS_ACCESS_TOKEN").is_none());
        let _ = SecretValue::new("x");
    }
}
