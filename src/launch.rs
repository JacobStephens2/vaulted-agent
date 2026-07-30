//! Launch path: resolve → scrub env → drop tokens → plan → exec (or spawn for tests).

use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::auth::{self, TokenKind};
use crate::backend;
use crate::config::{load_default_backend, AuthMode, Backend, Harness, Paths};
use crate::env_scrub::{build_child_env, MANAGER_TOKEN_VARS};
use crate::error::{Error, Result};
use crate::resume;
use crate::secret::SecretValue;

fn expand_home(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("$HOME") {
        let home = env::var("HOME").unwrap_or_default();
        return format!("{home}{rest}");
    }
    if let Some(rest) = s.strip_prefix("${HOME}") {
        let home = env::var("HOME").unwrap_or_default();
        return format!("{home}{rest}");
    }
    s.to_string()
}

fn resolve_workdir(harness: &Harness, caller_cwd: &Path) -> Result<PathBuf> {
    match harness.workdir.as_deref() {
        None | Some("") => Ok(caller_cwd.to_path_buf()),
        Some("caller") => {
            let c = env::var_os("VAULTED_AGENT_CALLER_CWD")
                .map(PathBuf::from)
                .unwrap_or_else(|| caller_cwd.to_path_buf());
            Ok(c)
        }
        Some(p) => Ok(PathBuf::from(expand_home(p))),
    }
}

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

pub fn force_prompt_from_env() -> bool {
    env::var_os("VAULTED_AGENT_PROMPT_AUTH").as_deref() == Some(OsStr::new("1"))
}

pub fn auth_mode_from_env_or_config(paths: &Paths) -> AuthMode {
    match env::var("VAULTED_AGENT_AUTH_MODE").as_deref() {
        Ok("prompt") => AuthMode::Prompt,
        Ok("file") => AuthMode::File,
        _ => crate::config::load_auth_mode(paths),
    }
}

#[derive(Default)]
pub struct LaunchOpts {
    pub force_prompt: bool,
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

    let mode = auth_mode_from_env_or_config(paths);
    let force = opts.force_prompt || force_prompt_from_env();

    let token = match backend_name {
        Backend::Bitwarden => Some(auth::load_manager_token(
            paths,
            mode,
            TokenKind::Bws,
            force,
        )?),
        Backend::OnePassword => Some(auth::load_manager_token(paths, mode, TokenKind::Op, force)?),
        Backend::Pass | Backend::Sops | Backend::Plainfile => None,
    };

    let secrets: HashMap<String, SecretValue> =
        backend::resolve(backend_name, &manifest, paths, token.as_ref())?;

    // Token is dropped from the launcher process env so it is not ambient.
    // Residual plaintext in this process's heap is out of scope for the threat
    // model (explicit child env is the boundary that matters).
    drop(token);
    for &name in MANAGER_TOKEN_VARS {
        env::remove_var(name);
    }

    let caller_cwd = env::current_dir().map_err(|e| Error::Message(format!("cwd: {e}")))?;
    let workdir = resolve_workdir(harness, &caller_cwd)?;

    let mut child_env = build_child_env(&harness.keep, &secrets);

    let mut cmdline = harness.command.clone();
    if let Some(bin) = &harness.bin_dir {
        let bin = expand_home(bin);
        let path = child_env
            .get(OsStr::new("PATH"))
            .map(|p| format!("{bin}:{}", p.to_string_lossy()))
            .unwrap_or_else(|| bin.clone());
        child_env.insert(OsString::from("PATH"), OsString::from(path));
    }

    if cmdline.is_empty() {
        return Err(Error::Message("empty command".into()));
    }
    let program = expand_home(&cmdline.remove(0));
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
    force_prompt: bool,
) -> Result<()> {
    let h = Harness {
        name: "run".into(),
        backend: Some(backend),
        manifest: manifest.display().to_string(),
        bin_dir: None,
        workdir: workdir.map(|s| s.to_string()),
        labels: false,
        keep: vec![],
        command: command.to_vec(),
    };
    launch_harness(
        paths,
        &h,
        &LaunchOpts {
            force_prompt,
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
            command: vec![agent.display().to_string()],
        };
        let plan = build_launch_plan(&paths, &h, &LaunchOpts::default()).unwrap();
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
