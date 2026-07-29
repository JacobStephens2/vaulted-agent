//! Launch path: resolve → scrub env → drop tokens → exec (or spawn for tests).

use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::auth::{self, TokenKind};
use crate::backend;
use crate::config::{AuthMode, Harness, Paths, load_auth_mode};
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

fn default_backend(paths: &Paths) -> String {
    crate::config::load_default_backend(paths)
}

fn handoff_mode_spawn() -> bool {
    matches!(
        env::var("VAULTED_AGENT_HANDOFF").as_deref(),
        Ok("spawn") | Ok("test")
    )
}

fn force_prompt_from_env() -> bool {
    env::var_os("VAULTED_AGENT_PROMPT_AUTH").as_deref() == Some(std::ffi::OsStr::new("1"))
}

pub struct LaunchOpts {
    pub force_prompt: bool,
    pub extra_args: Vec<String>,
}

impl Default for LaunchOpts {
    fn default() -> Self {
        Self {
            force_prompt: false,
            extra_args: Vec::new(),
        }
    }
}

pub fn launch_harness(paths: &Paths, harness: &Harness, opts: &LaunchOpts) -> Result<()> {
    let manifest = harness.resolve_manifest_path(paths);
    if !manifest.is_file() {
        return Err(Error::Io {
            path: manifest,
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "manifest not found"),
        });
    }

    let backend_name = harness
        .backend
        .clone()
        .unwrap_or_else(|| default_backend(paths));

    let mode = match env::var("VAULTED_AGENT_AUTH_MODE").as_deref() {
        Ok("prompt") => AuthMode::Prompt,
        Ok("file") => AuthMode::File,
        _ => load_auth_mode(paths),
    };
    let force = opts.force_prompt || force_prompt_from_env();

    let token = match backend_name.as_str() {
        "bitwarden" => Some(auth::load_manager_token(
            paths,
            mode,
            TokenKind::Bws,
            force,
        )?),
        "onepassword" => Some(auth::load_manager_token(
            paths,
            mode,
            TokenKind::Op,
            force,
        )?),
        _ => None,
    };

    let secrets: HashMap<String, SecretValue> =
        backend::resolve(&backend_name, &manifest, paths, token.as_ref())?;

    // Drop token from process env after resolve (best-effort)
    drop(token);
    for &name in MANAGER_TOKEN_VARS {
        env::remove_var(name);
    }

    let caller_cwd = env::current_dir().map_err(|e| Error::Message(format!("cwd: {e}")))?;
    let workdir = resolve_workdir(harness, &caller_cwd)?;

    let mut child_env = build_child_env(&harness.keep, &secrets);
    for &name in MANAGER_TOKEN_VARS {
        child_env.remove(std::ffi::OsStr::new(name));
    }

    let mut cmdline = harness.command.clone();
    if let Some(bin) = &harness.bin_dir {
        let bin = expand_home(bin);
        let path = child_env
            .get(std::ffi::OsStr::new("PATH"))
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
    extra = resume::normalize_argv(agent_base, &extra, harness.labels);

    let mut cmd = Command::new(&program);
    cmd.args(&cmdline)
        .args(&extra)
        .current_dir(&workdir)
        .env_clear()
        .envs(&child_env)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if handoff_mode_spawn() {
        let status = cmd
            .status()
            .map_err(|e| Error::Message(format!("failed to spawn {program}: {e}")))?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::Message(format!("command exited with {status}")))
        }
    } else {
        let err = cmd.exec();
        Err(Error::Message(format!("exec {program}: {err}")))
    }
}

pub fn launch_run(
    paths: &Paths,
    manifest: &Path,
    backend: &str,
    workdir: Option<&str>,
    command: &[String],
    force_prompt: bool,
) -> Result<()> {
    let h = Harness {
        name: "run".into(),
        backend: Some(backend.into()),
        manifest: manifest.display().to_string(),
        bin_dir: None,
        workdir: workdir.map(|s| s.to_string()),
        labels: false,
        keep: vec![],
        command: command.to_vec(),
    };
    // For run, manifest may be absolute already
    let mut h = h;
    if manifest.is_absolute() {
        h.manifest = manifest.display().to_string();
    }
    launch_harness(
        paths,
        &h,
        &LaunchOpts {
            force_prompt,
            extra_args: vec![],
        },
    )
}
