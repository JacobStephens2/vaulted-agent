//! Launch path: resolve → scrub env → drop tokens → exec (or spawn for tests).

use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::backend;
use crate::config::{Harness, Paths};
use crate::env_scrub::{build_child_env, MANAGER_TOKEN_VARS};
use crate::error::{Error, Result};
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

fn default_backend() -> String {
    env::var("VAULTED_AGENT_DEFAULT_BACKEND").unwrap_or_else(|_| "onepassword".into())
}

/// When set to "spawn", do not exec — spawn and wait (CLI acceptance tests).
fn handoff_mode_spawn() -> bool {
    matches!(
        env::var("VAULTED_AGENT_HANDOFF").as_deref(),
        Ok("spawn") | Ok("test")
    )
}

pub fn launch_harness(paths: &Paths, harness: &Harness) -> Result<()> {
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
        .unwrap_or_else(default_backend);
    let secrets: HashMap<String, SecretValue> = backend::resolve(&backend_name, &manifest)?;

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
            .unwrap_or(bin);
        child_env.insert(OsString::from("PATH"), OsString::from(path));
    }

    if cmdline.is_empty() {
        return Err(Error::Message("empty command".into()));
    }
    let program = cmdline.remove(0);
    let program = expand_home(&program);

    let mut cmd = Command::new(&program);
    cmd.args(&cmdline)
        .current_dir(&workdir)
        .env_clear()
        .envs(&child_env)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if handoff_mode_spawn() {
        let status = cmd.status().map_err(|e| Error::Message(format!(
            "failed to spawn {program}: {e}"
        )))?;
        if status.success() {
            Ok(())
        } else {
            Err(Error::Message(format!(
                "command exited with {status}"
            )))
        }
    } else {
        let err = cmd.exec();
        Err(Error::Message(format!("exec {program}: {err}")))
    }
}
