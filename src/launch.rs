//! Launch path: resolve → scrub env → drop tokens → plan → exec (or spawn for tests).

use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::auth::{self, TokenKind};
use crate::backend;
use crate::config::{load_default_backend, load_service_user, AuthMode, Backend, Harness, Paths};
use crate::env_scrub::{apply_aliases, build_child_env, MANAGER_TOKEN_VARS};
use crate::error::{Error, Result};
use crate::privilege;
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

/// True when the process can search (traverse) `path` — execute bit / ACL, not
/// necessarily list. `open()` would demand read permission and false-negative a
/// `setfacl …:x` fix (issue #56). Shared by launch preflight and doctor (#58).
#[cfg(unix)]
pub(crate) fn path_is_traversable(path: &Path) -> std::io::Result<()> {
    // `test -x` follows the same search rules as path resolution.
    let status = Command::new("test").arg("-x").arg(path).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Permission denied",
        ))
    }
}

#[cfg(not(unix))]
pub(crate) fn path_is_traversable(path: &Path) -> std::io::Result<()> {
    fs::metadata(path).map(|_| ())
}

/// Paths a `workdir = caller` launch is likely to need, for doctor probes.
/// Always includes the caller's cwd; when `SUDO_USER` is set (re-exec from an
/// operator), also their home directory.
pub(crate) fn caller_probe_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(c) = env::var("VAULTED_AGENT_CALLER_CWD") {
        if !c.is_empty() {
            out.push(PathBuf::from(c));
        }
    } else if let Ok(c) = env::current_dir() {
        out.push(c);
    }
    // After sudo -u service, HOME is usually the service account's. SUDO_USER
    // still names the operator; their home is the ordinary 0700 failure case.
    if let Ok(user) = env::var("SUDO_USER") {
        if let Some(home) = home_dir_for_user(&user) {
            if !out.iter().any(|p| p == &home) {
                out.push(home);
            }
        }
    }
    out
}

fn home_dir_for_user(user: &str) -> Option<PathBuf> {
    let out = Command::new("getent")
        .args(["passwd", user])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout);
    // name:x:uid:gid:gecos:home:shell
    let home = line.trim().split(':').nth(5)?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home))
}

/// Confirm the effective user can enter the resolved workdir before exec.
/// Bare exec EACCES names neither the directory, the account, nor the remedy.
pub(crate) fn ensure_workdir_usable(
    workdir: &Path,
    workdir_setting: Option<&str>,
    service_user: Option<&str>,
) -> Result<()> {
    match fs::metadata(workdir) {
        Ok(m) if !m.is_dir() => {
            return Err(Error::Message(format!(
                "workdir {} is not a directory",
                workdir.display()
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Message(format!(
                "workdir {} does not exist",
                workdir.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            // Fall through to the rich message below (cannot even stat).
        }
        Err(e) => {
            return Err(Error::Message(format!(
                "workdir {}: {e}",
                workdir.display()
            )));
        }
    }

    if path_is_traversable(workdir).is_ok() {
        return Ok(());
    }

    let who = privilege::current_user();
    let who = if who.is_empty() {
        "this process".to_string()
    } else {
        format!("`{who}`")
    };
    let mut msg = format!(
        "{who} cannot enter {} (Permission denied)",
        workdir.display()
    );

    let callerish = matches!(workdir_setting, None | Some("") | Some("caller"));
    if callerish {
        msg.push_str("\n  workdir resolved to your shell's cwd (workdir = caller)");
    } else if let Some(setting) = workdir_setting {
        msg.push_str(&format!("\n  workdir is set to `{setting}` in the harness"));
    }

    if let Some(svc) = service_user.filter(|s| !s.is_empty()) {
        msg.push_str(&format!(
            ", but agents run as `{svc}` (service_user), which has no traverse permission there.\n  \
             Fix one of:\n    \
             setfacl -m u:{svc}:x {wd}   # traverse only — does not allow listing\n    \
             launch from a directory {svc} can enter\n    \
             set an absolute `workdir` in the harness conf",
            wd = workdir.display()
        ));
    } else {
        msg.push_str(
            ".\n  Fix: grant this account execute (traverse) on the directory, or set an absolute \
             `workdir` the account can enter.",
        );
    }

    Err(Error::Message(msg))
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
        match backend::resolve(backend_name, &manifest, paths, token.as_ref()) {
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

    // Token is dropped from the launcher process env so it is not ambient.
    // Residual plaintext in this process's heap is out of scope for the threat
    // model (explicit child env is the boundary that matters).
    drop(token);
    for &name in MANAGER_TOKEN_VARS {
        env::remove_var(name);
    }

    let caller_cwd = env::current_dir().map_err(|e| Error::Message(format!("cwd: {e}")))?;
    let workdir = resolve_workdir(harness, &caller_cwd)?;
    // After the privilege hop (if any) this process *is* the effective launch
    // account. Fail here with a clear remedy rather than a bare exec EACCES
    // (issue #56).
    ensure_workdir_usable(
        &workdir,
        harness.workdir.as_deref(),
        load_service_user(paths).as_deref(),
    )?;

    // Per-harness renames after inject (issue #66). Mutates the secrets map
    // only; values are still never logged. Fail closed if a source is missing.
    apply_aliases(&mut secrets, &harness.aliases)?;

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

    // kimi 0.33–0.34 default to agent-core-v2 print mode, whose auth gate
    // ignores process.env (kimi-code#2745; fix #2746). Vault inject still works
    // with KIMI_CODE_LEGACY_FLAG=1 or on 0.32 / post-fix. Do not set if the
    // operator already put a value in keep/parent (or_insert). Issue #70.
    if agent_base == "kimi" {
        child_env
            .entry(OsString::from("KIMI_CODE_LEGACY_FLAG"))
            .or_insert_with(|| OsString::from("1"));
    }

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
        aliases: vec![],
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
            aliases: vec![],
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

    #[test]
    fn ensure_workdir_usable_accepts_traversable_dir() {
        let tmp = tempfile::tempdir().unwrap();
        ensure_workdir_usable(tmp.path(), Some("caller"), None).unwrap();
    }

    #[test]
    fn ensure_workdir_usable_reports_missing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope");
        let err = ensure_workdir_usable(&missing, Some("/srv/x"), None).unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn ensure_workdir_usable_names_service_user_on_permission_denied() {
        // Skip when root: chmod 000 does not stop root from traversing.
        let uid = Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
            })
            .unwrap_or(0);
        if uid == 0 {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let blocked = tmp.path().join("blocked");
        fs::create_dir(&blocked).unwrap();
        let mut perms = fs::metadata(&blocked).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o000);
        fs::set_permissions(&blocked, perms).unwrap();

        let err = ensure_workdir_usable(&blocked, Some("caller"), Some("conductor")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cannot enter"), "{msg}");
        assert!(msg.contains("conductor"), "{msg}");
        assert!(msg.contains("setfacl"), "{msg}");
        assert!(msg.contains("workdir = caller"), "{msg}");

        let mut perms = fs::metadata(&blocked).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&blocked, perms).unwrap();
    }
}
