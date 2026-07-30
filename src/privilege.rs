//! Service-user privilege hop: pure plan + thin sudo adapter.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::Paths;
use crate::error::{Error, Result};

/// Pure decision for whether to re-exec under `service_user`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReexecDecision {
    Skip,
    Reexec {
        service: String,
        launcher: PathBuf,
        /// Env assignments passed via `sudo … env KEY=val …`.
        forward_env: Vec<(String, String)>,
        /// Original argv as typed (after argv0), for sudoers fidelity.
        argv: Vec<String>,
    },
}

/// Facts for planning re-exec (all injectable for unit tests).
#[derive(Debug, Clone)]
pub struct ReexecFacts {
    pub current_user: String,
    pub service_user: Option<String>,
    pub no_reexec: bool,
    pub argv0: String,
    pub bin_dir: String,
    pub caller_cwd: String,
    pub config_dir: Option<String>,
    /// Original operator argv (without argv0).
    pub orig_argv: Vec<String>,
}

impl ReexecFacts {
    pub fn from_runtime(paths: &Paths, argv0: &str, orig_argv: &[String]) -> Self {
        let current_user = Command::new("id")
            .arg("-un")
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        let service_user = crate::config::load_service_user(paths);
        let caller_cwd = env::var("VAULTED_AGENT_CALLER_CWD").unwrap_or_else(|_| {
            env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| ".".into())
        });
        let bin_dir = env::var("VAULTED_AGENT_BIN_DIR").unwrap_or_else(|_| "/usr/local/bin".into());
        let config_dir = env::var("VAULTED_AGENT_CONFIG_DIR").ok();
        Self {
            current_user,
            service_user,
            no_reexec: env::var_os("VAULTED_AGENT_NO_REEXEC").is_some(),
            argv0: argv0.to_string(),
            bin_dir,
            caller_cwd,
            config_dir,
            orig_argv: orig_argv.to_vec(),
        }
    }
}

fn resolve_launcher(argv0: &str, bin_dir: &str) -> PathBuf {
    let invoked = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("vaulted-agent");
    let launcher = PathBuf::from(bin_dir).join(invoked);
    if launcher.is_file() {
        launcher
    } else {
        PathBuf::from(argv0)
    }
}

/// Pure planning: no process spawn.
pub fn plan_service_user_reexec(facts: &ReexecFacts) -> ReexecDecision {
    let Some(service) = facts
        .service_user
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return ReexecDecision::Skip;
    };
    if facts.current_user == service {
        return ReexecDecision::Skip;
    }
    if facts.no_reexec {
        return ReexecDecision::Skip;
    }

    let launcher = resolve_launcher(&facts.argv0, &facts.bin_dir);
    let mut forward_env = vec![("VAULTED_AGENT_CALLER_CWD".into(), facts.caller_cwd.clone())];
    if let Some(c) = &facts.config_dir {
        forward_env.push(("VAULTED_AGENT_CONFIG_DIR".into(), c.clone()));
    }

    ReexecDecision::Reexec {
        service: service.to_string(),
        launcher,
        forward_env,
        argv: facts.orig_argv.clone(),
    }
}

/// Apply decision: Skip is a no-op; Reexec replaces the process via sudo.
pub fn apply_reexec(decision: ReexecDecision) -> Result<()> {
    match decision {
        ReexecDecision::Skip => Ok(()),
        ReexecDecision::Reexec {
            service,
            launcher,
            forward_env,
            argv,
        } => {
            let mut cmd = Command::new("sudo");
            cmd.arg("-u").arg(&service).arg("env");
            for (k, v) in &forward_env {
                cmd.arg(format!("{k}={v}"));
            }
            cmd.arg(&launcher);
            for a in &argv {
                cmd.arg(a);
            }
            let err = {
                use std::os::unix::process::CommandExt;
                cmd.exec()
            };
            Err(Error::Message(format!("sudo re-exec failed: {err}")))
        }
    }
}

/// Runtime entry used by main/commands: plan from live facts, then apply.
pub fn maybe_reexec_service_user(paths: &Paths, argv0: &str, orig_argv: &[String]) -> Result<()> {
    let facts = ReexecFacts::from_runtime(paths, argv0, orig_argv);
    apply_reexec(plan_service_user_reexec(&facts))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_facts() -> ReexecFacts {
        ReexecFacts {
            current_user: "alice".into(),
            service_user: Some("conductor".into()),
            no_reexec: false,
            argv0: "/usr/local/bin/vaulted-agent".into(),
            bin_dir: "/usr/local/bin".into(),
            caller_cwd: "/work".into(),
            config_dir: Some("/etc/vaulted-agent".into()),
            orig_argv: vec!["claude".into(), "--resume".into(), "x".into()],
        }
    }

    #[test]
    fn skip_when_no_service_user() {
        let mut f = base_facts();
        f.service_user = None;
        assert_eq!(plan_service_user_reexec(&f), ReexecDecision::Skip);
    }

    #[test]
    fn skip_when_already_service_user() {
        let mut f = base_facts();
        f.current_user = "conductor".into();
        assert_eq!(plan_service_user_reexec(&f), ReexecDecision::Skip);
    }

    #[test]
    fn skip_when_no_reexec_flag() {
        let mut f = base_facts();
        f.no_reexec = true;
        assert_eq!(plan_service_user_reexec(&f), ReexecDecision::Skip);
    }

    #[test]
    fn reexec_preserves_argv_and_forwards_env() {
        let f = base_facts();
        match plan_service_user_reexec(&f) {
            ReexecDecision::Reexec {
                service,
                launcher,
                forward_env,
                argv,
            } => {
                assert_eq!(service, "conductor");
                assert_eq!(launcher, PathBuf::from("/usr/local/bin/vaulted-agent"));
                assert!(forward_env
                    .iter()
                    .any(|(k, v)| k == "VAULTED_AGENT_CALLER_CWD" && v == "/work"));
                assert!(forward_env
                    .iter()
                    .any(|(k, v)| k == "VAULTED_AGENT_CONFIG_DIR" && v == "/etc/vaulted-agent"));
                assert_eq!(argv, vec!["claude", "--resume", "x"]);
            }
            other => panic!("expected Reexec, got {other:?}"),
        }
    }

    #[test]
    fn skip_empty_service_user() {
        let mut f = base_facts();
        f.service_user = Some("  ".into());
        assert_eq!(plan_service_user_reexec(&f), ReexecDecision::Skip);
    }
}
