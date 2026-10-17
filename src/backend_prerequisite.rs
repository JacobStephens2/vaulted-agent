//! Token-free executable checks for setup and doctor. Setup checks both the
//! account doing vault work and the account a launch will use after sudo.

use std::env;
use std::process::{Command, Stdio};

use crate::config::{Backend, Paths};
use crate::defaults::Defaults;
use crate::env_scrub::MANAGER_TOKEN_VARS;
use crate::error::Result;
use crate::privilege;

// No vault command runs: `command -v` alone can also find a non-executable
// file, so require an executable regular file as well. Names are arguments.
const CHECK: &str = "tool=$(command -v \"$1\") && [ -f \"$tool\" ] && [ -x \"$tool\" ]";

pub(crate) fn available(tool: &str) -> bool {
    probe(tool, None)
}

fn probe(tool: &str, account: Option<&str>) -> bool {
    let mut cmd = match account {
        Some(user) => {
            let mut cmd = Command::new("sudo");
            cmd.args(["-n", "-u", user, "--", "/bin/sh"]);
            cmd
        }
        None => Command::new("/bin/sh"),
    };
    cmd.args(["-c", CHECK, "sh", tool]);
    for name in MANAGER_TOKEN_VARS {
        cmd.env_remove(name);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// None means the selected Backend's executable was found in every required
/// context. The diagnostic is also the installer's wire-only outcome marker:
/// `Vault setup incomplete:` must remain present when a prerequisite fails.
pub(crate) fn diagnostic(paths: &Paths, backend: Backend) -> Result<Option<String>> {
    let Some(cli) = backend.required_cli() else {
        return Ok(None);
    };
    let tool = cli.executable;
    let current = privilege::current_user();
    let launch = Defaults::load(paths)?
        .service_user
        .or_else(|| {
            env::var("SUDO_USER")
                .ok()
                .filter(|u| current == "root" && !u.is_empty())
        })
        .unwrap_or_else(|| current.clone());
    let mut contexts = Vec::new();
    if !available(tool) {
        contexts.push(format!(
            "setup execution account {current:?} (current PATH)"
        ));
    }
    if launch != current && !probe(tool, Some(&launch)) {
        contexts.push(format!("launch account {launch:?} (sudo PATH; missing/non-executable tool or non-interactive sudo check denied)"));
    }
    if contexts.is_empty() {
        return Ok(None);
    }
    let name = cli.name;
    let url = cli.installation_url;
    Ok(Some(format!(
        "Vault setup incomplete: {backend} requires executable `{tool}` ({name}).\n  \
         Unavailable in: {}.\n  Install: {url}\n  \
         Put `{tool}` on PATH with execute/traverse permissions for both setup and the launch account.\n  \
         For sudo/Service-user launches, check with `sudo -u {launch} -- /bin/sh -c 'command -v {tool}'`; resolve sudo access if the check is denied.\n  \
         Then rerun `vaulted-agent setup {backend}`. No Manager token was requested or verified.",
        contexts.join("; ")
    )))
}
