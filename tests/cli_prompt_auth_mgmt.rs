//! `-p` in front of a management command must reach it (issue #124).
//!
//! The launcher used to parse `-p` before `secrets` / `refresh` / `setup` and
//! then drop it, so only `VAULTED_AGENT_PROMPT_AUTH=1` forced a prompt there.
//! With a valid token file and no terminal, a forced prompt fails with "needs a
//! terminal"; reading the file instead would prove the flag was lost.

mod common;

use common::CliSeam;
use std::fs;
use std::process::{Command, Stdio};

fn seam() -> CliSeam {
    let seam = CliSeam::new();
    seam.install_fake_op();
    fs::write(
        seam.config_dir.join("manifests/m.env.tpl"),
        "A=op://Orchestrator/anthropic/conductor-api-key\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/probe.conf"),
        "backend = onepassword\nmanifest = m.env.tpl\ncommand = true\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = file\ndefault_backend = onepassword\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("op.env"),
        "OP_SERVICE_ACCOUNT_TOKEN=dummy\n",
    )
    .unwrap();
    seam
}

/// Run detached from any controlling terminal (`setsid`), so a prompt fails
/// fast instead of waiting on a developer's tty.
fn run(seam: &CliSeam, args: &[&str]) -> (bool, String) {
    let base = seam.vaulted_agent();
    let mut cmd = if Command::new("setsid").arg("true").status().is_ok() {
        let mut c = Command::new("setsid");
        c.arg(base.get_program());
        c
    } else {
        Command::new(base.get_program())
    };
    for (k, v) in base.get_envs() {
        match v {
            Some(v) => cmd.env(k, v),
            None => cmd.env_remove(k),
        };
    }
    if let Some(dir) = base.get_current_dir() {
        cmd.current_dir(dir);
    }
    let out = cmd
        .args(args)
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .env_remove("VAULTED_AGENT_PROMPT_AUTH")
        .env_remove("VAULTED_AGENT_AUTH_MODE")
        .stdin(Stdio::null())
        .output()
        .expect("vaulted-agent");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn prompt_flag_before_secrets_validate_forces_a_prompt() {
    let seam = seam();
    let (ok, out) = run(&seam, &["-p", "secrets", "validate", "probe"]);
    assert!(!ok, "-p must not fall back to the token file:\n{out}");
    assert!(out.contains("auth_mode=prompt needs a terminal"), "{out}");
}

#[test]
fn long_prompt_flag_before_secrets_validate_forces_a_prompt() {
    let seam = seam();
    let (ok, out) = run(&seam, &["--prompt-auth", "secrets", "validate", "probe"]);
    assert!(
        !ok,
        "--prompt-auth must not fall back to the token file:\n{out}"
    );
    assert!(out.contains("auth_mode=prompt needs a terminal"), "{out}");
}

#[test]
fn without_prompt_flag_secrets_validate_reads_the_token_file() {
    let seam = seam();
    let (ok, out) = run(&seam, &["secrets", "validate", "probe"]);
    assert!(ok, "{out}");
    assert!(out.contains("ok (1 variable(s) resolved)"), "{out}");
    assert!(!out.contains("needs a terminal"), "{out}");
}
