//! doctor must flag a manifest wired to an agent that cannot read it.
//!
//! Kimi Code takes a custom provider's key only from its own config file, so a
//! manifest on that harness resolves and injects perfectly into a child that
//! never looks. Every existing check passes — the file parses, the references
//! are well formed, the backend tool is present — and the report says healthy
//! right up until the agent fails with `provider … has no credential
//! configured`. This is the inverse of the empty-manifest warning: there the
//! harness has no secrets and says so, here it has secrets that cannot apply
//! (issue #68).

mod common;

use common::CliSeam;
use std::fs;

/// `command` is what the check keys on, not the harness name, so each case
/// varies exactly that.
fn seam_with(manifest: &str, command: &str) -> CliSeam {
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("manifests/m.env"), manifest).unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/probe.conf"),
        format!("backend = plainfile\nmanifest = m.env\ncommand = {command}\n"),
    )
    .unwrap();
    fs::write(seam.config_dir.join("defaults.conf"), "auth_mode = file\n").unwrap();
    seam
}

fn doctor(seam: &CliSeam) -> String {
    let out = seam
        .vaulted_agent()
        .args(["doctor"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("doctor");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_manifest_on_an_env_blind_agent_warns() {
    let seam = seam_with("FIREWORKS_API_KEY=fw_placeholder\n", "kimi --auto");
    let out = doctor(&seam);
    assert!(
        out.contains("does not read credentials from its environment"),
        "{out}"
    );
    assert!(out.contains("kimi"), "{out}");
    // It must count, not just print: the summary is what gets read.
    assert!(!out.contains("0 warning(s)"), "{out}");
    // A warning, never an error — the config is legal, just futile.
    assert!(out.contains("0 error(s)"), "{out}");
}

#[test]
fn the_command_may_be_an_absolute_path() {
    // install.sh writes `bin = <dir>` and a bare command, but a hand-edited
    // harness routinely names the binary outright. Keying on the basename is
    // the whole reason the check takes the command rather than the file name.
    let seam = seam_with(
        "FIREWORKS_API_KEY=fw_placeholder\n",
        "/home/agent/.kimi-code/bin/kimi --auto",
    );
    let out = doctor(&seam);
    assert!(
        out.contains("does not read credentials from its environment"),
        "{out}"
    );
}

#[test]
fn an_env_blind_agent_on_an_empty_manifest_is_not_flagged() {
    // The shipped shape. Pointing kimi at empty.env is the recommended fix, so
    // it must not warn about the very thing the fix does — the existing
    // "defines no variables" warning already covers a manifest with nothing in
    // it, and saying both would read as two problems.
    let seam = seam_with("# no variables here\n", "kimi --auto");
    let out = doctor(&seam);
    assert!(
        !out.contains("does not read credentials from its environment"),
        "{out}"
    );
    assert!(out.contains("manifest defines no variables"), "{out}");
}

#[test]
fn agents_that_do_read_the_environment_are_left_alone() {
    // The false positive that would make this check unusable: claude, codex and
    // grok all take credentials from the environment, which is the whole point
    // of the launcher. Only a named env-blind binary may be flagged.
    for command in ["claude --permission-mode auto", "codex", "grok"] {
        let seam = seam_with("ANTHROPIC_API_KEY=sk-placeholder\n", command);
        let out = doctor(&seam);
        assert!(
            !out.contains("does not read credentials from its environment"),
            "{command} must not be flagged:\n{out}"
        );
        assert!(out.contains("manifest syntax ok"), "{out}");
    }
}
