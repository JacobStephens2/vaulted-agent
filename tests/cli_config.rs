mod common;

use common::CliSeam;
use std::fs;

#[test]
fn unknown_harness_fails_closed_with_message() {
    let seam = CliSeam::new();
    let out = seam
        .vaulted_agent()
        .arg("nope")
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unknown harness") || err.contains("nope"), "{err}");
}

#[test]
fn loads_and_launches_plainfile_harness_with_true() {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend  = plainfile\nmanifest = empty.env\ncommand  = true\n",
    )
    .unwrap();
    fs::write(seam.config_dir.join("manifests/empty.env"), "# empty\n").unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("claude")
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn auth_mode_show_reads_defaults_conf() {
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("defaults.conf"), "auth_mode = prompt\n").unwrap();
    let out = seam
        .vaulted_agent()
        .args(["auth-mode", "show"])
        .output()
        .expect("run");
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("auth_mode=prompt"), "{stdout}");
}
