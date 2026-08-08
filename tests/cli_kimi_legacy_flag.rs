//! Issue #70: kimi child env gets KIMI_CODE_LEGACY_FLAG=1 for 0.33–0.34 gate.

mod common;

use common::CliSeam;
use std::fs;

#[test]
fn kimi_launch_sets_legacy_flag_when_unset() {
    let seam = CliSeam::new();
    seam.install_stub_agent("kimi");
    fs::write(
        seam.config_dir.join("manifests/m.env"),
        "OPENAI_API_KEY=from-vault\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/kimi.conf"),
        "backend = plainfile\nmanifest = m.env\ncommand = kimi --auto\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("kimi")
        .output()
        .expect("launch");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("kimi");
    assert!(
        rec.contains("ENV KIMI_CODE_LEGACY_FLAG=1"),
        "launcher must set LEGACY flag for kimi 0.33–0.34 gate:\n{rec}"
    );
    assert!(
        rec.contains("ENV OPENAI_API_KEY=from-vault"),
        "vault inject still applies:\n{rec}"
    );
}

#[test]
fn non_kimi_launch_does_not_set_legacy_flag() {
    let seam = CliSeam::new();
    seam.install_stub_agent("claude");
    fs::write(seam.config_dir.join("manifests/m.env"), "X=1\n").unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = plainfile\nmanifest = m.env\ncommand = claude\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("claude")
        .output()
        .expect("launch");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("claude");
    assert!(
        !rec.contains("KIMI_CODE_LEGACY_FLAG"),
        "must not set kimi flag for other agents:\n{rec}"
    );
}
