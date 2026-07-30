mod common;

use common::CliSeam;
use std::fs;

fn write_plain_harness(seam: &CliSeam, name: &str, manifest: &str, command: &str) {
    fs::write(
        seam.config_dir.join(format!("harnesses.d/{name}.conf")),
        format!("backend  = plainfile\nmanifest = {manifest}\ncommand  = {command}\n"),
    )
    .unwrap();
}

#[test]
fn plainfile_launch_injects_only_manifest_secrets() {
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/full.env"),
        "APP_DB_PASS=corr3ct\nGH_TOKEN=ghp_example\n",
    )
    .unwrap();
    write_plain_harness(&seam, "claude", "full.env", "agent");

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .env("PARENT_ONLY_SECRET", "must-not-appear")
        .env("BWS_ACCESS_TOKEN", "manager-must-not-appear")
        .arg("claude")
        .output()
        .expect("launch");
    assert!(
        out.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let rec = seam.read_stub_record("agent");
    assert!(rec.contains("ENV APP_DB_PASS"), "{rec}");
    assert!(rec.contains("ENV GH_TOKEN"), "{rec}");
    assert!(
        !rec.contains("PARENT_ONLY_SECRET"),
        "parent secret leaked: {rec}"
    );
    assert!(
        !rec.contains("BWS_ACCESS_TOKEN"),
        "manager token leaked: {rec}"
    );
}

#[test]
fn narrow_manifest_omits_secrets_not_named() {
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/readonly.env"),
        "APP_DB_PASS=readonly-only\n",
    )
    .unwrap();
    write_plain_harness(&seam, "grok", "readonly.env", "agent");

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("grok")
        .output()
        .expect("launch");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("agent");
    assert!(rec.contains("ENV APP_DB_PASS"), "{rec}");
    assert!(!rec.contains("GH_TOKEN"), "{rec}");
}

#[test]
fn missing_manifest_fails_closed() {
    let seam = CliSeam::new();
    write_plain_harness(&seam, "broken", "does-not-exist.env", "true");
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("broken")
        .output()
        .expect("launch");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("manifest") || err.contains("not found") || err.contains("No such"),
        "{err}"
    );
}
