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

#[test]
fn manifest_override_swaps_which_secrets_reach_the_agent() {
    // `va -m other.env claude` — the harness still decides the command, the
    // workdir and the backend; only which credentials it carries changes.
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/wide.env"),
        "APP_DB_PASS=corr3ct\nGH_TOKEN=ghp_example\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("manifests/narrow.env"),
        "REPORTING_DB_PASS=readonly\n",
    )
    .unwrap();
    write_plain_harness(&seam, "claude", "wide.env", "agent");

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .args(["-m", "narrow.env", "claude"])
        .output()
        .expect("launch");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let rec = seam.read_stub_record("agent");
    assert!(rec.contains("ENV REPORTING_DB_PASS"), "{rec}");
    // The harness default must be gone, not merged with the override.
    assert!(!rec.contains("ENV APP_DB_PASS"), "{rec}");
    assert!(!rec.contains("ENV GH_TOKEN"), "{rec}");

    // Announced, so a scrollback search can find which launch was overridden.
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("narrow.env"), "{err}");
}

#[test]
fn manifest_override_accepts_the_long_and_inline_spellings() {
    for args in [
        vec!["--manifest", "narrow.env", "claude"],
        vec!["--manifest=narrow.env", "claude"],
    ] {
        let seam = CliSeam::new();
        seam.install_stub_agent("agent");
        fs::write(seam.config_dir.join("manifests/wide.env"), "A=1\n").unwrap();
        fs::write(seam.config_dir.join("manifests/narrow.env"), "B=2\n").unwrap();
        write_plain_harness(&seam, "claude", "wide.env", "agent");

        let out = seam
            .vaulted_agent()
            .env("VAULTED_AGENT_HANDOFF", "spawn")
            .args(&args)
            .output()
            .expect("launch");
        assert!(out.status.success(), "{args:?}");
        let rec = seam.read_stub_record("agent");
        assert!(rec.contains("ENV B"), "{args:?} {rec}");
        assert!(!rec.contains("ENV A"), "{args:?} {rec}");
    }
}

#[test]
fn a_missing_override_manifest_fails_before_the_agent_starts() {
    // Otherwise the manifest reads as empty and the agent launches with nothing
    // in its environment, failing later for reasons that look unrelated.
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(seam.config_dir.join("manifests/wide.env"), "A=1\n").unwrap();
    write_plain_harness(&seam, "claude", "wide.env", "agent");

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .args(["-m", "typo.env", "claude"])
        .output()
        .expect("launch");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no manifest at"), "{err}");
    assert!(!seam.work_dir.join("agent.record").exists());
}

#[test]
fn manifest_override_is_refused_in_front_of_a_management_command() {
    // `run` and `refresh` read their own -m after the command name; a launcher
    // -m in front would be read by neither and silently do nothing.
    let seam = CliSeam::new();
    let out = seam
        .vaulted_agent()
        .args(["-m", "some.env", "doctor"])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("applies to a harness launch"), "{err}");
}
