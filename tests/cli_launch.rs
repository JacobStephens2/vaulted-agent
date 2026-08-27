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
fn bash_harness_appends_extra_args() {
    let seam = CliSeam::new();
    // Harness command is the stub name so the plan cannot resolve to /bin/bash.
    seam.install_stub_agent("va-bash-stub");
    fs::write(
        seam.config_dir.join("manifests/empty.env"),
        "APP_TOKEN=from-manifest\n",
    )
    .unwrap();
    write_plain_harness(&seam, "bash", "empty.env", "va-bash-stub");

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .args(["bash", "./script.sh", "--flag"])
        .output()
        .expect("launch");
    assert!(
        out.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let rec = seam.read_stub_record("va-bash-stub");
    assert!(
        rec.contains("ARGV:") && rec.contains("./script.sh") && rec.contains("--flag"),
        "extra args missing from child argv: {rec}"
    );
    assert!(rec.contains("ENV APP_TOKEN"), "{rec}");
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
    assert!(
        err.contains("applies to a harness launch") || err.contains("not to 'doctor'"),
        "{err}"
    );
}

#[test]
fn empty_manifest_override_is_rejected() {
    let seam = CliSeam::new();
    let out = seam
        .vaulted_agent()
        .args(["--manifest=", "claude"])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("non-empty"), "{err}");
}

#[test]
fn a_launch_that_cannot_resolve_names_the_variable_not_just_the_item() {
    // The failure an operator actually meets: an item renamed in the vault
    // leaves a well-formed reference that stops resolving, so nothing offline
    // catches it and the launch is where it surfaces. op names the item; the
    // manifest entry is what can be acted on.
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    seam.install_fake_op();
    fs::write(
        seam.config_dir.join("manifests/m.env.tpl"),
        "GOOD=op://Orchestrator/anthropic/conductor-api-key\n\
         GHOST=op://Orchestrator/renamed-away/password\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend  = onepassword\nmanifest = m.env.tpl\ncommand  = agent\n",
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

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("claude")
        .output()
        .expect("launch");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("GHOST"), "{err}");
    assert!(
        err.contains("op://Orchestrator/renamed-away/password"),
        "{err}"
    );
    // The one that resolves must not be blamed beside it.
    assert!(!err.contains("GOOD\n"), "{err}");
    // And it must point at the command that confirms a fix.
    assert!(err.contains("secrets validate"), "{err}");
    // Still a failed launch: the agent must not have run.
    assert!(!seam.work_dir.join("agent.record").exists());
}

#[test]
fn a_launch_that_resolves_says_nothing_extra() {
    // The blame block must not appear on a healthy launch.
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/ok.env"),
        "APP_DB_PASS=corr3ct\n",
    )
    .unwrap();
    write_plain_harness(&seam, "claude", "ok.env", "agent");
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("claude")
        .output()
        .expect("launch");
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("could not resolve"), "{err}");
    assert!(!err.contains("secrets validate"), "{err}");
}
