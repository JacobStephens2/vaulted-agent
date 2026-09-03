//! `secrets validate` must cover every manifest the box reads, not only the
//! ones a harness launches from.
//!
//! The outage this pins: a host had a second manifest — `env.tpl`, read by its
//! systemd units and non-interactive scripts — that no harness pointed at. An
//! item was deleted from the vault, every unit reading that manifest
//! fail-closed, and `secrets validate` reported six green harnesses. The
//! documented gate for exactly this fault said everything was fine.

mod common;

use common::CliSeam;
use std::fs;

/// A seam with one harness (`probe`) and whatever extra manifests the caller
/// records in defaults.conf.
fn seam_with(harness_manifest: &str, extra_defaults: &str) -> CliSeam {
    let seam = CliSeam::new();
    seam.install_fake_op();
    fs::write(
        seam.config_dir.join("manifests/m.env.tpl"),
        harness_manifest,
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/probe.conf"),
        "backend = onepassword\nmanifest = m.env.tpl\ncommand = true\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        format!("auth_mode = file\ndefault_backend = onepassword\n{extra_defaults}"),
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("op.env"),
        "OP_SERVICE_ACCOUNT_TOKEN=dummy\n",
    )
    .unwrap();
    seam
}

fn validate(seam: &CliSeam, args: &[&str]) -> (bool, String) {
    let mut a = vec!["secrets", "validate"];
    a.extend_from_slice(args);
    let out = seam
        .vaulted_agent()
        .args(&a)
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("validate");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// Write an out-of-tree manifest, the way `env.tpl` sits outside /etc.
fn extra_manifest(seam: &CliSeam, name: &str, text: &str) -> String {
    let p = seam.root.join(name);
    fs::write(&p, text).unwrap();
    p.display().to_string()
}

#[test]
fn a_dead_reference_in_an_extra_manifest_fails_the_whole_check() {
    let seam = seam_with("A=op://Orchestrator/anthropic/conductor-api-key\n", "");
    let env_tpl = extra_manifest(
        &seam,
        "env.tpl",
        "LIVE=op://Orchestrator/anthropic/conductor-api-key\n\
         CLOUD_BEAVER_DB_ADMIN_PASSWORD=op://Orchestrator/db-admin/password\n",
    );
    fs::write(
        seam.config_dir.join("defaults.conf"),
        format!("auth_mode = file\ndefault_backend = onepassword\nextra_manifest = {env_tpl}\n"),
    )
    .unwrap();

    let (ok, out) = validate(&seam, &[]);
    assert!(!ok, "a dead ref anywhere must exit non-zero:\n{out}");
    // The variable is what the operator greps for...
    assert!(out.contains("CLOUD_BEAVER_DB_ADMIN_PASSWORD"), "{out}");
    // ...and the manifest is what tells them where to fix it, since the
    // remedy differs between a va manifest and env.tpl.
    assert!(out.contains(&env_tpl), "{out}");
    // The harness that is genuinely fine still reports fine.
    assert!(out.contains("probe"), "{out}");
}

#[test]
fn a_clean_run_names_every_manifest_it_checked() {
    // "Green" has to be readable as coverage, not as an absence of news: the
    // operator must be able to see that env.tpl was one of the files checked.
    let seam = seam_with("A=op://Orchestrator/anthropic/conductor-api-key\n", "");
    let env_tpl = extra_manifest(
        &seam,
        "env.tpl",
        "LIVE=op://Orchestrator/bare item/password\n",
    );
    fs::write(
        seam.config_dir.join("defaults.conf"),
        format!("auth_mode = file\ndefault_backend = onepassword\nextra_manifest = {env_tpl}\n"),
    )
    .unwrap();

    let (ok, out) = validate(&seam, &[]);
    assert!(ok, "{out}");
    assert!(out.contains(&env_tpl), "{out}");
    assert!(out.contains("1 variable(s) resolved"), "{out}");
    // Each harness names the manifest it launches from, so six harnesses over
    // one file cannot be mistaken for six files checked.
    assert!(out.contains("m.env.tpl"), "{out}");
}

#[test]
fn offline_covers_the_extra_manifest_for_the_faults_it_does_catch() {
    let seam = seam_with("A=op://Orchestrator/anthropic/conductor-api-key\n", "");
    let env_tpl = extra_manifest(&seam, "env.tpl", "BAD-NAME=op://Orchestrator/anthropic/x\n");
    fs::write(
        seam.config_dir.join("defaults.conf"),
        format!("auth_mode = file\ndefault_backend = onepassword\nextra_manifest = {env_tpl}\n"),
    )
    .unwrap();

    let (ok, out) = validate(&seam, &["--offline"]);
    assert!(!ok, "a syntax fault must fail offline too:\n{out}");
    assert!(out.contains(&env_tpl), "{out}");
    assert!(out.contains("vault not probed"), "{out}");
}

#[test]
fn an_extra_manifest_that_is_not_on_disk_is_a_failure_not_a_skip() {
    // A manifest the box reads and that is missing is the same outage as one
    // that will not resolve. Silently skipping it is how the gate fails open.
    let seam = seam_with("A=op://Orchestrator/anthropic/conductor-api-key\n", "");
    let missing = seam.root.join("gone.tpl");
    fs::write(
        seam.config_dir.join("defaults.conf"),
        format!(
            "auth_mode = file\ndefault_backend = onepassword\nextra_manifest = {}\n",
            missing.display()
        ),
    )
    .unwrap();

    let (ok, out) = validate(&seam, &[]);
    assert!(!ok, "{out}");
    assert!(out.contains("gone.tpl"), "{out}");
}

#[test]
fn several_extra_manifests_are_all_checked() {
    let seam = seam_with("A=op://Orchestrator/anthropic/conductor-api-key\n", "");
    let one = extra_manifest(&seam, "env.tpl", "A=op://Orchestrator/bare item/password\n");
    let two = extra_manifest(
        &seam,
        "other.tpl",
        "B=op://Orchestrator/renamed-away/password\n",
    );
    fs::write(
        seam.config_dir.join("defaults.conf"),
        format!(
            "auth_mode = file\ndefault_backend = onepassword\n\
             extra_manifest = {one}\nextra_manifest = {two}\n"
        ),
    )
    .unwrap();

    let (ok, out) = validate(&seam, &[]);
    assert!(!ok, "{out}");
    assert!(out.contains(&one), "{out}");
    assert!(out.contains(&two), "{out}");
    assert!(out.contains("renamed-away"), "{out}");
}

#[test]
fn an_extra_manifest_can_name_its_own_backend() {
    // env.tpl is 1Password here, but the concept is not: a box may read a
    // plainfile manifest as well, and a wrong default must not be assumed.
    let seam = seam_with("A=op://Orchestrator/anthropic/conductor-api-key\n", "");
    let plain = extra_manifest(&seam, "plain.env", "A=hunter2\n");
    fs::write(
        seam.config_dir.join("defaults.conf"),
        format!(
            "auth_mode = file\ndefault_backend = onepassword\nextra_manifest = {plain} = plainfile\n"
        ),
    )
    .unwrap();

    let (ok, out) = validate(&seam, &[]);
    assert!(ok, "{out}");
    assert!(out.contains(&plain), "{out}");
}

#[test]
fn an_extra_manifest_is_not_a_harness() {
    // The manifest set is first-class, not a seventh fake harness: nothing
    // about it should make it launchable or listable as one.
    let seam = seam_with("A=op://Orchestrator/anthropic/conductor-api-key\n", "");
    let env_tpl = extra_manifest(&seam, "env.tpl", "A=op://Orchestrator/bare item/password\n");
    fs::write(
        seam.config_dir.join("defaults.conf"),
        format!("auth_mode = file\ndefault_backend = onepassword\nextra_manifest = {env_tpl}\n"),
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .args(["secrets", "which"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("which");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.contains("probe"), "{text}");
    assert!(
        !text.contains(&env_tpl),
        "extra manifests are not harnesses:\n{text}"
    );
}

#[test]
fn a_bad_extra_manifest_line_is_rejected_rather_than_ignored() {
    let seam = seam_with("A=op://Orchestrator/anthropic/conductor-api-key\n", "");
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = file\ndefault_backend = onepassword\nextra_manifest = /tmp/x = nosuchbackend\n",
    )
    .unwrap();

    let (ok, out) = validate(&seam, &[]);
    assert!(!ok, "{out}");
    assert!(out.contains("nosuchbackend"), "{out}");
}
