//! `secrets validate` must ask the vault, not just read the file.
//!
//! A reference can be perfectly well-formed and name an item that no longer
//! exists — after a rename, say. The shape check passed, validate printed "ok",
//! and every launch then failed. CONTEXT.md calls this command the pre-flight
//! gate that must not fail open, so these pin that it does not.

mod common;

use common::CliSeam;
use std::fs;

fn seam_with(manifest: &str) -> CliSeam {
    let seam = CliSeam::new();
    seam.install_fake_op();
    fs::write(seam.config_dir.join("manifests/m.env.tpl"), manifest).unwrap();
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

#[test]
fn a_reference_to_a_missing_item_fails_and_names_the_variable() {
    // The exact shape of the outage: well-formed, unresolvable.
    let seam = seam_with(
        "GOOD=op://Orchestrator/anthropic/conductor-api-key\n\
         GHOST=op://Orchestrator/renamed-away/password\n",
    );
    let (ok, out) = validate(&seam, &["m.env.tpl"]);
    assert!(
        !ok,
        "validate must fail on an unresolvable reference:\n{out}"
    );
    // The item is what op names; the variable is what the operator can act on.
    assert!(out.contains("GHOST"), "{out}");
    assert!(
        out.contains("op://Orchestrator/renamed-away/password"),
        "{out}"
    );
    // The one that is fine must not be blamed alongside it.
    assert!(!out.contains("GOOD\n"), "{out}");
}

#[test]
fn a_resolvable_manifest_passes_and_says_how_many() {
    let seam = seam_with(
        "A=op://Orchestrator/anthropic/conductor-api-key\n\
         B=op://Orchestrator/bare item/password\n",
    );
    let (ok, out) = validate(&seam, &["m.env.tpl"]);
    assert!(ok, "{out}");
    assert!(out.contains("2 reference(s) resolved"), "{out}");
}

#[test]
fn resolved_values_never_reach_the_output() {
    // A validate command that printed secrets would be a worse bug than the one
    // it fixes. The fake op returns a marker value; it must not appear.
    let seam = seam_with("A=op://Orchestrator/anthropic/conductor-api-key\n");
    let (ok, out) = validate(&seam, &["m.env.tpl"]);
    assert!(ok, "{out}");
    assert!(!out.contains("fake-value"), "secret value leaked:\n{out}");
}

#[test]
fn offline_keeps_the_cheap_check_for_hosts_without_a_token() {
    let seam = seam_with("GHOST=op://Orchestrator/renamed-away/password\n");
    let (ok, out) = validate(&seam, &["m.env.tpl", "--offline"]);
    assert!(ok, "offline must not consult the vault:\n{out}");
    assert!(out.contains("vault not probed"), "{out}");
}

#[test]
fn validating_every_harness_resolves_each_one() {
    let seam = seam_with("A=op://Orchestrator/anthropic/conductor-api-key\n");
    let (ok, out) = validate(&seam, &[]);
    assert!(ok, "{out}");
    assert!(out.contains("probe: ok (1 reference(s) resolved)"), "{out}");
}
