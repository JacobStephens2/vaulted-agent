//! Issue #149: `setup <backend>` runs Vault wiring before Token capture, and
//! `--wire-only` wires and stops there.
//!
//! The wiring rules themselves are unit-tested through the Vault wiring plan;
//! these cover the verb: the flag, its refusals, and the order against a
//! missing or rejected token.

mod common;

use common::CliSeam;
use std::fs;
use std::io::Write;
use std::process::{Command, Output, Stdio};

/// A shape-valid Bitwarden Secrets Manager access token (not a real one).
const BWS_TOKEN: &str = "0.11111111-1111-1111-1111-111111111111.clientsecret:enckey";

const DAY_ONE: &str = "backend = plainfile\nmanifest = empty.env\ncommand = claude\n";

/// A machine as install leaves it before vault setup: one day-one Harness.
fn day_one_seam() -> CliSeam {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = file\ndefault_backend = plainfile\n",
    )
    .unwrap();
    fs::write(seam.config_dir.join("manifests/empty.env"), "").unwrap();
    seam.write_harness("claude", DAY_ONE);
    seam
}

fn run_with_stdin(cmd: &mut Command, stdin: &str) -> Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn read(seam: &CliSeam, rel: &str) -> String {
    fs::read_to_string(seam.config_dir.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn assert_wired(seam: &CliSeam, backend: &str, refs: &str) {
    let conf = read(seam, "harnesses.d/claude.conf");
    assert!(conf.contains(&format!("backend = {backend}")), "{conf}");
    assert!(conf.contains(&format!("manifest = {refs}")), "{conf}");
    assert!(conf.contains("workdir = caller"), "{conf}");
    let defaults = read(seam, "defaults.conf");
    assert!(
        defaults.contains(&format!("default_backend = {backend}")),
        "{defaults}"
    );
    assert!(seam.config_dir.join("manifests").join(refs).is_file());
}

#[test]
fn wire_only_wires_and_never_touches_the_token() {
    let seam = day_one_seam();
    // Any vault call would fail loudly: wiring needs none.
    seam.write_executable("bws", "#!/bin/sh\necho 'bws called' >&2\nexit 1\n");

    let out = seam
        .vaulted_agent()
        .env("BWS_ACCESS_TOKEN", BWS_TOKEN)
        .args(["setup", "bitwarden", "--wire-only"])
        .output()
        .expect("run");
    let text = combined(&out);
    assert!(out.status.success(), "{text}");
    assert_wired(&seam, "bitwarden", "openai.env.refs");
    assert!(text.contains("wired claude.conf"), "{text}");
    assert!(!text.contains("bws called"), "{text}");
    assert!(!seam.config_dir.join("bws.env").exists());
}

#[test]
fn wire_only_twice_changes_nothing_the_second_time() {
    let seam = day_one_seam();
    let wire = || {
        seam.vaulted_agent()
            .args(["setup", "pass", "--wire-only"])
            .output()
            .expect("run")
    };
    assert!(wire().status.success());
    let before = read(&seam, "harnesses.d/claude.conf");
    let out = wire();
    assert!(out.status.success(), "{}", combined(&out));
    assert!(
        combined(&out).contains("nothing changed"),
        "{}",
        combined(&out)
    );
    assert_eq!(read(&seam, "harnesses.d/claude.conf"), before);
}

#[test]
fn the_starter_refs_file_passes_offline_validate_for_every_backend() {
    for (backend, refs) in [
        ("bitwarden", "openai.env.refs"),
        ("onepassword", "onepassword.refs"),
        ("pass", "pass.refs"),
    ] {
        let seam = day_one_seam();
        let out = seam
            .vaulted_agent()
            .args(["setup", backend, "--wire-only"])
            .output()
            .expect("run");
        assert!(out.status.success(), "{backend}: {}", combined(&out));
        assert_wired(&seam, backend, refs);

        let out = seam
            .vaulted_agent()
            .env("VAULTED_AGENT_NO_REEXEC", "1")
            .args(["secrets", "validate", "--offline"])
            .output()
            .expect("validate");
        assert!(out.status.success(), "{backend}: {}", combined(&out));
    }
}

#[test]
fn sops_records_the_default_backend_and_leaves_harnesses_alone() {
    let seam = day_one_seam();
    let out = seam
        .vaulted_agent()
        .args(["setup", "sops", "--wire-only"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", combined(&out));
    assert_eq!(read(&seam, "harnesses.d/claude.conf"), DAY_ONE);
    assert!(read(&seam, "defaults.conf").contains("default_backend = sops"));
    assert!(
        combined(&out).contains("left claude.conf"),
        "{}",
        combined(&out)
    );
}

#[test]
fn wire_only_with_set_token_is_refused() {
    let seam = day_one_seam();
    let out = run_with_stdin(
        seam.vaulted_agent()
            .args(["setup", "bitwarden", "--wire-only", "--set-token"]),
        &format!("{BWS_TOKEN}\n"),
    );
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(combined(&out).contains("--wire-only"), "{}", combined(&out));
    assert_eq!(read(&seam, "harnesses.d/claude.conf"), DAY_ONE);
    assert!(!seam.config_dir.join("bws.env").exists());
}

#[test]
fn wire_only_without_a_backend_is_refused() {
    let seam = day_one_seam();
    let out = seam
        .vaulted_agent()
        .env("BWS_ACCESS_TOKEN", BWS_TOKEN)
        .args(["setup", "--wire-only"])
        .output()
        .expect("run");
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(
        combined(&out).contains("name the backend"),
        "{}",
        combined(&out)
    );
    assert_eq!(read(&seam, "harnesses.d/claude.conf"), DAY_ONE);
}

#[test]
fn no_token_and_no_terminal_still_wires_then_fails_with_the_set_token_hint() {
    let seam = day_one_seam();
    let out = seam
        .vaulted_agent()
        .args(["setup", "bitwarden"])
        .output()
        .expect("run");
    let text = combined(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("--set-token"), "{text}");
    assert_wired(&seam, "bitwarden", "openai.env.refs");
    assert!(!seam.config_dir.join("bws.env").exists());
}

#[test]
fn a_rejected_token_still_wires_and_stores_nothing() {
    let seam = day_one_seam();
    seam.write_executable("bws", "#!/bin/sh\necho 'not authenticated' >&2\nexit 1\n");
    let out = run_with_stdin(
        seam.vaulted_agent()
            .args(["setup", "bitwarden", "--set-token"]),
        &format!("{BWS_TOKEN}\n"),
    );
    let text = combined(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("rejected by the vault"), "{text}");
    assert_wired(&seam, "bitwarden", "openai.env.refs");
    assert!(!seam.config_dir.join("bws.env").exists());
}

#[test]
fn setup_bitwarden_maps_secrets_into_the_wired_refs_file_and_reports_the_wiring() {
    let seam = day_one_seam();
    let secrets = seam.write_secrets_json("secrets.json", r#"{"OPENAI_API_KEY":"sk-x"}"#);
    seam.install_fake_bws(&secrets);
    let out = run_with_stdin(
        seam.vaulted_agent()
            .args(["setup", "bitwarden", "--set-token"]),
        &format!("{BWS_TOKEN}\n"),
    );
    let text = combined(&out);
    assert!(out.status.success(), "{text}");
    assert!(!text.contains("Point a harness at it"), "{text}");
    assert!(text.contains("wired claude.conf"), "{text}");
    assert_wired(&seam, "bitwarden", "openai.env.refs");
    let refs = read(&seam, "manifests/openai.env.refs");
    assert!(refs.contains("OPENAI_API_KEY="), "{refs}");
}

#[test]
fn setup_onepassword_no_longer_prints_an_example_harness() {
    let seam = day_one_seam();
    seam.install_fake_op();
    let out = run_with_stdin(
        seam.vaulted_agent()
            .args(["setup", "onepassword", "--set-token"]),
        "ops_eyJmYWtlIjoidG9rZW4ifQ\n",
    );
    let text = combined(&out);
    assert!(out.status.success(), "{text}");
    assert!(!text.contains("Example harness"), "{text}");
    assert_wired(&seam, "onepassword", "onepassword.refs");
}
