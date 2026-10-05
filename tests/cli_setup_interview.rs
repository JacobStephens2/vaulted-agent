//! Issue #158: the Setup interview checks the command line before anything is
//! written, and setup's no-backend auto-pick reads Token capture's doors.
//!
//! The interview itself (scripted replies, each menu's parse) is unit-tested in
//! `setup_interview`, the door rule in `auth`; this is the CLI seam.

mod common;

use common::CliSeam;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Output;

const OP_TOKEN: &str = "ops_eyJmYWtlIjoidG9rZW4ifQ";
const DAY_ONE: &str = "backend = plainfile\nmanifest = empty.env\ncommand = claude\n";
const DEFAULTS: &str = "auth_mode = file\n";

/// A vault CLI that refuses every token.
const REJECTING: &str = "#!/bin/sh\necho '[ERROR] invalid token' >&2\nexit 1\n";

fn day_one_seam() -> CliSeam {
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("defaults.conf"), DEFAULTS).unwrap();
    seam.write_harness("claude", DAY_ONE);
    seam
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn read(seam: &CliSeam, rel: &str) -> String {
    fs::read_to_string(seam.config_dir.join(rel)).unwrap()
}

#[test]
fn a_refused_command_line_writes_nothing() {
    for args in [
        &["setup", "frobnicate"][..],
        &["setup", "pass", "--set-token"],
        &["setup", "sops", "--set-token"],
    ] {
        let seam = day_one_seam();
        let out = seam.vaulted_agent().args(args).output().expect("run");
        let text = combined(&out);
        assert!(!out.status.success(), "{args:?}: {text}");
        assert!(
            !text.contains("vaulted-agent setup\n"),
            "{args:?} got as far as the header:\n{text}"
        );
        assert_eq!(read(&seam, "defaults.conf"), DEFAULTS, "{args:?}");
        assert_eq!(read(&seam, "harnesses.d/claude.conf"), DAY_ONE, "{args:?}");
    }
}

#[test]
fn an_empty_exported_var_and_a_keyless_token_file_pick_no_backend() {
    let seam = day_one_seam();
    fs::write(seam.config_dir.join("bws.env"), "OTHER=x\n").unwrap();
    let out = seam
        .vaulted_agent()
        .env("BWS_ACCESS_TOKEN", "")
        .env("OP_SERVICE_ACCOUNT_TOKEN", "")
        .args(["setup"])
        .output()
        .expect("run");
    let text = combined(&out);
    assert!(out.status.success(), "{text}");
    assert!(text.contains("No vault token yet"), "{text}");
    assert_eq!(read(&seam, "defaults.conf"), DEFAULTS);
    assert_eq!(read(&seam, "harnesses.d/claude.conf"), DAY_ONE);
}

#[test]
fn an_empty_bitwarden_var_falls_through_to_an_exported_onepassword_token() {
    let seam = day_one_seam();
    seam.write_executable("op", REJECTING);
    let out = seam
        .vaulted_agent()
        .env("BWS_ACCESS_TOKEN", "")
        .env("OP_SERVICE_ACCOUNT_TOKEN", OP_TOKEN)
        .args(["setup"])
        .output()
        .expect("run");
    let text = combined(&out);
    // Wired to 1Password, then the rejected token fails capture.
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("Vault wiring (onepassword)"), "{text}");
    assert!(
        read(&seam, "defaults.conf").contains("default_backend = onepassword"),
        "{text}"
    );
    assert!(!seam.config_dir.join("op.env").exists(), "{text}");
}

#[test]
fn an_unreadable_bitwarden_token_file_still_picks_bitwarden() {
    if is_root() {
        eprintln!("skipped: root reads any file");
        return;
    }
    let seam = day_one_seam();
    let bws = seam.config_dir.join("bws.env");
    fs::write(&bws, "BWS_ACCESS_TOKEN=0.x:y\n").unwrap();
    fs::set_permissions(&bws, fs::Permissions::from_mode(0o000)).unwrap();
    let out = seam
        .vaulted_agent()
        .env("OP_SERVICE_ACCOUNT_TOKEN", OP_TOKEN)
        .args(["setup"])
        .output()
        .expect("run");
    let text = combined(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("Vault wiring (bitwarden)"), "{text}");
    assert!(text.contains("cannot be read"), "{text}");
}

fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
}
