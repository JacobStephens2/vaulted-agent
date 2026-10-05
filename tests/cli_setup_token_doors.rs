//! Issue #156: Token capture owns every way `setup` obtains a Manager token.
//!
//! The exported env var and the existing token file are doors like the paste
//! and the pipe: each is verified against the backend before anything is
//! stored, and a rejected one fails `setup` without touching the token file.
//! The decision table is unit-tested in `auth`; this is the CLI seam.

mod common;

use common::CliSeam;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Output;

const BWS_TOKEN: &str = "0.11111111-1111-1111-1111-111111111111.clientsecret:enckey";
const OP_TOKEN: &str = "ops_eyJmYWtlIjoidG9rZW4ifQ";

/// A vault CLI that refuses every token, the way a revoked one is refused.
const REJECTING: &str = "#!/bin/sh\necho '[ERROR] invalid token' >&2\nexit 1\n";

fn seam_with_auth_mode(auth_mode: &str) -> CliSeam {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        format!("auth_mode = {auth_mode}\n"),
    )
    .unwrap();
    seam
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_rejected_exported_onepassword_token_is_not_written() {
    let seam = seam_with_auth_mode("file");
    seam.write_executable("op", REJECTING);
    let out = seam
        .vaulted_agent()
        .env("OP_SERVICE_ACCOUNT_TOKEN", "garbage")
        .args(["setup", "onepassword"])
        .output()
        .expect("run");
    let text = combined(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("OP_SERVICE_ACCOUNT_TOKEN"), "{text}");
    assert!(text.contains("nothing written"), "{text}");
    assert!(
        !text.contains("garbage"),
        "token leaked into output:\n{text}"
    );
    assert!(!seam.config_dir.join("op.env").exists(), "{text}");
}

#[test]
fn a_rejected_exported_bitwarden_token_is_not_written() {
    let seam = seam_with_auth_mode("file");
    seam.write_executable("bws", REJECTING);
    let out = seam
        .vaulted_agent()
        .env("BWS_ACCESS_TOKEN", BWS_TOKEN)
        .args(["setup", "bitwarden"])
        .output()
        .expect("run");
    let text = combined(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("BWS_ACCESS_TOKEN"), "{text}");
    assert!(text.contains("nothing written"), "{text}");
    assert!(!seam.config_dir.join("bws.env").exists(), "{text}");
}

#[test]
fn a_rejected_exported_token_fails_in_prompt_mode_too() {
    let seam = seam_with_auth_mode("prompt");
    seam.write_executable("op", REJECTING);
    let out = seam
        .vaulted_agent()
        .env("OP_SERVICE_ACCOUNT_TOKEN", OP_TOKEN)
        .args(["setup", "onepassword"])
        .output()
        .expect("run");
    let text = combined(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("OP_SERVICE_ACCOUNT_TOKEN"), "{text}");
    assert!(!seam.config_dir.join("op.env").exists(), "{text}");
}

#[test]
fn a_rejected_token_file_fails_setup_and_is_left_byte_identical() {
    let seam = seam_with_auth_mode("file");
    seam.write_executable("op", REJECTING);
    let path = seam.config_dir.join("op.env");
    let body = format!("# rotated by hand\nOP_SERVICE_ACCOUNT_TOKEN={OP_TOKEN}\n");
    fs::write(&path, &body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let out = seam
        .vaulted_agent()
        .args(["setup", "onepassword"])
        .output()
        .expect("run");
    let text = combined(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("--set-token"), "{text}");
    assert!(text.contains("nothing written"), "{text}");
    assert_eq!(fs::read_to_string(&path).unwrap(), body);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600,
        "a rejected token file was touched"
    );
}

#[test]
fn a_working_token_file_is_verified_and_kept() {
    let seam = seam_with_auth_mode("file");
    seam.install_fake_op();
    let path = seam.config_dir.join("op.env");
    let body = format!("OP_SERVICE_ACCOUNT_TOKEN={OP_TOKEN}\n");
    fs::write(&path, &body).unwrap();

    let out = seam
        .vaulted_agent()
        .args(["setup", "onepassword"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", combined(&out));
    assert_eq!(fs::read_to_string(&path).unwrap(), body);
}

#[test]
fn setup_bitwarden_lists_the_vault_once() {
    let seam = seam_with_auth_mode("file");
    let secrets = seam.write_secrets_json("secrets.json", r#"{"OPENAI_API_KEY":"sk-x"}"#);
    let real = seam.install_fake_bws(&secrets);
    let real_bws = real.with_file_name("bws-real");
    fs::rename(&real, &real_bws).unwrap();
    let calls = seam.root.join("bws-calls");
    seam.write_executable(
        "bws",
        &format!(
            "#!/bin/sh\necho \"$*\" >> '{}'\nexec '{}' \"$@\"\n",
            calls.display(),
            real_bws.display()
        ),
    );

    let out = seam
        .vaulted_agent()
        .env("BWS_ACCESS_TOKEN", BWS_TOKEN)
        .args(["setup", "bitwarden"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", combined(&out));
    let log = fs::read_to_string(&calls).unwrap();
    assert_eq!(
        log.lines().filter(|l| l.starts_with("secret list")).count(),
        1,
        "{log}"
    );
}
