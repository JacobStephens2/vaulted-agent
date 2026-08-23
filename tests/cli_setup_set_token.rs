//! Issue #77: `setup` captures and stores the manager token.
//!
//! The CLI is the acceptance seam. The decision table itself is unit-tested in
//! `auth`; these cover the piped door (`--set-token`), the non-TTY error text,
//! and the states capture must leave alone.

mod common;

use common::CliSeam;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};

/// A shape-valid Bitwarden Secrets Manager access token (not a real one).
const BWS_TOKEN: &str = "0.11111111-1111-1111-1111-111111111111.clientsecret:enckey";

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        })
        .unwrap_or(1)
        == 0
}

/// Run the launcher with `stdin` piped in, the way an operator pipes a token.
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

fn file_mode_seam(auth_mode: &str) -> CliSeam {
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
fn set_token_writes_the_verified_token() {
    let seam = file_mode_seam("file");
    let secrets = seam.write_secrets_json("secrets.json", r#"{"OPENAI_API_KEY":"sk-x"}"#);
    seam.install_fake_bws(&secrets);

    let out = run_with_stdin(
        seam.vaulted_agent()
            .args(["setup", "bitwarden", "--set-token"]),
        &format!("{BWS_TOKEN}\n"),
    );
    assert!(out.status.success(), "{}", combined(&out));

    let path = seam.config_dir.join("bws.env");
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text, format!("BWS_ACCESS_TOKEN={BWS_TOKEN}\n"), "{text}");
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o640, "mode {mode:o}");
}

#[test]
fn set_token_strips_a_leading_key_prefix() {
    let seam = file_mode_seam("file");
    let secrets = seam.write_secrets_json("secrets.json", r#"{"OPENAI_API_KEY":"sk-x"}"#);
    seam.install_fake_bws(&secrets);

    let out = run_with_stdin(
        seam.vaulted_agent()
            .args(["setup", "bitwarden", "--set-token"]),
        &format!("BWS_ACCESS_TOKEN={BWS_TOKEN}\n"),
    );
    assert!(out.status.success(), "{}", combined(&out));
    let text = fs::read_to_string(seam.config_dir.join("bws.env")).unwrap();
    assert_eq!(text, format!("BWS_ACCESS_TOKEN={BWS_TOKEN}\n"), "{text}");
}

#[test]
fn set_token_rejects_empty_stdin() {
    // Nobody pipes by accident: empty is an error here, not a skip.
    let seam = file_mode_seam("file");
    let out = run_with_stdin(
        seam.vaulted_agent()
            .args(["setup", "bitwarden", "--set-token"]),
        "\n",
    );
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(
        combined(&out).contains("empty BWS_ACCESS_TOKEN"),
        "{}",
        combined(&out)
    );
    assert!(!seam.config_dir.join("bws.env").exists());
}

#[test]
fn set_token_outranks_an_exported_token() {
    // An explicit argument beats ambient env, so a rotation cannot silently
    // store the stale exported value.
    let seam = file_mode_seam("file");
    let secrets = seam.write_secrets_json("secrets.json", r#"{"OPENAI_API_KEY":"sk-x"}"#);
    seam.install_fake_bws(&secrets);

    let stale = "0.99999999-9999-9999-9999-999999999999.stale:stale";
    let out = run_with_stdin(
        seam.vaulted_agent().env("BWS_ACCESS_TOKEN", stale).args([
            "setup",
            "bitwarden",
            "--set-token",
        ]),
        &format!("{BWS_TOKEN}\n"),
    );
    assert!(out.status.success(), "{}", combined(&out));
    let text = fs::read_to_string(seam.config_dir.join("bws.env")).unwrap();
    assert!(text.contains(BWS_TOKEN), "{text}");
    assert!(
        !text.contains("stale"),
        "stale exported token was stored: {text}"
    );
}

#[test]
fn set_token_rejects_a_master_password_before_the_vault_sees_it() {
    let seam = file_mode_seam("file");
    // No `bws` on PATH at all: the shape check must reject before any vault call.
    seam.write_executable("bws", "#!/bin/sh\necho 'bws must not run' >&2\nexit 3\n");

    let out = run_with_stdin(
        seam.vaulted_agent()
            .args(["setup", "bitwarden", "--set-token"]),
        "correcthorsebatterystaple\n",
    );
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(
        combined(&out).contains("start with `0.`"),
        "{}",
        combined(&out)
    );
    assert!(
        !combined(&out).contains("bws must not run"),
        "{}",
        combined(&out)
    );
    assert!(!seam.config_dir.join("bws.env").exists());
}

#[test]
fn an_invalid_token_never_lands_on_disk() {
    let seam = file_mode_seam("file");
    seam.write_executable("bws", "#!/bin/sh\necho 'not authenticated' >&2\nexit 1\n");

    let out = run_with_stdin(
        seam.vaulted_agent()
            .args(["setup", "bitwarden", "--set-token"]),
        &format!("{BWS_TOKEN}\n"),
    );
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(
        combined(&out).contains("rejected by the vault"),
        "{}",
        combined(&out)
    );
    assert!(
        !seam.config_dir.join("bws.env").exists(),
        "unverified token was written"
    );
}

#[test]
fn set_token_is_refused_in_prompt_mode() {
    let seam = file_mode_seam("prompt");
    let out = run_with_stdin(
        seam.vaulted_agent()
            .env("VAULTED_AGENT_AUTH_MODE", "prompt")
            .args(["setup", "bitwarden", "--set-token"]),
        &format!("{BWS_TOKEN}\n"),
    );
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(
        combined(&out).contains("auth-mode file"),
        "{}",
        combined(&out)
    );
    assert!(!seam.config_dir.join("bws.env").exists());
}

#[test]
fn no_terminal_and_no_token_points_at_set_token() {
    // `.output()` gives the child a null stdin, so there is no interactive
    // paste available — the same state as an agent-to-agent or CI invocation.
    let seam = file_mode_seam("file");
    let out = seam
        .vaulted_agent()
        .args(["setup", "bitwarden"])
        .output()
        .expect("run");
    assert!(!out.status.success(), "{}", combined(&out));
    let text = combined(&out);
    assert!(text.contains("--set-token"), "{text}");
    assert!(text.contains("BWS_ACCESS_TOKEN"), "{text}");
    assert!(!seam.config_dir.join("bws.env").exists());
}

#[test]
fn capture_never_overwrites_an_unreadable_token_file() {
    // Invariant 6 / issue #51: a permissions fault must not be papered over by
    // storing a fresh paste on top of a working credential.
    if is_root() {
        return;
    }
    let seam = file_mode_seam("file");
    let path = seam.config_dir.join("bws.env");
    fs::write(&path, "BWS_ACCESS_TOKEN=already-working\n").unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&path, perms).unwrap();

    let out = run_with_stdin(
        seam.vaulted_agent()
            .args(["setup", "bitwarden", "--set-token"]),
        &format!("{BWS_TOKEN}\n"),
    );
    assert!(!out.status.success(), "{}", combined(&out));
    assert!(
        combined(&out).contains("cannot be read"),
        "{}",
        combined(&out)
    );

    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms).unwrap();
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text, "BWS_ACCESS_TOKEN=already-working\n", "{text}");
}

#[test]
fn an_unchanged_token_is_not_rewritten_but_its_mode_is_repaired() {
    // State (b): identical bytes, wrong mode. Repair ownership/mode without
    // truncating a credential other processes may be reading.
    let seam = file_mode_seam("file");
    let secrets = seam.write_secrets_json("secrets.json", r#"{"OPENAI_API_KEY":"sk-x"}"#);
    seam.install_fake_bws(&secrets);
    let path = seam.config_dir.join("bws.env");
    fs::write(&path, format!("BWS_ACCESS_TOKEN={BWS_TOKEN}\n")).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms).unwrap();
    let before = fs::metadata(&path).unwrap().modified().unwrap();

    let out = seam
        .vaulted_agent()
        .env("BWS_ACCESS_TOKEN", BWS_TOKEN)
        .args(["setup", "bitwarden"])
        .output()
        .expect("run");
    assert!(out.status.success(), "{}", combined(&out));

    let meta = fs::metadata(&path).unwrap();
    assert_eq!(
        meta.modified().unwrap(),
        before,
        "identical bytes rewritten"
    );
    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
}

#[test]
fn set_token_writes_a_verified_onepassword_token() {
    let seam = file_mode_seam("file");
    seam.install_fake_op();

    let out = run_with_stdin(
        seam.vaulted_agent()
            .args(["setup", "onepassword", "--set-token"]),
        "ops_eyJmYWtlIjoidG9rZW4ifQ\n",
    );
    assert!(out.status.success(), "{}", combined(&out));
    let path = seam.config_dir.join("op.env");
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(
        text, "OP_SERVICE_ACCOUNT_TOKEN=ops_eyJmYWtlIjoidG9rZW4ifQ\n",
        "{text}"
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[test]
fn launching_never_captures_a_token() {
    // Regression: token capture is a `setup` path. The launch path stays small
    // and auditable, and must never gain a credential-writing mode — whatever
    // happens to be on stdin there belongs to the agent, not to the launcher.
    let seam = file_mode_seam("file");
    seam.install_stub_agent("agent");
    let secrets = seam.write_secrets_json("secrets.json", r#"{"OPENAI_API_KEY":"sk-x"}"#);
    seam.install_fake_bws(&secrets);
    fs::write(
        seam.config_dir.join("manifests/bw.refs"),
        "OPENAI_API_KEY=00000000-0000-0000-0000-000000000000\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend  = bitwarden\nmanifest = bw.refs\ncommand  = agent\n",
    )
    .unwrap();

    let out = run_with_stdin(
        seam.vaulted_agent()
            .env("VAULTED_AGENT_HANDOFF", "spawn")
            .arg("claude"),
        &format!("{BWS_TOKEN}\n"),
    );
    assert!(
        !seam.config_dir.join("bws.env").exists(),
        "launch wrote a token file: {}",
        combined(&out)
    );
}
