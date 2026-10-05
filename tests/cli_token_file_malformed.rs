//! Issue #160: a Manager-token file that does not parse is a fault, named with
//! its path and line by every reader, never an invitation to paste.

mod common;

use common::CliSeam;
use std::fs;
use std::io::Write;
use std::process::{Output, Stdio};

/// A shape-valid Bitwarden Secrets Manager access token (not a real one).
const BWS_TOKEN: &str = "0.11111111-1111-1111-1111-111111111111.clientsecret:enckey";

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A file-mode machine with a malformed `op.env`.
fn seam_with_malformed_op_env() -> CliSeam {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = file\ndefault_backend = onepassword\n",
    )
    .unwrap();
    fs::write(seam.config_dir.join("op.env"), "ops_pasted_without_a_key\n").unwrap();
    seam
}

#[test]
fn a_launch_fails_closed_on_a_malformed_token_file_and_names_it() {
    let seam = seam_with_malformed_op_env();
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/op.env.refs"),
        "A=op://V/item/field\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/opprobe.conf"),
        "backend = onepassword\nmanifest = op.env.refs\ncommand = agent\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .args(["opprobe"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .stdin(Stdio::null())
        .output()
        .expect("launch");
    let text = combined(&out);
    assert!(!out.status.success(), "must not launch: {text}");
    let path = seam.config_dir.join("op.env");
    assert!(
        text.contains(&format!("{} is malformed (line 1:", path.display())),
        "{text}"
    );
    assert!(text.contains("setup onepassword --set-token"), "{text}");
    assert!(!text.contains("onepassword missing"), "{text}");
    assert!(
        !text.contains("hidden, not written"),
        "no paste prompt: {text}"
    );
    assert!(
        !text.contains("cannot be read"),
        "not a permissions fault: {text}"
    );
}

#[test]
fn doctor_counts_a_malformed_token_file_as_an_error() {
    let seam = seam_with_malformed_op_env();
    let out = seam
        .vaulted_agent()
        .args(["doctor"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("doctor");
    let text = combined(&out);
    assert!(text.contains("op.env: malformed"), "{text}");
    assert!(text.contains("line 1:"), "{text}");
    assert!(!text.contains("op.env: present"), "{text}");
}

#[test]
fn doctor_says_a_token_file_holds_no_value_for_an_empty_key() {
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("bws.env"), "BWS_ACCESS_TOKEN=\n").unwrap();
    let out = seam
        .vaulted_agent()
        .args(["doctor"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("doctor");
    let text = combined(&out);
    assert!(
        text.contains("bws.env: holds no value for BWS_ACCESS_TOKEN"),
        "{text}"
    );
}

#[test]
fn setup_without_set_token_refuses_a_malformed_token_file() {
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("defaults.conf"), "auth_mode = file\n").unwrap();
    let path = seam.config_dir.join("bws.env");
    fs::write(&path, "stray line\n").unwrap();
    let out = seam
        .vaulted_agent()
        .args(["setup", "bitwarden"])
        .stdin(Stdio::null())
        .output()
        .expect("setup");
    let text = combined(&out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("is malformed (line 1:"), "{text}");
    assert!(!text.contains("cannot be read"), "{text}");
    assert_eq!(fs::read_to_string(&path).unwrap(), "stray line\n");
}

#[test]
fn set_token_replaces_a_malformed_token_file_once_the_token_verifies() {
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("defaults.conf"), "auth_mode = file\n").unwrap();
    let secrets = seam.write_secrets_json("secrets.json", r#"{"OPENAI_API_KEY":"sk-x"}"#);
    seam.install_fake_bws(&secrets);
    let path = seam.config_dir.join("bws.env");
    fs::write(&path, "stray line\n").unwrap();

    let mut child = seam
        .vaulted_agent()
        .args(["setup", "bitwarden", "--set-token"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(format!("{BWS_TOKEN}\n").as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success(), "{}", combined(&out));
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        format!("BWS_ACCESS_TOKEN={BWS_TOKEN}\n")
    );
}
