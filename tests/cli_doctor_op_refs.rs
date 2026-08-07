//! Issue #53: doctor must not treat plain literals as broken op:// references.

mod common;

use common::CliSeam;
use std::fs;

#[test]
fn doctor_flags_only_malformed_op_refs_not_literals() {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("manifests/mixed.env.tpl"),
        "\
GOOD=op://Vault/item/field
BAD_PARENS=op://Vault/db-admin (rw)/user
AWS_DEFAULT_REGION=us-east-1
API_BASE_URL=https://example.com/v1
",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/probe.conf"),
        "backend = onepassword\nmanifest = mixed.env.tpl\ncommand = true\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = file\ndefault_backend = onepassword\n",
    )
    .unwrap();
    // Token file present so doctor does not also complain about missing auth.
    fs::write(
        seam.config_dir.join("op.env"),
        "OP_SERVICE_ACCOUNT_TOKEN=dummy\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .args(["doctor"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("doctor");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        combined.contains("BAD_PARENS"),
        "malformed op:// ref must be flagged:\n{combined}"
    );
    assert!(
        !combined.contains("AWS_DEFAULT_REGION") && !combined.contains("API_BASE_URL"),
        "plain literals must not be flagged as unparseable refs:\n{combined}"
    );
    assert!(
        !combined.contains("GOOD,"),
        "valid op:// ref must not be flagged:\n{combined}"
    );
    // Doctor should still report an error overall because BAD_PARENS is real.
    assert!(
        combined.contains("ERROR: op cannot parse"),
        "expected parse error for the bad ref:\n{combined}"
    );
}

#[test]
fn doctor_ok_when_manifest_mixes_valid_refs_and_literals() {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("manifests/ok.env.tpl"),
        "\
SECRET=op://Vault/item/field
AWS_DEFAULT_REGION=us-east-1
API_BASE_URL=https://example.com/v1
",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/probe.conf"),
        "backend = onepassword\nmanifest = ok.env.tpl\ncommand = true\n",
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
        .args(["doctor"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("doctor");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !combined.contains("ERROR: op cannot parse"),
        "healthy template must not be painted red:\n{combined}"
    );
    assert!(
        combined.contains("manifest syntax ok"),
        "expected syntax ok:\n{combined}"
    );
}
