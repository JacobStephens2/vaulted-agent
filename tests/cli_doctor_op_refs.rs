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

#[test]
fn legacy_name_warning_is_counted_and_does_not_dump_the_whole_manifest() {
    // A whole-vault manifest hit this with 81 names per harness. The report
    // said "0 warning(s)" underneath them, because the warning printed without
    // touching the counter the summary reads.
    let seam = CliSeam::new();
    let mut manifest = String::new();
    for i in 0..30 {
        manifest.push_str(&format!(
            "ITEM{i}_ADD_MORE_API_KEY=op://Vault/item{i}/add more/api-key\n"
        ));
    }
    fs::write(seam.config_dir.join("manifests/legacy.env.tpl"), &manifest).unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/probe.conf"),
        "backend = onepassword\nmanifest = legacy.env.tpl\ncommand = true\n",
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
        combined.contains("30 variable(s) carry a 1Password default section label"),
        "expected the legacy-name warning:\n{combined}"
    );
    // Truncated: a sample plus a count, not all 30.
    assert!(
        combined.contains("and 22 more"),
        "warning must not list every name:\n{combined}"
    );
    assert!(
        !combined.contains("ITEM29_ADD_MORE_API_KEY"),
        "name past the sample must not appear:\n{combined}"
    );
    // What was printed and what was summarised must agree.
    assert!(
        !combined.contains("0 warning(s)"),
        "a printed warning must reach the summary count:\n{combined}"
    );
}
