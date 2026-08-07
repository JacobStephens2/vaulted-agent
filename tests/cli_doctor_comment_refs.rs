//! doctor must catch a secret reference written into a comment.
//!
//! `op inject` resolves every reference in the file, comments included, and a
//! failed lookup aborts the injection of the whole manifest. The dotenv parser
//! doctor used drops comments before any check ran, so a manifest that could
//! not inject at all was reported healthy — observed in the wild after an
//! illustrative op:// went into a header note and took 200 variables down.

mod common;

use common::CliSeam;
use std::fs;

fn seam_with(manifest: &str) -> CliSeam {
    let seam = CliSeam::new();
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

fn doctor(seam: &CliSeam) -> String {
    let out = seam
        .vaulted_agent()
        .args(["doctor"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("doctor");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_reference_in_a_comment_is_an_error_naming_its_line() {
    let seam = seam_with(
        "# a header\n\
         # merge compares the field, so op://Vault/item/add more/x no longer\n\
         # reads as new when section 1 maps op://Vault/item/x. Prose follows.\n\
         GOOD=op://Vault/item/field\n",
    );
    let out = doctor(&seam);
    assert!(
        out.contains("comment line(s) contain a secret reference"),
        "{out}"
    );
    assert!(out.contains("line 2"), "{out}");
    assert!(out.contains("line 3"), "{out}");
    // It must count, not just print: the summary is what gets read.
    assert!(!out.contains("0 error(s)"), "{out}");
}

#[test]
fn ordinary_comments_are_left_alone() {
    // The false positive that would make this check unusable: manifests are
    // heavily commented, and only an actual reference may be flagged.
    let seam = seam_with(
        "# Primary production database. Rotate in 1Password, no change here.\n\
         # See docs/manifests.md — values fetched live at launch.\n\
         # TODO: split the reporting credential out of this file.\n\
         PROD_DB_PASS=op://Vault/db/password\n\
         AWS_DEFAULT_REGION=us-east-1\n",
    );
    let out = doctor(&seam);
    assert!(
        !out.contains("comment line(s) contain"),
        "prose comments must not be flagged:\n{out}"
    );
    assert!(out.contains("manifest syntax ok"), "{out}");
    // Do not require "0 error(s)": doctor still reports missing `op` on PATH
    // for onepassword harnesses in CI. That is unrelated to comment scanning.
}
