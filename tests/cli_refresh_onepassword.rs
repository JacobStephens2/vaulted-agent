//! `vaulted-agent refresh` against the 1Password backend: item selection turns
//! into `VAR=op://VAULT/ITEM/FIELD` refs, and never into secret values.
mod common;

use common::CliSeam;
use std::fs;

const TOKEN: &str = "ops_fake-service-account-token";

/// Values the fake vault holds. None of these may ever reach a refs file.
const SECRET_VALUES: [&str; 6] = [
    "sk-SECRET-VALUE-1",
    "otpauth://SECRET-VALUE-2",
    "github_pat_SECRET_VALUE_3",
    "SECRET-TOP",
    "SECRET-MYSQL",
    "SECRET-REPLICA",
];

fn refs_path(seam: &CliSeam, name: &str) -> std::path::PathBuf {
    seam.config_dir.join("manifests").join(name)
}

#[test]
fn refresh_writes_op_references_and_no_secret_values() {
    let seam = CliSeam::new();
    seam.install_fake_op();

    let out = seam
        .vaulted_agent()
        .args(["refresh", "--backend", "onepassword", "--all"])
        .env("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
        .output()
        .expect("run refresh");
    assert!(
        out.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let body = fs::read_to_string(refs_path(&seam, "onepassword.refs")).expect("refs file written");

    // References, keyed by a var derived from item + field.
    assert!(
        body.contains("ANTHROPIC_CONDUCTOR_API_KEY=op://Orchestrator/anthropic/conductor-api-key"),
        "{body}"
    );
    // Item titles with spaces are kept readable: `op inject` reads a dotenv
    // value to end of line.
    assert!(
        body.contains(
            "GITHUB_TOKEN_FINE_GRAINED_TOKEN=op://Orchestrator/github token/fine-grained-token"
        ),
        "{body}"
    );

    // The invariant that matters: no secret material on disk.
    for v in SECRET_VALUES {
        assert!(!body.contains(v), "refs file leaked a secret value: {body}");
    }

    // Empty and OTP fields are not referenceable.
    assert!(!body.contains("blank-field"), "{body}");
    assert!(!body.contains("one-time"), "{body}");
    // An item with no fields contributes nothing.
    assert!(!body.contains("bare item"), "{body}");
}

/// One item can hold several fields with the same label in different sections,
/// holding different secrets. Keying on the label alone would collapse them to a
/// single ambiguous reference and silently drop the rest.
#[test]
fn same_label_in_different_sections_becomes_distinct_references() {
    let seam = CliSeam::new();
    seam.install_fake_op();

    let out = seam
        .vaulted_agent()
        .args(["refresh", "--backend", "onepassword", "--all"])
        .env("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
        .output()
        .expect("run refresh");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let body = fs::read_to_string(refs_path(&seam, "onepassword.refs")).unwrap();

    // Three distinct passwords on one item: top-level, and one per section.
    assert!(
        body.contains("DB_EXAMPLE_COM_PASSWORD=op://Orchestrator/db.example.com/password"),
        "{body}"
    );
    assert!(
        body.contains(
            "DB_EXAMPLE_COM_MYSQL_PASSWORD=op://Orchestrator/db.example.com/mysql/password"
        ),
        "{body}"
    );
    // The third field carries only a section id; its label comes from `sections`.
    assert!(
        body.contains(
            "DB_EXAMPLE_COM_REPLICA_PASSWORD=op://Orchestrator/db.example.com/replica/password"
        ),
        "{body}"
    );

    let count = body
        .lines()
        .filter(|l| l.contains("op://Orchestrator/db.example.com/"))
        .count();
    assert_eq!(
        count, 3,
        "expected 3 distinct host refs, got {count}:\n{body}"
    );
}

/// A per-item vault failure must not discard the other items. Reading a real
/// vault takes ~a minute; a transient 502 partway through used to lose all of it.
#[test]
fn an_unreadable_item_is_reported_and_the_rest_still_land() {
    let seam = CliSeam::new();
    seam.install_fake_op();

    let out = seam
        .vaulted_agent()
        .args(["refresh", "--backend", "onepassword", "--all"])
        .env("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
        .output()
        .expect("run refresh");
    assert!(
        out.status.success(),
        "one bad item aborted the run: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Warned on stderr, summarised on stdout - skipping is never silent.
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("flaky item"),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("could not be read"), "stdout={stdout}");

    // And the readable items still made it.
    let body = fs::read_to_string(refs_path(&seam, "onepassword.refs")).unwrap();
    assert!(body.contains("ANTHROPIC_CONDUCTOR_API_KEY="), "{body}");
    assert!(body.contains("DB_EXAMPLE_COM_MYSQL_PASSWORD="), "{body}");
}

#[test]
fn refresh_merge_is_idempotent() {
    let seam = CliSeam::new();
    seam.install_fake_op();

    let run = || {
        seam.vaulted_agent()
            .args(["refresh", "--backend", "onepassword", "--all"])
            .env("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
            .output()
            .expect("run refresh")
    };

    assert!(run().status.success());
    let first = fs::read_to_string(refs_path(&seam, "onepassword.refs")).unwrap();

    // Second pass defaults to merge because the file now exists.
    let out = run();
    assert!(out.status.success());
    let second = fs::read_to_string(refs_path(&seam, "onepassword.refs")).unwrap();

    assert_eq!(first, second, "merge re-added mappings it already had");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("No new mappings"),
        "stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Regression: a 1Password-only install used to fail bare `refresh` with
/// "backend needs bws.env" because refresh always loaded the Bitwarden token,
/// ignoring the configured backend.
#[test]
fn bare_refresh_uses_the_configured_backend_not_bitwarden() {
    let seam = CliSeam::new();
    seam.install_fake_op();
    seam.write_harness(
        "claude",
        "backend = onepassword\nmanifest = onepassword.refs\ncommand = claude\n",
    );

    let out = seam
        .vaulted_agent()
        .args(["refresh", "--all"])
        .env("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
        .output()
        .expect("run refresh");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("bws.env"),
        "bare refresh still demanded a Bitwarden token: {stderr}"
    );
    assert!(out.status.success(), "stderr={stderr}");
    assert!(refs_path(&seam, "onepassword.refs").is_file());
}

#[test]
fn refresh_rejects_a_backend_without_refs_files() {
    let seam = CliSeam::new();
    let out = seam
        .vaulted_agent()
        .args(["refresh", "--backend", "sops"])
        .output()
        .expect("run refresh");
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("does not apply"),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}
