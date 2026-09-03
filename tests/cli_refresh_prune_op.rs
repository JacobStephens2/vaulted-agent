//! `vaulted-agent refresh --prune` against 1Password (issue #81).
//!
//! Same rule as Bitwarden — prune by resolvability, never by provenance — over
//! a vault where "does not resolve" has more shapes: the item can be gone, the
//! field can be gone, the item can be one this run never opened, and the
//! variable can match a recorded `# exclude:` while still resolving perfectly
//! well. Only the first two are prunable (ADR-0005).

mod common;

use common::CliSeam;
use std::fs;
use std::path::PathBuf;

const TOKEN: &str = "ops_fake-service-account-token";

fn seam_with_manifest(body: &str) -> CliSeam {
    let seam = CliSeam::new();
    seam.install_fake_op();
    fs::write(seam.config_dir.join("manifests/op.refs"), body).unwrap();
    seam.write_harness(
        "claude",
        "backend = onepassword\nmanifest = op.refs\ncommand = true\n",
    );
    seam
}

fn refs_path(seam: &CliSeam) -> PathBuf {
    seam.config_dir.join("manifests/op.refs")
}

fn refresh(seam: &CliSeam, args: &[&str]) -> (bool, String) {
    let mut a = vec!["refresh", "--backend", "onepassword"];
    a.extend_from_slice(args);
    let out = seam
        .vaulted_agent()
        .args(&a)
        .env("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("run refresh");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// Everything that must survive a prune, in one file. Each line is a shape that
/// a naive "not in what refresh would generate" rule would delete.
const MIXED: &str = "\
# 1Password refs (no secret values).
# operator header, hand written

ANTHROPIC_CONDUCTOR_API_KEY=op://Orchestrator/anthropic/conductor-api-key
ANTHROPIC_ONE_TIME=op://Orchestrator/anthropic/one-time
ANTHROPIC_BLANK_FIELD=op://Orchestrator/anthropic/blank-field
DB_EXAMPLE_COM_MYSQL_PASSWORD=op://Orchestrator/db.example.com/mysql/password
DB_EXAMPLE_COM_HOST=op://Orchestrator/db.example.com/website
FLAKY_KEY=op://Orchestrator/flaky item/api-key
AWS_REGION=us-east-1
PINNED=op://Orchestrator/anthropic/REPLACE_WITH_FIELD
GONE_ITEM_KEY=op://Orchestrator/vanished/api-key
ANTHROPIC_OLD_KEY=op://Orchestrator/anthropic/old-api-key
";

#[test]
fn dangling_item_and_field_are_reported_and_left_alone_without_prune() {
    let seam = seam_with_manifest(MIXED);
    let (ok, out) = refresh(&seam, &["--all"]);

    // refresh is not a gate; `secrets validate` is (invariant 5).
    assert!(ok, "refresh must still exit 0:\n{out}");
    assert!(out.contains("Dangling refs in"), "{out}");
    assert!(
        out.contains("GONE_ITEM_KEY=op://Orchestrator/vanished/api-key"),
        "{out}"
    );
    assert!(
        out.contains("ANTHROPIC_OLD_KEY=op://Orchestrator/anthropic/old-api-key"),
        "{out}"
    );
    assert!(out.contains("Re-run with --prune"), "{out}");

    // Nothing was removed. New mappings may have been appended (merge), so the
    // check is that every original line is still there, in order.
    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert!(after.starts_with(MIXED), "file was rewritten:\n{after}");
}

#[test]
fn prune_removes_only_what_does_not_resolve() {
    let seam = seam_with_manifest(MIXED);
    let (ok, out) = refresh(&seam, &["--all", "--prune"]);
    assert!(ok, "{out}");
    assert!(out.contains("Remove 2 dangling mapping(s)"), "{out}");

    let after = fs::read_to_string(refs_path(&seam)).unwrap();

    // Gone: the item is not in the listing, and the field is not on an item the
    // run opened.
    assert!(!after.contains("GONE_ITEM_KEY"), "{after}");
    assert!(!after.contains("old-api-key"), "{after}");

    // Kept, and every one for a different reason.
    for kept in [
        // Resolves, and is exactly what refresh would generate.
        "ANTHROPIC_CONDUCTOR_API_KEY=op://Orchestrator/anthropic/conductor-api-key",
        // An OTP field: `op` resolves it, refresh would never map it. Judging
        // against what refresh would generate would delete a working line.
        "ANTHROPIC_ONE_TIME=op://Orchestrator/anthropic/one-time",
        // Same, for a field whose value is empty today.
        "ANTHROPIC_BLANK_FIELD=op://Orchestrator/anthropic/blank-field",
        // Section-qualified.
        "DB_EXAMPLE_COM_MYSQL_PASSWORD=op://Orchestrator/db.example.com/mysql/password",
        // Website URL field.
        "DB_EXAMPLE_COM_HOST=op://Orchestrator/db.example.com/website",
        // The item could not be read this run (a 502 in the fake vault). A
        // transient failure must never read as "the secret is gone".
        "FLAKY_KEY=op://Orchestrator/flaky item/api-key",
        // Not a reference at all.
        "AWS_REGION=us-east-1",
        // A placeholder stays loud: invariant 4, and validate's business.
        "PINNED=op://Orchestrator/anthropic/REPLACE_WITH_FIELD",
        // Comments and the operator's own header.
        "# operator header, hand written",
    ] {
        assert!(after.contains(kept), "prune took {kept}:\n{after}");
    }

    // The unread item is named rather than passed over in silence.
    assert!(out.contains("Refs this run did not check"), "{out}");
    assert!(out.contains("FLAKY_KEY"), "{out}");
}

/// The question #81 existed to settle: a recorded exclusion says what refresh
/// may **add**. It does not make a working mapping prunable.
#[test]
fn an_excluded_mapping_that_resolves_is_reported_not_pruned() {
    let body = "\
# exclude: *_CONDUCTOR_API_KEY
ANTHROPIC_CONDUCTOR_API_KEY=op://Orchestrator/anthropic/conductor-api-key
";
    let seam = seam_with_manifest(body);
    let (ok, out) = refresh(&seam, &["--all", "--prune"]);
    assert!(ok, "{out}");

    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert!(
        after.contains("ANTHROPIC_CONDUCTOR_API_KEY=op://Orchestrator/anthropic/conductor-api-key"),
        "an excluded mapping that resolves must survive prune:\n{after}"
    );
    assert!(out.contains("Mapped but excluded in"), "{out}");
    assert!(out.contains("edit-manifest"), "{out}");
    assert!(!out.contains("Remove 1 dangling"), "{out}");
}

/// An exclusion that covers a mapping which is *also* dangling changes nothing:
/// it goes because it does not resolve, and it is not reported twice under two
/// headings that suggest two different fates.
#[test]
fn an_excluded_mapping_that_dangles_is_pruned_as_dangling() {
    let body = "\
# exclude: GONE_*
GONE_KEY=op://Orchestrator/vanished/api-key
";
    let seam = seam_with_manifest(body);
    let (ok, out) = refresh(&seam, &["--all", "--prune"]);
    assert!(ok, "{out}");

    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert!(!after.contains("GONE_KEY"), "{after}");
    assert!(out.contains("Remove 1 dangling mapping(s)"), "{out}");
    assert!(!out.contains("Mapped but excluded"), "{out}");
}

/// `--replace` regenerates the file, so it prunes by construction. Passing both
/// is a no-op rather than an error — the same contract Bitwarden has.
#[test]
fn replace_and_prune_together_is_a_no_op_not_an_error() {
    let seam = seam_with_manifest(MIXED);
    let (ok, out) = refresh(&seam, &["--all", "--replace", "--prune"]);
    assert!(ok, "{out}");
    assert!(out.contains("--replace rewrites the file"), "{out}");
}
