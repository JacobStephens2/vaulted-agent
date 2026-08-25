//! `vaulted-agent refresh` against a secret renamed in the vault (issue #82).
//!
//! ADR-0003 could only prune a rename: report the old key gone, add the new one,
//! and leave the operator to notice they were the same secret. Generated lines
//! now record the UUID they came from, so the same run says **renamed** and
//! repairs the one line — keeping the variable name, so a harness `alias =`
//! reading it never breaks.
//!
//! These also pin the launch-path half of the format change: an annotated line
//! still resolves, and still passes the pre-flight gate.

mod common;

use common::CliSeam;
use std::fs;
use std::path::PathBuf;

/// The fake `bws` derives ids from key order, so `ASSEMBLY_AI_API_KEY` is
/// …-000000000001. Index 0 is deliberately something else: the all-zero UUID is
/// a placeholder, and invariant 4 keeps those out of the resolvable world.
const VAULT: &str = r#"{"OPENAI_API_KEY": "sk-openai", "ASSEMBLY_AI_API_KEY": "sk-assembly"}"#;

const RENAMED_UUID: &str = "00000000-0000-0000-0000-000000000001";

/// A manifest carrying the rename: the line still asks for the old key, but
/// records the secret it was generated from.
fn manifest_with_rename() -> String {
    format!(
        "# Bitwarden Secrets Manager refs (no secret values).\n\
         # operator header, hand written\n\
         \n\
         OPENAI_API_KEY=name:OPENAI_API_KEY\n\
         ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY # uuid:{RENAMED_UUID}\n"
    )
}

fn seam_with_manifest(body: &str) -> CliSeam {
    let seam = CliSeam::new();
    let map = seam.write_secrets_json("vault.json", VAULT);
    seam.install_fake_bws(&map);
    fs::write(seam.config_dir.join("manifests/bws.refs"), body).unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = bitwarden\nmanifest = bws.refs\ncommand = stub-agent\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("bws.env"),
        "BWS_ACCESS_TOKEN=test-token\n",
    )
    .unwrap();
    seam
}

fn refs_path(seam: &CliSeam) -> PathBuf {
    seam.config_dir.join("manifests/bws.refs")
}

fn va(seam: &CliSeam, args: &[&str]) -> (bool, String) {
    let out = seam
        .vaulted_agent()
        .args(args)
        .env("VAULTED_AGENT_AUTH_MODE", "file")
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("run vaulted-agent");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn a_rename_is_reported_as_a_rename_and_not_as_a_loss_plus_a_gain() {
    let before = manifest_with_rename();
    let seam = seam_with_manifest(&before);
    let (ok, out) = va(&seam, &["refresh", "--all"]);

    assert!(ok, "refresh must still exit 0:\n{out}");
    assert!(
        out.to_lowercase().contains("renamed"),
        "the rename was not named:\n{out}"
    );
    assert!(
        out.contains(&format!(
            "ASSEMBLY_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{RENAMED_UUID}"
        )),
        "the repair was not shown:\n{out}"
    );
    // Not "1 dangling": the secret is there, and refresh can prove it.
    assert!(
        !out.contains("Dangling refs"),
        "reported as dangling as well:\n{out}"
    );
    // Merge must not append a second mapping for a secret already mapped.
    assert_eq!(
        fs::read_to_string(refs_path(&seam)).unwrap(),
        before,
        "refresh changed the file without being asked"
    );
    assert!(out.contains("--prune"), "no way out offered:\n{out}");
}

#[test]
fn prune_repairs_the_line_in_place_and_keeps_the_variable_name() {
    let seam = seam_with_manifest(&manifest_with_rename());
    let (ok, out) = va(&seam, &["refresh", "--all", "--prune"]);
    assert!(ok, "{out}");

    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert_eq!(
        after,
        format!(
            "# Bitwarden Secrets Manager refs (no secret values).\n\
             # operator header, hand written\n\
             \n\
             OPENAI_API_KEY=name:OPENAI_API_KEY\n\
             ASSEMBLY_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{RENAMED_UUID}\n"
        ),
        "repair was not surgical:\n{out}"
    );
}

#[test]
fn a_deleted_secret_is_still_pruned_not_repaired() {
    // The recording only proves a rename when the secret is still visible.
    let before = "OPENAI_API_KEY=name:OPENAI_API_KEY\n\
                  GONE=name:GONE # uuid:00000000-0000-0000-0000-000000000099\n";
    let seam = seam_with_manifest(before);
    let (ok, out) = va(&seam, &["refresh", "--all", "--prune"]);
    assert!(ok, "{out}");
    assert!(out.contains("Dangling refs"), "{out}");

    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert!(!after.contains("GONE"), "dangling line survived:\n{after}");
    assert!(
        after.contains("OPENAI_API_KEY=name:OPENAI_API_KEY"),
        "{after}"
    );
}

#[test]
fn an_annotated_line_still_resolves_at_launch() {
    // The launch path is the reason this was deferred. A recorded UUID must be
    // invisible to it: the secret arrives under the variable the file names.
    let seam = seam_with_manifest(&format!(
        "ASSEMBLY_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{RENAMED_UUID}\n"
    ));
    seam.install_stub_agent("stub-agent");
    let (ok, out) = va(&seam, &["-H", "claude"]);
    assert!(ok, "launch failed:\n{out}");

    let record = seam.read_stub_record("stub-agent");
    assert!(
        record.contains("ENV ASSEMBLY_API_KEY=sk-assembly"),
        "secret not injected:\n{record}"
    );
}

#[test]
fn an_annotated_line_passes_the_pre_flight_gate() {
    let seam = seam_with_manifest(&format!(
        "ASSEMBLY_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{RENAMED_UUID}\n"
    ));
    let (ok, out) = va(&seam, &["secrets", "validate"]);
    assert!(ok, "validate rejected a resolvable annotated line:\n{out}");
}

#[test]
fn refresh_writes_the_recording_onto_the_lines_it_generates() {
    // No backfill (ADR-0004): the corpus migrates as refresh adds mappings, and
    // lines already on disk are left exactly as they are.
    let seam = seam_with_manifest("# operator header\nOPENAI_API_KEY=name:OPENAI_API_KEY\n");
    let (ok, out) = va(&seam, &["refresh", "--all"]);
    assert!(ok, "{out}");

    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert!(
        after.contains(&format!(
            "ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{RENAMED_UUID}"
        )),
        "generated line carries no recording:\n{after}"
    );
    assert!(
        after.contains("OPENAI_API_KEY=name:OPENAI_API_KEY\n"),
        "an existing line was backfilled:\n{after}"
    );
}

#[test]
fn a_repair_cannot_collide_with_a_variable_the_file_already_has() {
    // The new key already has its own hand-written line. Because the repair
    // keeps the old variable name, it cannot introduce a duplicate VAR — the
    // worst it can do is map one secret under two names, which a refs file has
    // always allowed and which injects the same value either way.
    let before = format!(
        "OPENAI_API_KEY=name:OPENAI_API_KEY\n\
         MINE=name:ASSEMBLY_AI_API_KEY\n\
         ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY # uuid:{RENAMED_UUID}\n"
    );
    let seam = seam_with_manifest(&before);
    let (ok, out) = va(&seam, &["refresh", "--all", "--prune"]);
    assert!(ok, "{out}");

    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert_eq!(
        after,
        format!(
            "OPENAI_API_KEY=name:OPENAI_API_KEY\n\
             MINE=name:ASSEMBLY_AI_API_KEY\n\
             ASSEMBLY_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{RENAMED_UUID}\n"
        )
    );
    // No variable appears twice, so nothing shadows anything.
    let vars: Vec<&str> = after
        .lines()
        .filter(|l| l.contains('='))
        .map(|l| l.split_once('=').unwrap().0)
        .collect();
    assert_eq!(vars, vec!["OPENAI_API_KEY", "MINE", "ASSEMBLY_API_KEY"]);
}

#[test]
fn two_lines_recording_one_renamed_secret_both_repair() {
    // Keyed by line text, so two distinct lines are two distinct edits. Both
    // keep their own variable, and both end up resolving.
    let before = format!(
        "OPENAI_API_KEY=name:OPENAI_API_KEY\n\
         A_KEY=name:ASSEMBLY_API_KEY # uuid:{RENAMED_UUID}\n\
         B_KEY=name:ASSEMBLY_API_KEY # uuid:{RENAMED_UUID}\n"
    );
    let seam = seam_with_manifest(&before);
    let (ok, out) = va(&seam, &["refresh", "--all", "--prune"]);
    assert!(ok, "{out}");

    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert_eq!(
        after,
        format!(
            "OPENAI_API_KEY=name:OPENAI_API_KEY\n\
             A_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{RENAMED_UUID}\n\
             B_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{RENAMED_UUID}\n"
        )
    );
    let (ok, out) = va(&seam, &["secrets", "validate"]);
    assert!(ok, "repaired file does not pass the gate:\n{out}");
}

#[test]
fn replace_mode_warns_that_a_rename_will_take_the_variable_with_it() {
    // The repair keeps the variable name, which is why the rename path skips the
    // alias warning. `--replace` does not repair — it regenerates from the
    // listing, so the secret comes back under its *new* key and the old
    // variable disappears. ADR-0003 kept this warning as the one piece of
    // cleanup refresh cannot do itself, and it has to fire here.
    let seam = seam_with_manifest(&manifest_with_rename());
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = bitwarden\nmanifest = bws.refs\ncommand = stub-agent\n\
         alias = ASSEMBLYAI_API_KEY = ASSEMBLY_API_KEY\n",
    )
    .unwrap();

    let (ok, out) = va(&seam, &["refresh", "--all", "--replace", "--prune"]);
    assert!(ok, "{out}");
    assert!(
        out.contains("ASSEMBLY_API_KEY") && out.to_lowercase().contains("alias"),
        "no alias warning for a variable --replace is about to drop:\n{out}"
    );

    // And the premise: the old variable really is gone.
    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert!(
        !after.contains("ASSEMBLY_API_KEY=") || after.contains("ASSEMBLY_AI_API_KEY="),
        "{after}"
    );
}
