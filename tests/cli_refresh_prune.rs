//! `vaulted-agent refresh --prune` against Bitwarden (issue #80).
//!
//! A secret renamed in the vault leaves its old mapping behind, and every
//! launch through that manifest then fails closed on a reference nothing
//! answers. These pin the whole contract: dangling refs are reported on every
//! run, removed only when asked, and the removal keeps every other byte of the
//! file — including the lines an operator wrote by hand.

mod common;

use common::CliSeam;
use std::fs;
use std::path::PathBuf;

/// A vault holding the renamed secret and one other. The fake `bws` derives
/// ids from key order, so `ASSEMBLY_AI_API_KEY` is …-000000000000.
const VAULT: &str = r#"{"ASSEMBLY_AI_API_KEY": "sk-assembly", "OPENAI_API_KEY": "sk-openai"}"#;

const MANIFEST: &str = "# Bitwarden Secrets Manager refs (no secret values).\n\
                        # operator header, hand written\n\
                        \n\
                        PINNED=00000000-0000-0000-0000-000000000001\n\
                        ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY\n";

fn seam_with_manifest(body: &str) -> CliSeam {
    let seam = CliSeam::new();
    let map = seam.write_secrets_json("vault.json", VAULT);
    seam.install_fake_bws(&map);
    fs::write(seam.config_dir.join("manifests/bws.refs"), body).unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = bitwarden\nmanifest = bws.refs\ncommand = true\n",
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

fn refresh(seam: &CliSeam, args: &[&str]) -> (bool, String) {
    let mut a = vec!["refresh"];
    a.extend_from_slice(args);
    let out = seam
        .vaulted_agent()
        .args(&a)
        .env("VAULTED_AGENT_AUTH_MODE", "file")
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

#[test]
fn a_dangling_ref_is_reported_and_left_alone_without_prune() {
    // Everything the vault holds is already mapped, so merge has nothing to
    // add and the file must come back byte-identical. That promise is what
    // makes the feature safe to ship: no --prune, no TTY, no write.
    let before = "OPENAI_API_KEY=name:OPENAI_API_KEY\n\
                  ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY\n\
                  ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY\n";
    let seam = seam_with_manifest(before);
    let (ok, out) = refresh(&seam, &["--all"]);

    // refresh is not a gate; `secrets validate` is (invariant 5).
    assert!(ok, "refresh must still exit 0:\n{out}");
    assert!(
        out.contains("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY"),
        "{out}"
    );
    assert!(out.contains("--prune"), "no way out offered:\n{out}");
    assert_eq!(
        fs::read_to_string(refs_path(&seam)).unwrap(),
        before,
        "reported instead of changing nothing"
    );
}

#[test]
fn a_rename_in_the_vault_is_mapped_anew_and_the_old_line_pruned() {
    // The whole bug, end to end: refresh against one vault, rename the secret
    // in it, refresh again. Merge alone can only add the new name.
    let seam = CliSeam::new();
    let before = seam.write_secrets_json(
        "before.json",
        r#"{"ASSEMBLY_API_KEY": "sk-assembly", "OPENAI_API_KEY": "sk-openai"}"#,
    );
    seam.install_fake_bws(&before);
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = bitwarden\nmanifest = bws.refs\ncommand = true\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("bws.env"),
        "BWS_ACCESS_TOKEN=test-token\n",
    )
    .unwrap();

    let (ok, out) = refresh(&seam, &["--all"]);
    assert!(ok, "{out}");
    assert!(
        fs::read_to_string(refs_path(&seam))
            .unwrap()
            .contains("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY"),
        "first refresh did not map the secret"
    );

    // …renamed in Bitwarden: same secret, new key.
    let after_rename = seam.write_secrets_json("before.json", VAULT);
    seam.install_fake_bws(&after_rename);
    let (ok, out) = refresh(&seam, &["--all", "--prune"]);
    assert!(ok, "{out}");

    let body = fs::read_to_string(refs_path(&seam)).unwrap();
    assert!(
        body.contains("ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY"),
        "{body}"
    );
    assert!(
        !body.contains("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY"),
        "the old mapping outlived the rename:\n{body}"
    );
}

#[test]
fn a_launch_through_a_dangling_ref_names_the_manifest_and_the_way_out() {
    // `no secret matched name:X` alone says neither which file holds the
    // mapping nor how to be rid of it.
    let seam = seam_with_manifest("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY\n");
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = bitwarden\nmanifest = bws.refs\ncommand = agent\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .arg("claude")
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .env("VAULTED_AGENT_AUTH_MODE", "file")
        .output()
        .expect("launch");
    assert!(!out.status.success(), "a dangling ref must fail closed");
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("no secret matched name:ASSEMBLY_API_KEY"),
        "{err}"
    );
    assert!(err.contains("bws.refs"), "manifest not named:\n{err}");
    assert!(
        err.contains("refresh --prune"),
        "no way out offered:\n{err}"
    );
}

#[test]
fn prune_removes_the_dangling_line_and_keeps_every_other_byte() {
    let seam = seam_with_manifest(MANIFEST);
    let (ok, out) = refresh(&seam, &["--all", "--prune"]);
    assert!(ok, "{out}");

    // Removed lines print verbatim: scrollback is the recovery path.
    assert!(
        out.contains("- ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY"),
        "{out}"
    );

    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert!(
        !after.contains("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY"),
        "still dangling:\n{after}"
    );
    // Untouched: the operator's header, the blank line, and a UUID-form ref
    // that `--replace` would have rewritten into `name:` form.
    assert!(after.contains("# operator header, hand written"), "{after}");
    assert!(
        after.contains("hand written\n\nPINNED="),
        "the blank line went with it:\n{after}"
    );
    assert!(
        after.contains("PINNED=00000000-0000-0000-0000-000000000001"),
        "{after}"
    );
    assert!(
        after.contains("ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY"),
        "{after}"
    );
    // No backup file left in the manifest directory, temp file included.
    let names: Vec<String> = fs::read_dir(seam.config_dir.join("manifests"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(names, vec!["bws.refs".to_string()], "{names:?}");
}

#[test]
fn a_ref_refresh_cannot_judge_is_reported_but_never_pruned() {
    // Shape is `secrets validate`'s concern. Prune removes what does not
    // resolve, and this has not been shown not to.
    let seam = seam_with_manifest("JUNK=not-a-reference\nOPENAI_API_KEY=name:OPENAI_API_KEY\n");
    let (ok, out) = refresh(&seam, &["--all", "--prune"]);
    assert!(ok, "{out}");
    assert!(out.contains("JUNK=not-a-reference"), "{out}");
    assert!(
        fs::read_to_string(refs_path(&seam))
            .unwrap()
            .contains("JUNK=not-a-reference"),
        "pruned a line it could not judge"
    );
}

#[test]
fn an_alias_reading_a_doomed_var_is_warned_about_not_blocked() {
    // Prune removes the mapping; the `alias =` line naming it lives in a
    // harness file prune does not own.
    let seam = seam_with_manifest(MANIFEST);
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = bitwarden\nmanifest = bws.refs\ncommand = true\n\
         alias = ASSEMBLY_KEY = ASSEMBLY_API_KEY\n",
    )
    .unwrap();

    let (ok, out) = refresh(&seam, &["--all", "--prune"]);
    assert!(ok, "a warning must not block:\n{out}");
    assert!(
        out.contains("alias = ASSEMBLY_KEY = ASSEMBLY_API_KEY"),
        "{out}"
    );
    assert!(
        !fs::read_to_string(refs_path(&seam))
            .unwrap()
            .contains("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY"),
        "warning turned into a block"
    );
}

#[test]
fn replace_and_prune_together_are_a_no_op_not_an_error() {
    // `--replace` regenerates the file, so it already prunes by construction.
    let seam = seam_with_manifest(MANIFEST);
    let (ok, out) = refresh(&seam, &["--all", "--replace", "--prune"]);
    assert!(ok, "{out}");
    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert!(
        !after.contains("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY"),
        "{after}"
    );
}

#[test]
fn merge_does_not_stack_a_banner_on_every_run() {
    let seam = seam_with_manifest("OPENAI_API_KEY=name:OPENAI_API_KEY\n");
    let (ok, out) = refresh(&seam, &["--all"]);
    assert!(ok, "{out}");
    // A second run with a third secret in the vault appends under the same
    // separator rather than opening another one.
    let map = seam.write_secrets_json(
        "vault.json",
        r#"{"ASSEMBLY_AI_API_KEY": "a", "OPENAI_API_KEY": "b", "META_AI_API_KEY": "c"}"#,
    );
    seam.install_fake_bws(&map);
    let (ok, out) = refresh(&seam, &["--all"]);
    assert!(ok, "{out}");

    let after = fs::read_to_string(refs_path(&seam)).unwrap();
    assert_eq!(
        after
            .matches("# --- appended by vaulted-agent refresh ---")
            .count(),
        1,
        "{after}"
    );
    assert!(
        after.contains("META_AI_API_KEY=name:META_AI_API_KEY"),
        "{after}"
    );
}
