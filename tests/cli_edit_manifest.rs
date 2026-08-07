//! `edit-manifest`: pick a manifest, open it, and check it on save.

mod common;

use common::CliSeam;
use std::fs;

fn seam_with_manifests(seam: &CliSeam) {
    fs::write(
        seam.config_dir.join("manifests/wide.env.tpl"),
        "A=op://V/item/a\nB=op://V/item/b\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("manifests/narrow.env.tpl"),
        "A=op://V/item/a\n",
    )
    .unwrap();
    // Neither of these may be offered: editing one changes nothing anyone reads.
    fs::write(
        seam.config_dir.join("manifests/wide.env.tpl.example"),
        "A=x\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir
            .join("manifests/wide.env.tpl.bak-20260807-120000"),
        "A=x\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = onepassword\nmanifest = wide.env.tpl\ncommand = true\n",
    )
    .unwrap();
}

#[test]
fn help_describes_the_command() {
    let seam = CliSeam::new();
    let out = seam
        .vaulted_agent()
        .args(["edit-manifest", "--help"])
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(text.contains("edit-manifest"), "{text}");
    assert!(text.contains("sudoedit"), "{text}");
}

#[test]
fn a_named_manifest_opens_in_the_editor_and_reports_it_is_clean() {
    let seam = CliSeam::new();
    seam_with_manifests(&seam);
    let out = seam
        .vaulted_agent()
        // A no-op "editor" stands in for the interactive part.
        .env("EDITOR", "true")
        .args(["edit-manifest", "narrow.env.tpl"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("narrow.env.tpl"), "{text}");
    assert!(text.contains("1 variable(s), no problems"), "{text}");
}

#[test]
fn an_edit_that_puts_a_reference_in_a_comment_is_caught() {
    // Same rule as doctor: op inject reads comments. edit-manifest must not
    // report "no problems" for a file that cannot inject.
    let seam = CliSeam::new();
    seam_with_manifests(&seam);
    let editor = seam.work_dir.join("comment-ref.sh");
    fs::write(
        &editor,
        "#!/usr/bin/env bash\nprintf '# see op://Vault/item/field for details\\nA=op://V/item/a\\n' > \"$1\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&editor, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out = seam
        .vaulted_agent()
        .env("EDITOR", &editor)
        .args(["edit-manifest", "narrow.env.tpl"])
        .output()
        .expect("run");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("problem"), "{text}");
    assert!(text.contains("comment") && text.contains("op://"), "{text}");
}

#[test]
fn an_edit_that_breaks_a_reference_is_reported_not_accepted_silently() {
    let seam = CliSeam::new();
    seam_with_manifests(&seam);
    // An "editor" that writes a reference op cannot parse — the failure that
    // takes every other variable in the file down with it at launch.
    let editor = seam.work_dir.join("break-it.sh");
    fs::write(
        &editor,
        "#!/usr/bin/env bash\nprintf 'A=op://V/db-admin (rw)/pass\\n' > \"$1\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&editor, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out = seam
        .vaulted_agent()
        .env("EDITOR", &editor)
        // Answer the "edit again?" prompt with nothing: no tty, so it must not
        // loop forever waiting for one.
        .args(["edit-manifest", "narrow.env.tpl"])
        .output()
        .expect("run");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("problem"), "{text}");
    assert!(text.contains("aborts the whole manifest"), "{text}");
}

#[test]
fn an_unknown_name_is_a_typo_not_an_invitation_to_create() {
    let seam = CliSeam::new();
    seam_with_manifests(&seam);
    let out = seam
        .vaulted_agent()
        .env("EDITOR", "true")
        .args(["edit-manifest", "nope.env.tpl"])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no manifest named"), "{err}");
    assert!(!seam.config_dir.join("manifests/nope.env.tpl").exists());
}

#[test]
fn a_path_is_refused_so_the_name_stays_a_name() {
    let seam = CliSeam::new();
    seam_with_manifests(&seam);
    for bad in ["../../etc/passwd", "sub/dir.env", ".."] {
        let out = seam
            .vaulted_agent()
            .env("EDITOR", "true")
            .args(["edit-manifest", bad])
            .output()
            .expect("run");
        assert!(!out.status.success(), "{bad} should be refused");
    }
}

#[test]
fn without_a_terminal_it_says_to_name_one_rather_than_hanging() {
    let seam = CliSeam::new();
    seam_with_manifests(&seam);
    let out = seam
        .vaulted_agent()
        .env("EDITOR", "true")
        .args(["edit-manifest"])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("no terminal"), "{err}");
}
