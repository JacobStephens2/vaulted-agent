//! Bootstrap-installer seam: `install-remote.sh` as a process.
//!
//! The hosted script at https://vaultedagent.com/install.sh is a copy of
//! `install-remote.sh`, piped into `bash` as root on other people's machines.
//! It has no other test lane, so drive it here: fixture tarball over file://,
//! stub `install.sh` inside, no network and no real privilege.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const MARKER: &str = "STUB-INSTALL-SH-RAN";

/// GitHub names a tarball's top directory after the repo's *current* name, and
/// a renamed repo keeps serving the old URL by redirect. So the directory can
/// be named anything; only its contents identify it. Regression: the script
/// matched on a hardcoded `vaulted-agent-launcher-*` glob, and the rename to
/// `vaulted-agent` broke every remote install with "unexpected layout".
#[test]
fn runs_install_sh_from_a_tarball_named_after_a_renamed_repo() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // Source tree whose top directory matches no name the script could guess.
    let staged = root.join("staged").join("some-other-name-9.9.9");
    fs::create_dir_all(&staged).expect("staged dir");
    fs::write(
        staged.join("install.sh"),
        format!("#!/usr/bin/env bash\nprintf '{MARKER}\\n'\n"),
    )
    .expect("stub install.sh");

    let tarball = root.join("src.tar.gz");
    let tar = Command::new("tar")
        .arg("-czf")
        .arg(&tarball)
        .arg("-C")
        .arg(root.join("staged"))
        .arg("some-other-name-9.9.9")
        .status()
        .expect("run tar");
    assert!(tar.success(), "fixture tarball should build");

    // `sudo` shim: the script re-execs under sudo when not root. Shadow it so
    // the test never touches real privilege and never blocks on a password.
    let shim = root.join("shim");
    fs::create_dir_all(&shim).expect("shim dir");
    let sudo = shim.join("sudo");
    fs::write(&sudo, "#!/bin/sh\nexec \"$@\"\n").expect("sudo shim");
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o755)).expect("chmod shim");

    // A preset VAULTED_AGENT_BIN means "use this binary" — no asset download.
    let bin = root.join("vaulted-agent");
    fs::write(&bin, "#!/bin/sh\nexit 0\n").expect("stub bin");
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).expect("chmod stub bin");

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/install-remote.sh");
    let path = format!(
        "{}:{}",
        shim.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new("bash")
        .arg(script)
        .env("PATH", path)
        .env("VAULTED_AGENT_VERSION", "v9.9.9")
        .env(
            "VAULTED_AGENT_ARCHIVE_URL",
            format!("file://{}", tarball.display()),
        )
        .env("VAULTED_AGENT_BIN", &bin)
        .output()
        .expect("run install-remote.sh");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unexpected layout"),
        "should locate install.sh by content, not by directory name\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(MARKER),
        "should have run install.sh from the tarball\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(
        out.status.success(),
        "status={:?}\nstdout={stdout}\nstderr={stderr}",
        out.status.code()
    );
}
