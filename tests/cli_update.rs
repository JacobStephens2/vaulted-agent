//! CLI seam: `va update` replaces the installed launcher binary.
//!
//! Network is not a seam. Tests feed a local tarball through
//! `VAULTED_AGENT_UPDATE_ASSET` and a writable dest through
//! `VAULTED_AGENT_UPDATE_DEST`.

mod common;

use common::CliSeam;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn pack_asset(dir: &Path, member_name: &str, body: &str) -> std::path::PathBuf {
    let staged = dir.join("staged");
    fs::create_dir_all(&staged).unwrap();
    write_executable(&staged.join(member_name), body);
    let tgz = dir.join("asset.tar.gz");
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&tgz)
        .arg("-C")
        .arg(&staged)
        .arg(member_name)
        .status()
        .expect("tar");
    assert!(status.success(), "fixture tarball");
    tgz
}

#[test]
fn update_is_a_management_command_not_an_unknown_harness() {
    let seam = CliSeam::new();
    let dest = seam.root.join("installed/vaulted-agent");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    write_executable(&dest, "#!/bin/sh\necho vaulted-agent 0.0.1\n");

    let out = seam
        .vaulted_agent()
        .arg("update")
        .arg("--check")
        .arg("v0.4.20")
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unknown command"),
        "update should be reserved, not a missing harness\nstderr={stderr}"
    );
    assert!(
        out.status.success(),
        "stderr={stderr} stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn update_check_names_current_and_target() {
    let seam = CliSeam::new();
    let dest = seam.root.join("installed/vaulted-agent");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    write_executable(&dest, "#!/bin/sh\necho vaulted-agent 0.0.1\n");

    let out = seam
        .vaulted_agent()
        .arg("update")
        .arg("--check")
        .arg("v0.4.20")
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "should print the running version\n{stdout}"
    );
    assert!(
        stdout.contains("v0.4.20"),
        "should print the requested tag\n{stdout}"
    );
}

#[test]
fn update_replaces_dest_from_a_local_tarball() {
    let seam = CliSeam::new();
    let dest = seam.root.join("installed/vaulted-agent");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    write_executable(&dest, "#!/bin/sh\necho vaulted-agent 0.0.1\n");

    let tgz = pack_asset(
        &seam.root,
        "vaulted-agent",
        "#!/bin/sh\necho 'vaulted-agent 9.9.9'\n",
    );

    let out = seam
        .vaulted_agent()
        .arg("update")
        .arg("v9.9.9")
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .env("VAULTED_AGENT_UPDATE_ASSET", &tgz)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    let probe = Command::new(&dest).arg("version").output().expect("probe");
    let stdout = String::from_utf8_lossy(&probe.stdout);
    assert!(
        stdout.contains("9.9.9"),
        "dest should now be the asset\nstdout={stdout}\nstderr={}",
        String::from_utf8_lossy(&probe.stderr)
    );
}

#[test]
fn update_dry_run_does_not_replace_dest() {
    let seam = CliSeam::new();
    let dest = seam.root.join("installed/vaulted-agent");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    write_executable(&dest, "#!/bin/sh\necho vaulted-agent 0.0.1\n");
    let tgz = pack_asset(
        &seam.root,
        "vaulted-agent",
        "#!/bin/sh\necho 'vaulted-agent 9.9.9'\n",
    );

    let out = seam
        .vaulted_agent()
        .arg("update")
        .arg("--dry-run")
        .arg("v9.9.9")
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .env("VAULTED_AGENT_UPDATE_ASSET", &tgz)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let probe = Command::new(&dest).arg("version").output().expect("probe");
    let stdout = String::from_utf8_lossy(&probe.stdout);
    assert!(
        stdout.contains("0.0.1"),
        "dry-run must leave dest alone\n{stdout}"
    );
}
