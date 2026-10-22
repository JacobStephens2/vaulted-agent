//! Bootstrap-installer seam: tests/install_remote_bootstrap.sh against
//! `install-remote.sh` in this tree.
//!
//! The suite stubs curl, tar, bash and sudo, so it needs no network or
//! privilege offline. Its one online test (the published archive matches the
//! recorded digest) runs in scripts/release.sh deploy-site, not here: on a
//! release branch the tag does not exist yet. Linux only: the suite calls
//! /bin/tar, /usr/bin/shasum and sha256sum by path.
#![cfg(target_os = "linux")]
use std::fs;
use std::process::Command;

const SUITE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/install_remote_bootstrap.sh"
);
const BOOTSTRAP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/install-remote.sh");

#[test]
fn bootstrap_suite_passes_offline() {
    // Between prepare and deploy-site the digest is empty. The suite's
    // default-tag tests need one to exist, not to be the real one.
    let tmp = tempfile::tempdir().expect("tempdir");
    let staged = tmp.path().join("install.sh");
    let text = fs::read_to_string(BOOTSTRAP).expect("read install-remote.sh");
    let text = text.replace(
        "DEFAULT_ARCHIVE_SHA256=\"\"",
        &format!("DEFAULT_ARCHIVE_SHA256=\"{}\"", "0".repeat(64)),
    );
    fs::write(&staged, text).expect("stage install.sh");

    let out = Command::new("bash")
        .arg(SUITE)
        .env("INSTALL_SH", &staged)
        .env("INSTALL_REMOTE_TEST_OFFLINE", "1")
        .output()
        .expect("run bootstrap suite");
    assert!(
        out.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
