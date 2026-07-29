//! CLI seam: version reporting (ticket: Cargo workspace + version CLI).
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vaulted-agent"))
}

#[test]
fn version_subcommand_prints_package_version_and_exits_zero() {
    let out = bin().arg("version").output().expect("run vaulted-agent version");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("vaulted-agent"),
        "stdout should name the tool: {stdout:?}"
    );
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "stdout should include CARGO_PKG_VERSION: {stdout:?}"
    );
}

#[test]
fn version_long_flag_prints_package_version_and_exits_zero() {
    let out = bin().arg("--version").output().expect("run --version");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn version_short_flag_prints_package_version_and_exits_zero() {
    let out = bin().arg("-V").output().expect("run -V");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}
