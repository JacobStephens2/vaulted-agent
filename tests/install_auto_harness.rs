use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

#[test]
fn dry_run_auto_detects_agy_as_an_agent_harness() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bin = tmp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let agy = bin.join("agy");
    fs::write(&agy, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&agy, fs::Permissions::from_mode(0o755)).unwrap();

    let user_out = Command::new("id")
        .arg("-un")
        .output()
        .expect("current user");
    assert!(user_out.status.success());
    let user = String::from_utf8(user_out.stdout).unwrap();
    let path = std::env::join_paths([
        bin.as_path(),
        Path::new("/usr/local/bin"),
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])
    .unwrap();

    let out = Command::new("/bin/bash")
        .arg(format!("{}/install.sh", env!("CARGO_MANIFEST_DIR")))
        .args([
            "--dry-run",
            "--user",
            user.trim(),
            "--prefix",
            tmp.path().join("prefix").to_str().unwrap(),
            "--config",
            tmp.path().join("etc").to_str().unwrap(),
            "--no-link",
            "--no-va",
            "--no-setup",
        ])
        .env("HOME", tmp.path().join("home"))
        .env("PATH", path)
        .env("VAULTED_AGENT_BIN", env!("CARGO_BIN_EXE_vaulted-agent"))
        .env_remove("SUDO_USER")
        .output()
        .expect("install dry run");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("harnesses.d/agy.conf  (bin=") && stdout.contains("command=agy)"),
        "AGY live Harness was not proposed:\n{stdout}"
    );
    assert!(
        stdout.contains("va agy"),
        "AGY missing from next steps:\n{stdout}"
    );
    assert!(
        !stdout.contains("No claude/codex/grok/kimi/agy found"),
        "AGY must count as a detected agent:\n{stdout}"
    );
}
