//! Issue #58: doctor probes workdir traversal instead of warning from config shape.

mod common;

use common::CliSeam;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u32>()
                .ok()
        })
        .unwrap_or(1)
        == 0
}

#[test]
fn doctor_silent_on_caller_service_user_when_cwd_traversable() {
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("manifests/empty.env"), "\n").unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = plainfile\nmanifest = empty.env\nworkdir = caller\ncommand = true\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = file\nservice_user = conductor\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .args(["doctor"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .env("VAULTED_AGENT_CALLER_CWD", seam.work_dir.as_os_str())
        .output()
        .expect("doctor");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains("cannot enter"),
        "traversable cwd must not warn:\n{combined}"
    );
    assert!(
        !combined.contains("WARN: workdir=caller with service_user"),
        "static shape warning must be gone:\n{combined}"
    );
}

#[test]
fn doctor_warns_when_caller_cwd_is_untraversable() {
    if is_root() {
        return;
    }
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("manifests/empty.env"), "\n").unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = plainfile\nmanifest = empty.env\nworkdir = caller\ncommand = true\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = file\nservice_user = conductor\n",
    )
    .unwrap();

    let blocked = seam.root.join("blocked");
    fs::create_dir(&blocked).unwrap();
    let mut perms = fs::metadata(&blocked).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&blocked, perms).unwrap();

    let out = seam
        .vaulted_agent()
        .args(["doctor"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .env("VAULTED_AGENT_CALLER_CWD", &blocked)
        .output()
        .expect("doctor");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("cannot enter"),
        "blocked path should warn:\n{combined}"
    );
    assert!(combined.contains("setfacl"), "{combined}");
    assert!(combined.contains("conductor"), "{combined}");

    let mut perms = fs::metadata(&blocked).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&blocked, perms).unwrap();
}
