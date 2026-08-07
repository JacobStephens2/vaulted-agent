//! Issue #56: launch fails with a clear workdir traverse error, not bare exec EACCES.

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
fn launch_names_workdir_and_service_user_when_untraversable() {
    if is_root() {
        return;
    }
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(seam.config_dir.join("manifests/empty.env"), "\n").unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/probe.conf"),
        "backend = plainfile\nmanifest = empty.env\nworkdir = caller\ncommand = agent\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = file\nservice_user = conductor\n",
    )
    .unwrap();

    let blocked = seam.root.join("blocked-home");
    fs::create_dir(&blocked).unwrap();
    let mut perms = fs::metadata(&blocked).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&blocked, perms).unwrap();

    // Do not current_dir into blocked: the test process cannot enter it either.
    // workdir=caller reads VAULTED_AGENT_CALLER_CWD after the privilege hop.
    let out = seam
        .vaulted_agent()
        .args(["probe"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .env("VAULTED_AGENT_CALLER_CWD", &blocked)
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .output()
        .expect("launch");
    let err = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!out.status.success(), "must fail: {err}");
    assert!(
        err.contains("cannot enter") || err.contains("Permission denied"),
        "{err}"
    );
    assert!(err.contains("conductor"), "name service_user: {err}");
    assert!(err.contains("setfacl"), "name the ACL fix: {err}");

    let mut perms = fs::metadata(&blocked).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&blocked, perms).unwrap();
}
