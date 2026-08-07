//! Issue #51: unreadable token file is not reported as "missing".

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
fn doctor_reports_unreadable_op_env_not_missing() {
    if is_root() {
        // chmod 000 does not deny root; nothing useful to assert.
        return;
    }
    let seam = CliSeam::new();
    let path = seam.config_dir.join("op.env");
    fs::write(&path, "OP_SERVICE_ACCOUNT_TOKEN=dummy\n").unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&path, perms).unwrap();

    let out = seam
        .vaulted_agent()
        .args(["doctor"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let combined = format!("{stdout}{}", String::from_utf8_lossy(&out.stderr));

    assert!(
        combined.contains("op.env: unreadable"),
        "expected unreadable, got:\n{combined}"
    );
    assert!(
        !combined.contains("op.env: missing"),
        "must not call an unreadable file missing:\n{combined}"
    );
    assert!(
        combined.contains("no service_user set") || combined.contains("HINT: no service_user"),
        "should hint at service_user when unset:\n{combined}"
    );

    // Restore for cleanup.
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms).unwrap();
}

#[test]
fn launch_fails_closed_on_unreadable_token_without_prompting_as_missing() {
    if is_root() {
        return;
    }
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/op.env.refs"),
        "A=op://V/item/field\n",
    )
    .unwrap();
    // onepassword so load_manager_token reads op.env in file mode.
    fs::write(
        seam.config_dir.join("harnesses.d/opprobe.conf"),
        "backend = onepassword\nmanifest = op.env.refs\ncommand = agent\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = file\ndefault_backend = onepassword\n",
    )
    .unwrap();
    let path = seam.config_dir.join("op.env");
    fs::write(&path, "OP_SERVICE_ACCOUNT_TOKEN=dummy\n").unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o000);
    fs::set_permissions(&path, perms).unwrap();

    // Non-interactive: no TTY for a fall-through prompt even if code regressed.
    let out = seam
        .vaulted_agent()
        .args(["opprobe"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("launch");
    let err = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(!out.status.success(), "must not launch: {err}");
    assert!(
        err.contains("cannot read") || err.contains("Permission denied"),
        "expected permission error, not missing:\n{err}"
    );
    assert!(
        !err.contains("onepassword missing"),
        "must not report unreadable as missing:\n{err}"
    );

    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&path, perms).unwrap();
}
