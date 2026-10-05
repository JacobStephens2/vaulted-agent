//! Issue #146: `defaults.conf` is read through Machine defaults, which fails
//! closed on a file it cannot read or a value it does not recognise.

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

fn plainfile_harness(seam: &CliSeam, name: &str) {
    fs::write(
        seam.config_dir.join(format!("harnesses.d/{name}.conf")),
        format!("backend = plainfile\nmanifest = empty.env\ncommand = {name}\n"),
    )
    .unwrap();
    fs::write(seam.config_dir.join("manifests/empty.env"), "# empty\n").unwrap();
}

#[test]
fn an_unreadable_defaults_conf_stops_a_launch_before_the_agent_runs() {
    if is_root() {
        // chmod 000 does not deny root; nothing useful to assert.
        return;
    }
    let seam = CliSeam::new();
    seam.install_stub_agent("claude");
    plainfile_harness(&seam, "claude");
    let defaults = seam.config_dir.join("defaults.conf");
    fs::write(&defaults, "service_user = conductor\n").unwrap();
    fs::set_permissions(&defaults, fs::Permissions::from_mode(0o000)).unwrap();

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("claude")
        .output()
        .expect("run");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "a launch must not run as the caller");
    assert!(err.contains(&defaults.display().to_string()), "{err}");
    assert!(err.contains("Permission denied"), "{err}");
    assert!(
        !seam.work_dir.join("claude.record").exists(),
        "the agent ran: {err}"
    );
}

#[test]
fn a_typod_auth_mode_fails_validate_with_its_line_and_auth_mode_repairs_it() {
    let seam = CliSeam::new();
    plainfile_harness(&seam, "claude");
    let defaults = seam.config_dir.join("defaults.conf");
    fs::write(
        &defaults,
        "# Machine-wide launcher defaults.\nauth_mode = promt\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .args(["secrets", "validate", "--offline"])
        .output()
        .expect("run");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("defaults.conf:2:"), "{err}");
    assert!(err.contains("promt"), "{err}");

    let out = seam
        .vaulted_agent()
        .args(["auth-mode", "file"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read_to_string(&defaults).unwrap(),
        "# Machine-wide launcher defaults.\nauth_mode = file\n"
    );

    let out = seam
        .vaulted_agent()
        .args(["secrets", "validate", "--offline"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn doctor_reports_a_bad_defaults_conf_once_and_carries_on() {
    let seam = CliSeam::new();
    plainfile_harness(&seam, "claude");
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "default_backend = bitwarde\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .arg("doctor")
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!out.status.success(), "{stdout}");
    assert_eq!(
        stdout
            .lines()
            .filter(|l| l.contains("defaults.conf:1:"))
            .count(),
        1,
        "{stdout}"
    );
    assert!(stdout.contains("ERROR: defaults.conf:1:"), "{stdout}");
    assert!(stdout.contains("auth_mode: file (built-in)"), "{stdout}");
    assert!(
        stdout.contains("default_backend: onepassword (built-in)"),
        "{stdout}"
    );
    // The Harness checks still ran.
    assert!(stdout.contains("harness: claude"), "{stdout}");
}

#[test]
fn an_invalid_default_backend_override_stops_run() {
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("manifests/empty.env"), "# empty\n").unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_DEFAULT_BACKEND", "vault")
        .args(["run", "-m", "empty.env", "--", "true"])
        .output()
        .expect("run");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(err.contains("VAULTED_AGENT_DEFAULT_BACKEND"), "{err}");
}
