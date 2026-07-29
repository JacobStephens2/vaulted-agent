//! #30: setup onepassword writes op.env when auth_mode=file.

mod common;

use common::CliSeam;
use std::fs;

#[test]
fn setup_onepassword_writes_op_env_file_mode() {
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("defaults.conf"), "auth_mode = file\n").unwrap();
    let out = seam
        .vaulted_agent()
        .env("OP_SERVICE_ACCOUNT_TOKEN", "ops-sa-test-token")
        .env("VAULTED_AGENT_AUTH_MODE", "file")
        .args(["setup", "onepassword"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let path = seam.config_dir.join("op.env");
    assert!(path.is_file(), "op.env missing");
    let text = fs::read_to_string(&path).unwrap();
    assert!(text.contains("OP_SERVICE_ACCOUNT_TOKEN=ops-sa-test-token"), "{text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640, "mode {mode:o}");
    }
}

#[test]
fn setup_onepassword_prompt_mode_does_not_write_file() {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = prompt\n",
    )
    .unwrap();
    let out = seam
        .vaulted_agent()
        .env("OP_SERVICE_ACCOUNT_TOKEN", "ops-should-not-disk")
        .env("VAULTED_AGENT_AUTH_MODE", "prompt")
        .args(["setup", "onepassword"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !seam.config_dir.join("op.env").is_file(),
        "op.env must not be written in prompt mode"
    );
}
