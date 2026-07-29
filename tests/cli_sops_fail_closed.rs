//! #29: sops fails closed on placeholder decrypted values.

mod common;

use common::CliSeam;
use std::fs;

#[test]
fn sops_placeholder_value_aborts_launch() {
    let seam = CliSeam::new();
    seam.write_executable(
        "sops",
        "#!/usr/bin/env bash\nset -euo pipefail\necho 'APP_DB_PASS=REPLACE_WITH_SECRET'\n",
    );
    seam.install_stub_agent("agent");
    fs::write(seam.config_dir.join("age.key"), "AGE-SECRET-KEY-TEST\n").unwrap();
    fs::write(
        seam.config_dir.join("manifests/enc.env"),
        "APP_DB_PASS=encrypted\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/x.conf"),
        "backend = sops\nmanifest = enc.env\ncommand = agent\n",
    )
    .unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("x")
        .output()
        .expect("run");
    assert!(
        !out.status.success(),
        "expected fail-closed; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("placeholder") || err.contains("REPLACE"),
        "{err}"
    );
}
