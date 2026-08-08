//! Issue #68: doctor must not green-light a vault manifest for env-blind agents.
//!
//! Kimi (and tools like it) do not read custom provider credentials from the
//! process environment. A harness pointed at a real refs file looks healthy
//! under syntax checks and fails later inside the agent.

mod common;

use common::CliSeam;
use std::fs;

fn doctor(seam: &CliSeam) -> String {
    let out = seam
        .vaulted_agent()
        .args(["doctor"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("doctor");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Kimi harness under plainfile, with the given manifest body and optional
/// extra harness conf lines (e.g. alias=).
fn seam_kimi(manifest_body: &str, harness_extra: &str) -> CliSeam {
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("manifests/m.env"), manifest_body).unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/kimi.conf"),
        format!("backend = plainfile\nmanifest = m.env\n{harness_extra}command = kimi --auto\n"),
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = file\ndefault_backend = plainfile\n",
    )
    .unwrap();
    seam
}

#[test]
fn doctor_warns_when_kimi_points_at_a_nonempty_manifest() {
    let seam = seam_kimi("OPENAI_API_KEY=plain-not-used-by-kimi\n", "");
    let out = doctor(&seam);
    assert!(
        out.contains("WARN:") && out.contains("kimi"),
        "env-blind agent with secrets in the manifest must warn:\n{out}"
    );
    assert!(
        out.contains("config.toml") || out.contains("process environment"),
        "message must say where the key actually belongs:\n{out}"
    );
}

#[test]
fn doctor_accepts_empty_manifest_for_kimi() {
    let seam = seam_kimi("# none\n", "");
    let out = doctor(&seam);
    assert!(
        !out.contains("WARN: manifest defines no variables"),
        "empty.env for kimi is expected, not a finish-setup warning:\n{out}"
    );
    assert!(
        out.contains("empty manifest is expected") || out.contains("note:"),
        "should note empty is OK for kimi:\n{out}"
    );
}

#[test]
fn doctor_warns_on_useless_alias_for_kimi() {
    let seam = seam_kimi(
        "OPENAI_API_KEY=a\nFIREWORKS_AI_API_KEY=b\n",
        "alias = OPENAI_API_KEY = FIREWORKS_AI_API_KEY\n",
    );
    let out = doctor(&seam);
    assert!(
        out.contains("alias") && out.contains("WARN"),
        "alias on env-blind agent must warn:\n{out}"
    );
}
