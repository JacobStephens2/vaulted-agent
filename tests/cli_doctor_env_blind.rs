//! Env-blind agent registry (etc/env-blind-agents) and doctor interaction.
//!
//! Issue #70: kimi is *not* structurally env-blind — do not warn on a non-empty
//! manifest for kimi. The list may still gain real env-blind tools later.

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
fn doctor_does_not_treat_kimi_as_env_blind() {
    // #70: non-empty manifest for kimi is a normal vault wiring, not a WARN.
    let seam = seam_kimi("OPENAI_API_KEY=vault-injected-key\n", "");
    let out = doctor(&seam);
    assert!(
        out.contains("manifest syntax ok"),
        "healthy non-empty kimi manifest:\n{out}"
    );
    assert!(
        !out.contains("env-blind")
            && !out.contains("silent no-op")
            && !out.contains("empty manifest is expected"),
        "kimi must not be classified env-blind:\n{out}"
    );
}

#[test]
fn doctor_warns_empty_manifest_for_kimi_like_other_agents() {
    // With env-blind removed, empty day-one is the same "finish setup" shape.
    let seam = seam_kimi("# none\n", "");
    let out = doctor(&seam);
    assert!(
        out.contains("WARN: manifest defines no variables"),
        "empty manifest should warn for kimi like claude:\n{out}"
    );
    assert!(
        !out.contains("empty manifest is expected"),
        "should not special-case kimi empty as expected:\n{out}"
    );
}

#[test]
fn doctor_does_not_warn_alias_on_kimi_as_env_blind() {
    let seam = seam_kimi(
        "OPENAI_API_KEY=a\nFIREWORKS_AI_API_KEY=b\n",
        "alias = OPENAI_API_KEY = FIREWORKS_AI_API_KEY\n",
    );
    let out = doctor(&seam);
    assert!(
        !out.contains("alias= is set on an env-blind agent"),
        "alias is valid for Fireworks-backed kimi (#66/#70):\n{out}"
    );
}
