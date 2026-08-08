//! Harness `alias = TARGET = SOURCE` (issue #66).
//!
//! One shared manifest can hold both OPENAI_API_KEY and FIREWORKS_AI_API_KEY.
//! An agent that hardcodes OPENAI_API_KEY for a non-OpenAI provider needs the
//! Fireworks value under that name for *this harness only*.

mod common;

use common::CliSeam;
use std::fs;

#[test]
fn alias_puts_source_value_on_target_in_child_env() {
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/shared.env"),
        "OPENAI_API_KEY=openai-key-wrong-for-fireworks\n\
         FIREWORKS_AI_API_KEY=fireworks-key-correct\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/kimi.conf"),
        "backend  = plainfile\n\
         manifest = shared.env\n\
         alias    = OPENAI_API_KEY = FIREWORKS_AI_API_KEY\n\
         command  = agent\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("kimi")
        .output()
        .expect("launch");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("agent");
    assert!(
        rec.contains("ENV OPENAI_API_KEY=fireworks-key-correct"),
        "alias must overwrite target with source value:\n{rec}"
    );
    // Copy, not move.
    assert!(
        rec.contains("ENV FIREWORKS_AI_API_KEY=fireworks-key-correct"),
        "source must remain:\n{rec}"
    );
}

#[test]
fn alias_missing_source_fails_before_agent_runs() {
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/shared.env"),
        "OPENAI_API_KEY=openai-only\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/kimi.conf"),
        "backend  = plainfile\n\
         manifest = shared.env\n\
         alias    = OPENAI_API_KEY = FIREWORKS_AI_API_KEY\n\
         command  = agent\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("kimi")
        .output()
        .expect("launch");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("FIREWORKS_AI_API_KEY") && err.contains("not in the resolved manifest"),
        "{err}"
    );
    // Agent must not have started with the wrong credential.
    assert!(
        !seam.work_dir.join("agent.record").exists(),
        "agent must not run when alias fails"
    );
}

#[test]
fn harness_without_alias_keeps_manifest_value() {
    // Same shared manifest; another harness must not get the kimi rename.
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/shared.env"),
        "OPENAI_API_KEY=openai-key\n\
         FIREWORKS_AI_API_KEY=fireworks-key\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend  = plainfile\n\
         manifest = shared.env\n\
         command  = agent\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("claude")
        .output()
        .expect("launch");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("agent");
    assert!(
        rec.contains("ENV OPENAI_API_KEY=openai-key"),
        "no alias: manifest value stands:\n{rec}"
    );
}
