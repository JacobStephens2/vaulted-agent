//! Tickets 15–22: management commands + resume/labels.

mod common;

use common::CliSeam;
use std::fs;

#[test]
fn doctor_reports_ready_for_plainfile_harness() {
    let seam = CliSeam::new();
    fs::write(seam.config_dir.join("manifests/empty.env"), "X=1\n").unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = plainfile\nmanifest = empty.env\nworkdir = caller\ncommand = true\n",
    )
    .unwrap();
    let out = seam.vaulted_agent().arg("doctor").output().expect("run");
    assert!(
        out.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Ready") || stdout.contains("0 error"), "{stdout}");
}

#[test]
fn doctor_fails_on_bad_manifest() {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("manifests/bad.env.refs"),
        "OPENAI_API_KEY=REPLACE_WITH_BITWARDEN_SECRET_UUID\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = bitwarden\nmanifest = bad.env.refs\ncommand = true\n",
    )
    .unwrap();
    let out = seam.vaulted_agent().arg("doctor").output().expect("run");
    assert!(!out.status.success());
}

#[test]
fn refresh_replace_all_writes_refs_from_fake_bws() {
    let seam = CliSeam::new();
    let map = seam.write_secrets_json("secrets.json", r#"{"openai-api-key":"v","gh-token":"g"}"#);
    let script = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail
map='{map}'
case "${{1-}} ${{2-}}" in
  "secret list")
    python3 -c "
import json
m=json.load(open('$map'))
print(json.dumps([{{'id': '00000000-0000-0000-0000-%012d' % i, 'key': k, 'project': {{'name': 'tools'}}}} for i,k in enumerate(m)]))
"
    ;;
  *) exit 1 ;;
esac
"#,
        map = map.display()
    );
    seam.write_executable("bws", &script);
    fs::write(seam.config_dir.join("bws.env"), "BWS_ACCESS_TOKEN=t\n").unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_AUTH_MODE", "file")
        .args(["refresh", "openai.env.refs", "--replace", "--all"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let refs = fs::read_to_string(seam.config_dir.join("manifests/openai.env.refs")).unwrap();
    assert!(refs.contains("name:openai-api-key") || refs.contains("OPENAI"), "{refs}");
    assert!(refs.contains("name:gh-token") || refs.contains("GH"), "{refs}");
    assert!(!refs.contains("v\n") && !refs.contains("=g\n"), "values leaked: {refs}");
}

#[test]
fn resume_codex_normalizes_flag_to_subcommand() {
    let seam = CliSeam::new();
    seam.install_stub_agent("codex");
    fs::write(seam.config_dir.join("manifests/empty.env"), "#\n").unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/codex.conf"),
        "backend = plainfile\nmanifest = empty.env\ncommand = codex\n",
    )
    .unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .args(["codex", "--resume", "abc-session"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("codex");
    assert!(rec.contains("resume"), "{rec}");
    assert!(rec.contains("abc-session"), "{rec}");
    // Should not pass --resume to codex
    assert!(
        !rec.contains("--resume"),
        "codex should get subcommand form: {rec}"
    );
}

#[test]
fn resume_claude_normalizes_bare_resume_to_flag() {
    let seam = CliSeam::new();
    seam.install_stub_agent("claude");
    fs::write(seam.config_dir.join("manifests/empty.env"), "#\n").unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = plainfile\nmanifest = empty.env\ncommand = claude\n",
    )
    .unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .args(["claude", "resume", "sess-1"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("claude");
    assert!(rec.contains("--resume"), "{rec}");
    assert!(rec.contains("sess-1"), "{rec}");
}

#[test]
fn labels_maps_non_uuid_session_to_uuidv5() {
    let seam = CliSeam::new();
    seam.install_stub_agent("claude");
    fs::write(seam.config_dir.join("manifests/empty.env"), "#\n").unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = plainfile\nmanifest = empty.env\nlabels = yes\ncommand = claude\n",
    )
    .unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .args(["claude", "--resume", "my-label"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("claude");
    // Expect a UUID shape in argv, not the raw label
    assert!(!rec.contains(" my-label") && !rec.contains("'my-label'"), "label not mapped: {rec}");
    // UUID pattern roughly
    assert!(
        rec.contains("--resume")
            && rec.chars().filter(|c| *c == '-').count() >= 4,
        "{rec}"
    );
}

#[test]
fn uninstall_dry_run_exits_zero() {
    let seam = CliSeam::new();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_BIN_DIR", seam.path_dir.display().to_string())
        .args(["uninstall", "--dry-run", "-y"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("dry-run") || stdout.contains("uninstall"), "{stdout}");
}

#[test]
fn secrets_list_uses_fake_bws() {
    let seam = CliSeam::new();
    let map = seam.write_secrets_json("secrets.json", r#"{"k1":"v1"}"#);
    let script = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail
map='{map}'
python3 -c "
import json
m=json.load(open('$map'))
print(json.dumps([{{'id': '00000000-0000-0000-0000-000000000001', 'key': k, 'project': {{'name': 'p'}}}} for k in m]))
"
"#,
        map = map.display()
    );
    // bws secret list
    seam.write_executable(
        "bws",
        &format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
map='{map}'
case "${{1-}} ${{2-}}" in
  "secret list")
    python3 -c "
import json
m=json.load(open('$map'))
print(json.dumps([{{'id': '00000000-0000-0000-0000-000000000001', 'key': k, 'project': {{'name': 'p'}}}} for k in m]))
"
    ;;
  *) exit 1 ;;
esac
"#,
            map = map.display()
        ),
    );
    let _ = script;
    fs::write(seam.config_dir.join("bws.env"), "BWS_ACCESS_TOKEN=t\n").unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_AUTH_MODE", "file")
        .args(["secrets", "list"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("k1"), "{stdout}");
}
