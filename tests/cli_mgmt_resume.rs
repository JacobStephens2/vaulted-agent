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
    assert!(
        stdout.contains("Ready") || stdout.contains("0 error"),
        "{stdout}"
    );
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
    assert!(refs.contains("name:openai-api-key"), "{refs}");
    assert!(refs.contains("name:gh-token"), "{refs}");
    // Literal secret values from the fake vault must never land in the refs file.
    assert!(
        !refs.contains("=v")
            && !refs.contains("=g")
            && !refs.contains("\"v\"")
            && !refs.contains("\"g\""),
        "values leaked: {refs}"
    );
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
    assert!(
        !rec.contains(" my-label") && !rec.contains("'my-label'"),
        "label not mapped: {rec}"
    );
    assert!(rec.contains("--resume"), "{rec}");
    // Extract argv tokens after ARGV: and require a canonical UUID after --resume.
    let argv = rec.lines().find(|l| l.starts_with("ARGV:")).unwrap_or("");
    let uuid_re = regex_lite_uuid(argv);
    assert!(uuid_re, "expected UUIDv5 session id in argv, got: {argv}");
}

/// True if `s` contains a standard 8-4-4-4-12 hex UUID token.
fn regex_lite_uuid(s: &str) -> bool {
    // Walk for a token matching the UUID shape without pulling in the regex crate.
    for part in s.split(|c: char| c.is_whitespace() || c == '\'' || c == '"') {
        let b = part.as_bytes();
        if b.len() != 36 {
            continue;
        }
        let ok = (0..36).all(|i| match i {
            8 | 13 | 18 | 23 => b[i] == b'-',
            _ => b[i].is_ascii_hexdigit(),
        });
        if ok {
            return true;
        }
    }
    false
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
    assert!(
        stdout.contains("dry-run") || stdout.contains("uninstall"),
        "{stdout}"
    );
}

/// Issue #162: one Uninstall plan. Owned links and the launcher go; a foreign
/// `*-conductor` link and the Manager-token file stay, even under --purge.
#[test]
fn uninstall_purge_keeps_foreign_links_and_credentials() {
    use std::os::unix::fs::symlink;

    let seam = CliSeam::new();
    let bin = seam.root.join("prefix");
    fs::create_dir(&bin).unwrap();
    let launcher = bin.join("vaulted-agent");
    fs::write(&launcher, "#!/bin/sh\n").unwrap();
    symlink(&launcher, bin.join("va")).unwrap();
    symlink(&launcher, bin.join("claude-conductor")).unwrap();
    symlink("/bin/true", bin.join("other-conductor")).unwrap();
    let op_env = seam.config_dir.join("op.env");
    fs::write(&op_env, "OP_SERVICE_ACCOUNT_TOKEN=ops_fake\n").unwrap();
    fs::write(seam.config_dir.join("defaults.conf"), "auth_mode = file\n").unwrap();

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_BIN_DIR", &bin)
        .env_remove("SUDO_USER")
        .args(["uninstall", "--purge", "--yes"])
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout={stdout} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    for gone in ["vaulted-agent", "va", "claude-conductor"] {
        assert!(
            bin.join(gone).symlink_metadata().is_err(),
            "{gone}: {stdout}"
        );
    }
    assert!(bin.join("other-conductor").is_symlink(), "{stdout}");
    assert!(stdout.contains("(not ours)"), "{stdout}");
    assert!(op_env.is_file(), "{stdout}");
    assert!(!seam.config_dir.join("defaults.conf").exists(), "{stdout}");
    assert!(!seam.config_dir.join("harnesses.d").exists(), "{stdout}");
    assert!(stdout.contains("still holds op.env"), "{stdout}");
}

#[test]
fn secrets_list_uses_fake_bws() {
    let seam = CliSeam::new();
    let map = seam.write_secrets_json("secrets.json", r#"{"k1":"v1"}"#);
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
