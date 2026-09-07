//! Tickets 8–10: validation, auth_mode, workdir=caller.

mod common;

use common::CliSeam;
use std::fs;

fn write_plain_harness(seam: &CliSeam, name: &str, body: &str) {
    fs::write(
        seam.config_dir.join(format!("harnesses.d/{name}.conf")),
        body,
    )
    .unwrap();
}

#[test]
fn secrets_validate_fails_closed_on_unknown_backend() {
    let seam = CliSeam::new();
    // Harness load fails closed when backend is misspelled (typed Backend enum).
    fs::write(
        seam.config_dir.join("manifests/bad.refs"),
        "OPENAI_API_KEY=REPLACE_WITH_BITWARDEN_SECRET_UUID\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/typo.conf"),
        "backend = bitwarde\nmanifest = bad.refs\ncommand = true\n",
    )
    .unwrap();
    let out = seam
        .vaulted_agent()
        .args(["secrets", "validate"])
        .output()
        .expect("run");
    assert!(
        !out.status.success(),
        "unknown backend must not report ok: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn secrets_validate_rejects_placeholder_refs() {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("manifests/bad.env.refs"),
        "OPENAI_API_KEY=REPLACE_WITH_BITWARDEN_SECRET_UUID\n",
    )
    .unwrap();
    write_plain_harness(
        &seam,
        "claude",
        "backend = bitwarden\nmanifest = bad.env.refs\ncommand = true\n",
    );
    let out = seam
        .vaulted_agent()
        .args(["secrets", "validate", "claude"])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        err.contains("placeholder") || err.contains("FAIL") || err.contains("REPLACE"),
        "{err}"
    );
}

#[test]
fn secrets_validate_accepts_name_ref() {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("manifests/ok.env.refs"),
        "OPENAI_API_KEY=name:openai-api-key\n",
    )
    .unwrap();
    write_plain_harness(
        &seam,
        "claude",
        "backend = bitwarden\nmanifest = ok.env.refs\ncommand = true\n",
    );
    // --offline: this asserts that a `name:` ref is accepted as a valid *shape*.
    // Validate resolves against the vault by default now, which would need a
    // manager token this seam deliberately does not have.
    let out = seam
        .vaulted_agent()
        .args(["secrets", "validate", "claude", "--offline"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn secrets_validate_offline_rejects_glued_name_refs() {
    // Bash 0.3.0 refresh glued VAR=name:KEY lines together. Offline validate
    // must fail closed on the shape, not send the blob to the vault.
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("manifests/glued.env.refs"),
        "META_AI_API_KEY=name:META_AI_API_KEYFIREWORKS_API_KEY=name:FIREWORKS_API_KEY\n",
    )
    .unwrap();
    write_plain_harness(
        &seam,
        "grok",
        "backend = bitwarden\nmanifest = glued.env.refs\ncommand = true\n",
    );
    let out = seam
        .vaulted_agent()
        .args(["secrets", "validate", "grok", "--offline"])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(err.contains("glued onto one line"), "{err}");
    assert!(
        err.contains("FIREWORKS_API_KEY=name:FIREWORKS_API_KEY"),
        "{err}"
    );
}

#[test]
fn secrets_validate_without_a_token_fails_rather_than_passing_blind() {
    // The behaviour change that matters: a gate that cannot reach the vault
    // must say so, not report ok. Before this, no token meant a syntax check
    // and a cheerful exit 0.
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("manifests/ok.env.refs"),
        "OPENAI_API_KEY=name:openai-api-key\n",
    )
    .unwrap();
    write_plain_harness(
        &seam,
        "claude",
        "backend = bitwarden\nmanifest = ok.env.refs\ncommand = true\n",
    );
    let out = seam
        .vaulted_agent()
        .args(["secrets", "validate", "claude"])
        .output()
        .expect("run");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("bws.env") || err.contains("token"), "{err}");
}

#[test]
fn secrets_which_prints_var_names_only() {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("manifests/full.env"),
        "APP_DB_PASS=secret-value-must-not-print\nGH_TOKEN=also-secret\n",
    )
    .unwrap();
    write_plain_harness(
        &seam,
        "claude",
        "backend = plainfile\nmanifest = full.env\ncommand = true\n",
    );
    let out = seam
        .vaulted_agent()
        .args(["secrets", "which"])
        .output()
        .expect("run");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("APP_DB_PASS"), "{stdout}");
    assert!(stdout.contains("GH_TOKEN"), "{stdout}");
    assert!(!stdout.contains("secret-value"), "{stdout}");
    assert!(!stdout.contains("also-secret"), "{stdout}");
}

#[test]
fn auth_mode_set_file_writes_defaults() {
    let seam = CliSeam::new();
    let out = seam
        .vaulted_agent()
        .args(["auth-mode", "prompt"])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = fs::read_to_string(seam.config_dir.join("defaults.conf")).unwrap();
    assert!(
        text.contains("auth_mode = prompt") || text.contains("auth_mode=prompt"),
        "{text}"
    );
}

#[test]
fn workdir_caller_uses_invocation_cwd() {
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(seam.config_dir.join("manifests/empty.env"), "#\n").unwrap();
    write_plain_harness(
        &seam,
        "claude",
        "backend = plainfile\nmanifest = empty.env\nworkdir = caller\ncommand = agent\n",
    );
    // Nested workdir to prove cwd is preserved
    let nested = seam.work_dir.join("nested");
    fs::create_dir_all(&nested).unwrap();
    // Stub records cwd
    let record = nested.join("cwd.record");
    seam.write_executable(
        "agent",
        &format!(
            "#!/usr/bin/env bash\nset -euo pipefail\npwd > '{}'\n",
            record.display()
        ),
    );
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .current_dir(&nested)
        .arg("claude")
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cwd = fs::read_to_string(&record).unwrap();
    let cwd = cwd.trim();
    // macOS tempdirs are under /var → /private/var; compare canonical paths.
    assert_eq!(
        fs::canonicalize(cwd).unwrap(),
        fs::canonicalize(&nested).unwrap(),
        "expected workdir=caller → nested, got {cwd}"
    );
}

#[test]
fn workdir_absolute_overrides_caller() {
    let seam = CliSeam::new();
    let fixed = seam.root.join("fixed-wd");
    fs::create_dir_all(&fixed).unwrap();
    fs::write(seam.config_dir.join("manifests/empty.env"), "#\n").unwrap();
    let record = fixed.join("cwd.record");
    seam.write_executable(
        "agent",
        &format!(
            "#!/usr/bin/env bash\nset -euo pipefail\npwd > '{}'\n",
            record.display()
        ),
    );
    write_plain_harness(
        &seam,
        "claude",
        &format!(
            "backend = plainfile\nmanifest = empty.env\nworkdir = {}\ncommand = agent\n",
            fixed.display()
        ),
    );
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("claude")
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cwd = fs::read_to_string(&record).unwrap();
    assert_eq!(
        fs::canonicalize(cwd.trim()).unwrap(),
        fs::canonicalize(&fixed).unwrap()
    );
}
