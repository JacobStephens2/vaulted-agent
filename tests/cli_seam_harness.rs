//! CLI seam harness smoke tests (ticket: CLI test harness).
mod common;

use common::CliSeam;

#[test]
fn harness_runs_version_with_isolated_config_and_path() {
    let seam = CliSeam::new();
    let out = seam
        .vaulted_agent()
        .arg("version")
        .output()
        .expect("run version via seam");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("vaulted-agent"));
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
    // config dir was created for isolation
    assert!(seam.config_dir.join("harnesses.d").is_dir());
    assert!(seam.config_dir.join("manifests").is_dir());
}

#[test]
fn stub_agent_records_env_and_argv_when_invoked() {
    let seam = CliSeam::new();
    seam.install_stub_agent("stub-agent");
    let status = std::process::Command::new(seam.path_dir.join("stub-agent"))
        .args(["--hello", "world"])
        .env(
            "PATH",
            format!(
                "{}:{}",
                seam.path_dir.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .env("PARENT_ONLY_SECRET", "should-appear-in-record-as-name")
        .current_dir(&seam.work_dir)
        .status()
        .expect("run stub");
    assert!(status.success());
    let rec = seam.read_stub_record("stub-agent");
    assert!(rec.contains("ARGV:"), "{rec}");
    assert!(rec.contains("--hello"), "{rec}");
    assert!(rec.contains("ENV PARENT_ONLY_SECRET") || rec.contains("PARENT_ONLY_SECRET"), "{rec}");
}

#[test]
fn fake_bws_secret_list_returns_json_array() {
    let seam = CliSeam::new();
    let map = seam.write_secrets_json("secrets.json", r#"{"openai-api-key":"sk-test"}"#);
    seam.install_fake_bws(&map);
    let out = std::process::Command::new(seam.path_dir.join("bws"))
        .args(["secret", "list"])
        .output()
        .expect("fake bws list");
    assert!(out.status.success(), "stderr={}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("openai-api-key"), "{stdout}");
}
