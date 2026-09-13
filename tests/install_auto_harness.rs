use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use vaulted_agent::config::Harness;

#[test]
fn install_discovers_muse_and_preserves_an_existing_profile() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bin = tmp.path().join("bin");
    let config = tmp.path().join("etc");
    fs::create_dir(&bin).unwrap();
    let agents = ["claude", "codex", "grok", "kimi", "agy", "muse"];
    for name in agents {
        let agent = bin.join(name);
        fs::write(&agent, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let user_out = Command::new("id").arg("-un").output().unwrap();
    assert!(user_out.status.success());
    let user = String::from_utf8(user_out.stdout).unwrap();
    let path = std::env::join_paths([
        bin.as_path(),
        Path::new("/usr/bin"),
        Path::new("/bin"),
        Path::new("/usr/sbin"),
        Path::new("/sbin"),
    ])
    .unwrap();
    let mut installer = Command::new("/bin/bash");
    installer
        .arg(format!("{}/install.sh", env!("CARGO_MANIFEST_DIR")))
        .args(["--user", user.trim(), "--no-link", "--no-va", "--no-setup"])
        .arg("--prefix")
        .arg(tmp.path().join("prefix"))
        .arg("--config")
        .arg(&config)
        .arg("--workdir")
        .arg(tmp.path())
        .env_clear()
        .env("HOME", tmp.path().join("home"))
        .env("PATH", &path)
        .env("VAULTED_AGENT_BIN", env!("CARGO_BIN_EXE_vaulted-agent"));
    let out = installer.output().expect("install");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout={stdout}\nstderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let profile = config.join("harnesses.d/muse.conf");
    let contents = fs::read_to_string(&profile).expect("detected Muse has a live Harness");
    for (key, value) in [
        ("command", "muse"),
        ("backend", "plainfile"),
        ("manifest", "empty.env"),
        ("workdir", "caller"),
        ("bin", bin.to_str().unwrap()),
    ] {
        assert!(
            contents.lines().any(|line| line
                .split_once('=')
                .is_some_and(|(k, v)| k.trim() == key && v.trim() == value)),
            "missing {key}={value}: {contents}"
        );
    }
    assert!(config.join("harnesses.d/muse.conf.example").is_file());
    assert!(config.join("manifests/empty.env").is_file());
    assert!(stdout.contains("va muse"), "{stdout}");
    assert!(!stdout.contains("found. Install an agent CLI"), "{stdout}");

    // Both entry points must apply the same automatic defaults. Example
    // profiles intentionally make different command/permission choices.
    let update_config = tmp.path().join("update-config");
    let out = Command::new(env!("CARGO_BIN_EXE_vaulted-agent"))
        .args(["update", "--sync-harnesses"])
        .env_clear()
        .env("HOME", tmp.path().join("home"))
        .env("PATH", &path)
        .env("VAULTED_AGENT_CONFIG_DIR", &update_config)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for name in agents.into_iter().chain(["bash"]) {
        let relative = format!("harnesses.d/{name}.conf");
        let installed =
            Harness::parse(name, &fs::read_to_string(config.join(&relative)).unwrap()).unwrap();
        let updated = Harness::parse(
            name,
            &fs::read_to_string(update_config.join(&relative)).unwrap(),
        )
        .unwrap();
        assert_eq!(installed.command, updated.command, "{name}");
        assert_eq!(installed.keep, updated.keep, "{name}");
        assert_eq!(installed.env_sets, updated.env_sets, "{name}");
        assert_eq!(installed.backend, updated.backend, "{name}");
        assert_eq!(installed.manifest, updated.manifest, "{name}");
        assert_eq!(installed.workdir, updated.workdir, "{name}");
    }

    let custom =
        "backend = bitwarden\nmanifest = custom.refs\nworkdir = caller\ncommand = muse --yolo\n";
    fs::write(&profile, custom).unwrap();
    let out = installer.output().expect("reinstall");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read_to_string(profile).unwrap(), custom);
}

#[test]
fn dry_run_auto_detects_agy_as_an_agent_harness() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bin = tmp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let agy = bin.join("agy");
    fs::write(&agy, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&agy, fs::Permissions::from_mode(0o755)).unwrap();

    let user_out = Command::new("id")
        .arg("-un")
        .output()
        .expect("current user");
    assert!(user_out.status.success());
    let user = String::from_utf8(user_out.stdout).unwrap();
    let path = std::env::join_paths([
        bin.as_path(),
        Path::new("/usr/local/bin"),
        Path::new("/usr/bin"),
        Path::new("/bin"),
    ])
    .unwrap();

    let out = Command::new("/bin/bash")
        .arg(format!("{}/install.sh", env!("CARGO_MANIFEST_DIR")))
        .args([
            "--dry-run",
            "--user",
            user.trim(),
            "--prefix",
            tmp.path().join("prefix").to_str().unwrap(),
            "--config",
            tmp.path().join("etc").to_str().unwrap(),
            "--no-link",
            "--no-va",
            "--no-setup",
        ])
        .env("HOME", tmp.path().join("home"))
        .env("PATH", path)
        .env("VAULTED_AGENT_BIN", env!("CARGO_BIN_EXE_vaulted-agent"))
        .env_remove("SUDO_USER")
        .output()
        .expect("install dry run");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("harnesses.d/agy.conf  (bin=") && stdout.contains("command=agy)"),
        "AGY live Harness was not proposed:\n{stdout}"
    );
    assert!(
        stdout.contains("va agy"),
        "AGY missing from next steps:\n{stdout}"
    );
    assert!(
        !stdout.contains("found. Install an agent CLI"),
        "AGY must count as a detected agent:\n{stdout}"
    );
}
