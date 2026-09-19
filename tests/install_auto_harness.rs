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
fn install_resolves_auto_harnesses_for_the_service_account() {
    // Invoking user (SUDO_USER) and service account (--user) differ. Per-user
    // PATHs and homes are emulated with shims, so this needs no real accounts
    // and never touches the developer's home or installed agents.
    let tmp = tempfile::tempdir().expect("tempdir");
    let shim = tmp.path().join("shim");
    let users = tmp.path().join("users");
    let svc_bin = tmp.path().join("svc-bin");
    let invoker_bin = tmp.path().join("invoker-bin");
    let svc_home = tmp.path().join("svc-home");
    let invoker_home = tmp.path().join("invoker-home");
    for dir in [
        &shim,
        &users,
        &svc_bin,
        &invoker_bin,
        &svc_home,
        &invoker_home,
    ] {
        fs::create_dir(dir).unwrap();
    }
    let svc_local_bin = svc_home.join(".local/bin");
    let invoker_local_bin = invoker_home.join(".local/bin");
    fs::create_dir_all(&svc_local_bin).unwrap();
    fs::create_dir_all(&invoker_local_bin).unwrap();

    fn executable(path: &Path) {
        fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    // Fictitious CLI names (via VAULTED_AGENT_AUTO_HARNESSES below) so no
    // agent installed on the developer's machine can interfere: invokeronly
    // lives only on the invoking user's PATH, invokerhomeonly only in the
    // invoking user's ~/.local/bin, svconly only on the service account's
    // PATH, homeonly only in the service account's ~/.local/bin.
    executable(&invoker_bin.join("invokeronly"));
    executable(&invoker_local_bin.join("invokerhomeonly"));
    executable(&svc_bin.join("svconly"));
    executable(&svc_local_bin.join("homeonly"));
    fs::write(
        tmp.path().join("auto-harnesses"),
        "invokeronly\ninvokerhomeonly\nsvconly\nhomeonly\nbash\n",
    )
    .unwrap();

    fs::write(
        users.join("svc"),
        format!("{}:/usr/bin:/bin", svc_bin.display()),
    )
    .unwrap();
    fs::write(
        users.join("invoker"),
        format!("{}:/usr/bin:/bin", invoker_bin.display()),
    )
    .unwrap();
    fs::write(users.join("svc.home"), svc_home.to_str().unwrap()).unwrap();
    fs::write(users.join("invoker.home"), invoker_home.to_str().unwrap()).unwrap();

    // sudo -nu <user> -- command -v <name> with a per-user PATH from $users.
    fs::write(
        shim.join("sudo"),
        r#"#!/bin/bash
user=""
if [[ "${1:-}" == "-nu" ]]; then user="${2:-}"; shift 2; fi
if [[ "${1:-}" == "--" ]]; then shift; fi
if [[ "${1:-}" == "command" ]]; then
  shift
  if [[ -f "$FAKE_USER_PATHS/$user" ]]; then
    PATH="$(cat "$FAKE_USER_PATHS/$user")" command -v "$@"
    exit $?
  fi
  exit 1
fi
echo "fake sudo: unsupported invocation: $*" >&2
exit 1
"#,
    )
    .unwrap();
    // getent passwd <user> served from $users/<user>.home; unknown users fail
    // so user_home falls through exactly as it would for a stranger.
    fs::write(
        shim.join("getent"),
        r#"#!/bin/bash
if [[ "${1:-}" == "passwd" && -n "${2:-}" && -f "$FAKE_USER_PATHS/$2.home" ]]; then
  printf '%s:x:1001:1001::%s:/bin/bash\n' "$2" "$(cat "$FAKE_USER_PATHS/$2.home")"
  exit 0
fi
exit 1
"#,
    )
    .unwrap();
    let real_id = ["/usr/bin/id", "/bin/id"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .expect("a real id binary");
    fs::write(
        shim.join("id"),
        format!(
            r#"#!/bin/bash
if [[ "${{1:-}}" == "-u" && -n "${{2:-}}" && -f "$FAKE_USER_PATHS/$2.home" ]]; then exit 0; fi
if [[ "${{1:-}}" == "-gn" && -n "${{2:-}}" && -f "$FAKE_USER_PATHS/$2.home" ]]; then printf 'staff\n'; exit 0; fi
exec {real_id} "$@"
"#
        ),
    )
    .unwrap();
    for name in ["sudo", "getent", "id"] {
        fs::set_permissions(shim.join(name), fs::Permissions::from_mode(0o755)).unwrap();
    }

    let path = std::env::join_paths([
        shim.as_path(),
        Path::new("/usr/bin"),
        Path::new("/bin"),
        Path::new("/usr/sbin"),
        Path::new("/sbin"),
    ])
    .unwrap();
    let config = tmp.path().join("etc");
    let out = Command::new("/bin/bash")
        .arg(format!("{}/install.sh", env!("CARGO_MANIFEST_DIR")))
        .args(["--user", "svc", "--no-link", "--no-va", "--no-setup"])
        .arg("--prefix")
        .arg(tmp.path().join("prefix"))
        .arg("--config")
        .arg(&config)
        .arg("--workdir")
        .arg(tmp.path())
        .env_clear()
        .env("HOME", tmp.path().join("home"))
        .env("PATH", &path)
        .env("SUDO_USER", "invoker")
        .env("FAKE_USER_PATHS", &users)
        .env(
            "VAULTED_AGENT_AUTO_HARNESSES",
            tmp.path().join("auto-harnesses"),
        )
        .env("VAULTED_AGENT_BIN", env!("CARGO_BIN_EXE_vaulted-agent"))
        .output()
        .expect("install");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout={stdout}\nstderr={stderr}");

    // Service-account binaries produce live harnesses pointing at the service
    // account's directories (PATH hit and home-dir fallback alike).
    for (name, dir) in [
        ("svconly", svc_bin.to_str().unwrap()),
        ("homeonly", svc_local_bin.to_str().unwrap()),
    ] {
        let contents = fs::read_to_string(config.join(format!("harnesses.d/{name}.conf")))
            .unwrap_or_else(|_| panic!("{name} needs a live Harness:\n{stdout}"));
        assert!(
            contents.lines().any(|line| line
                .split_once('=')
                .is_some_and(|(k, v)| k.trim() == "bin" && v.trim() == dir)),
            "missing bin={dir}:\n{contents}"
        );
    }
    // System-wide binaries stay detectable for either installation shape.
    assert!(
        config.join("harnesses.d/bash.conf").is_file(),
        "system bash must stay detectable:\n{stdout}"
    );
    // Invoker-only binaries must not leak into the service account's config,
    // whether they live on the invoker's PATH or in the invoker's home.
    for name in ["invokeronly", "invokerhomeonly"] {
        assert!(
            !config.join(format!("harnesses.d/{name}.conf")).exists(),
            "{name} must not create a live Harness"
        );
        assert!(
            stdout.contains(name) && stdout.contains("invoker") && stdout.contains("svc"),
            "skip message for {name} must name the binary and both identities:\n{stdout}"
        );
        assert!(
            stdout.contains(&format!("install {name} for svc")),
            "skip message for {name} must give a concrete remedy:\n{stdout}"
        );
    }
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
