//! CLI seam: `va update` replaces the installed launcher binary.
//!
//! Network is not a seam. Tests feed a local tarball through
//! `VAULTED_AGENT_UPDATE_ASSET` and a writable dest through
//! `VAULTED_AGENT_UPDATE_DEST`.

mod common;

use common::CliSeam;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn write_executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn pack_asset(dir: &Path, member_name: &str, body: &str) -> std::path::PathBuf {
    let staged = dir.join("staged");
    fs::create_dir_all(&staged).unwrap();
    write_executable(&staged.join(member_name), body);
    let tgz = dir.join("asset.tar.gz");
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&tgz)
        .arg("-C")
        .arg(&staged)
        .arg(member_name)
        .status()
        .expect("tar");
    assert!(status.success(), "fixture tarball");
    tgz
}

#[test]
fn update_is_a_management_command_not_an_unknown_harness() {
    let seam = CliSeam::new();
    let dest = seam.root.join("installed/vaulted-agent");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    write_executable(&dest, "#!/bin/sh\necho vaulted-agent 0.0.1\n");

    let out = seam
        .vaulted_agent()
        .arg("update")
        .arg("--check")
        .arg("v0.4.20")
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unknown command"),
        "update should be reserved, not a missing harness\nstderr={stderr}"
    );
    assert!(
        out.status.success(),
        "stderr={stderr} stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn update_check_names_current_and_target() {
    let seam = CliSeam::new();
    let dest = seam.root.join("installed/vaulted-agent");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    write_executable(&dest, "#!/bin/sh\necho vaulted-agent 0.0.1\n");

    let out = seam
        .vaulted_agent()
        .arg("update")
        .arg("--check")
        .arg("v0.4.20")
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "should print the running version\n{stdout}"
    );
    assert!(
        stdout.contains("v0.4.20"),
        "should print the requested tag\n{stdout}"
    );
}

#[test]
fn update_replaces_dest_from_a_local_tarball() {
    let seam = CliSeam::new();
    let dest = seam.root.join("installed/vaulted-agent");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    write_executable(&dest, "#!/bin/sh\necho vaulted-agent 0.0.1\n");

    let tgz = pack_asset(
        &seam.root,
        "vaulted-agent",
        "#!/bin/sh\necho 'vaulted-agent 9.9.9'\n",
    );

    let out = seam
        .vaulted_agent()
        .arg("update")
        .arg("v9.9.9")
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .env("VAULTED_AGENT_UPDATE_ASSET", &tgz)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    let probe = Command::new(&dest).arg("version").output().expect("probe");
    let stdout = String::from_utf8_lossy(&probe.stdout);
    assert!(
        stdout.contains("9.9.9"),
        "dest should now be the asset\nstdout={stdout}\nstderr={}",
        String::from_utf8_lossy(&probe.stderr)
    );
}

#[test]
fn update_dry_run_does_not_replace_dest() {
    let seam = CliSeam::new();
    let dest = seam.root.join("installed/vaulted-agent");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    write_executable(&dest, "#!/bin/sh\necho vaulted-agent 0.0.1\n");
    let tgz = pack_asset(
        &seam.root,
        "vaulted-agent",
        "#!/bin/sh\necho 'vaulted-agent 9.9.9'\n",
    );

    let out = seam
        .vaulted_agent()
        .arg("update")
        .arg("--dry-run")
        .arg("v9.9.9")
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .env("VAULTED_AGENT_UPDATE_ASSET", &tgz)
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let probe = Command::new(&dest).arg("version").output().expect("probe");
    let stdout = String::from_utf8_lossy(&probe.stdout);
    assert!(
        stdout.contains("0.0.1"),
        "dry-run must leave dest alone\n{stdout}"
    );
}

fn pack_current_binary(seam: &CliSeam) -> std::path::PathBuf {
    let staged = seam.root.join("release");
    fs::create_dir(&staged).unwrap();
    fs::copy(
        env!("CARGO_BIN_EXE_vaulted-agent"),
        staged.join("vaulted-agent"),
    )
    .unwrap();
    let archive = seam.root.join("current.tar.gz");
    assert!(Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(staged)
        .arg("vaulted-agent")
        .status()
        .unwrap()
        .success());
    archive
}

fn isolated_update(seam: &CliSeam) -> Command {
    let mut cmd = seam.vaulted_agent();
    cmd.env_clear()
        .env("HOME", seam.root.join("home"))
        .env("PATH", format!("{}:/usr/bin:/bin", seam.path_dir.display()))
        .env("VAULTED_AGENT_CONFIG_DIR", &seam.config_dir);
    cmd
}

#[test]
fn update_adds_a_missing_muse_harness_and_launches_with_the_shared_manifest() {
    let seam = CliSeam::new();
    seam.install_stub_agent("muse");
    seam.write_harness(
        "claude",
        "backend = plainfile\nmanifest = shared.env\ncommand = claude\n",
    );
    fs::write(
        seam.config_dir.join("manifests/shared.env"),
        "APP_TOKEN=synthetic\n",
    )
    .unwrap();
    let archive = pack_current_binary(&seam);
    let dest = seam.root.join("installed/vaulted-agent");
    let out = isolated_update(&seam)
        .args(["update", "v9.9.9"])
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .env("VAULTED_AGENT_UPDATE_ASSET", archive)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        seam.config_dir.join("harnesses.d/muse.conf").is_file(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let out = Command::new(dest)
        .env_clear()
        .env("HOME", seam.root.join("home"))
        .env("PATH", "/usr/bin:/bin")
        .env("VAULTED_AGENT_CONFIG_DIR", &seam.config_dir)
        .current_dir(&seam.work_dir)
        .args(["muse", "--yolo"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let record = seam.read_stub_record("muse");
    assert_eq!(record.lines().next(), Some("ARGV: --yolo"));
    assert!(record.contains("ENV APP_TOKEN=synthetic\n"), "{record}");
}

#[test]
fn sync_keeps_codex_native_permissions() {
    let seam = CliSeam::new();
    seam.install_stub_agent("codex");
    let out = isolated_update(&seam)
        .args(["update", "--sync-harnesses"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = isolated_update(&seam)
        .args(["codex", "--help"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        seam.read_stub_record("codex").lines().next(),
        Some("ARGV: --help")
    );
}

#[test]
fn sync_preserves_existing_profiles_even_dangling_symlinks() {
    let seam = CliSeam::new();
    seam.install_stub_agent("muse");
    let profile = seam.config_dir.join("harnesses.d/muse.conf");
    std::os::unix::fs::symlink("operator-managed.conf", &profile).unwrap();
    let out = isolated_update(&seam)
        .args(["update", "--sync-harnesses"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read_link(profile).unwrap(),
        Path::new("operator-managed.conf")
    );
}

#[test]
fn sync_uses_an_empty_starter_when_existing_manifests_disagree() {
    let seam = CliSeam::new();
    seam.install_stub_agent("muse");
    seam.write_harness(
        "claude",
        "backend = bitwarden\nmanifest = wide.refs\ncommand = claude\n",
    );
    seam.write_harness(
        "grok",
        "backend = onepassword\nmanifest = narrow.refs\ncommand = grok\n",
    );
    let out = isolated_update(&seam)
        .args(["update", "--sync-harnesses"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let profile = fs::read_to_string(seam.config_dir.join("harnesses.d/muse.conf")).unwrap();
    assert!(
        profile.contains("backend = plainfile\nmanifest = empty.env\n"),
        "{profile}"
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("muse starts without secrets"));
    assert!(!seam.config_dir.join("bws.env").exists());
    assert!(!seam.config_dir.join("op.env").exists());
}

#[test]
fn sync_preserves_custom_harnesses_and_is_idempotent() {
    let seam = CliSeam::new();
    seam.install_stub_agent("muse");
    let custom =
        "# hand maintained\nbackend = bitwarden\nmanifest = personal.refs\ncommand = muse --yolo\n";
    seam.write_harness("muse", custom);
    fs::write(
        seam.config_dir.join("defaults.conf"),
        "auth_mode = prompt\n",
    )
    .unwrap();
    for _ in 0..2 {
        let out = isolated_update(&seam)
            .args(["update", "--sync-harnesses"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            fs::read_to_string(seam.config_dir.join("harnesses.d/muse.conf")).unwrap(),
            custom
        );
        assert_eq!(
            fs::read_to_string(seam.config_dir.join("defaults.conf")).unwrap(),
            "auth_mode = prompt\n"
        );
    }
}

#[test]
fn check_and_dry_run_do_not_add_harnesses_or_manifests() {
    for option in ["--check", "--dry-run"] {
        let seam = CliSeam::new();
        seam.install_stub_agent("muse");
        let archive = pack_current_binary(&seam);
        let dest = seam.root.join("installed/vaulted-agent");
        let out = isolated_update(&seam)
            .args(["update", option, "v9.9.9"])
            .env("VAULTED_AGENT_UPDATE_DEST", &dest)
            .env("VAULTED_AGENT_UPDATE_ASSET", archive)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!dest.exists());
        assert_eq!(
            fs::read_dir(seam.config_dir.join("harnesses.d"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(
            fs::read_dir(seam.config_dir.join("manifests"))
                .unwrap()
                .count(),
            0
        );
        if option == "--dry-run" {
            assert!(String::from_utf8_lossy(&out.stdout).contains("muse.conf"));
        }
    }
}

#[test]
fn sync_does_not_use_a_nonempty_empty_env_as_a_secret_free_starter() {
    let seam = CliSeam::new();
    seam.install_stub_agent("muse");
    let manifest = seam.config_dir.join("manifests/empty.env");
    fs::write(&manifest, "APP_TOKEN=must-not-be-granted\n").unwrap();
    let out = isolated_update(&seam)
        .args(["update", "--sync-harnesses"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not empty"));
    assert!(!seam.config_dir.join("harnesses.d/muse.conf").exists());
    assert_eq!(
        fs::read_to_string(manifest).unwrap(),
        "APP_TOKEN=must-not-be-granted\n"
    );
}

#[test]
fn sync_under_sudo_detects_the_invoking_users_local_agent() {
    let seam = CliSeam::new();
    seam.write_executable("id", "#!/bin/sh\necho root\n");
    let home = seam.root.join("operator-home");
    let bin = home.join(".local/bin");
    fs::create_dir_all(&bin).unwrap();
    fs::rename(seam.install_stub_agent("muse"), bin.join("muse")).unwrap();
    seam.write_executable(
        "dscl",
        &format!("#!/bin/sh\necho 'NFSHomeDirectory: {}'\n", home.display()),
    );
    seam.write_executable(
        "getent",
        &format!(
            "#!/bin/sh\necho 'operator:x:1001:1001::{}:/bin/sh'\n",
            home.display()
        ),
    );
    let out = isolated_update(&seam)
        .env("SUDO_USER", "operator")
        .args(["update", "--sync-harnesses"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let profile = fs::read_to_string(seam.config_dir.join("harnesses.d/muse.conf")).unwrap();
    assert!(
        profile.contains(&format!("bin = {}\n", bin.display())),
        "{profile}"
    );
    assert!(!seam.config_dir.join("harnesses.d/claude-ro.conf").exists());
}

#[test]
fn update_reports_a_config_failure_after_successful_binary_replacement() {
    let seam = CliSeam::new();
    let dest = seam.root.join("installed/vaulted-agent");
    let archive = pack_asset(&seam.root, "vaulted-agent", "#!/bin/sh\ncase \"$*\" in\n  'update --help') echo --sync-harnesses ;;\n  'update --sync-harnesses') exit 17 ;;\n  *) echo 'vaulted-agent 9.9.9' ;;\nesac\n");
    let out = isolated_update(&seam)
        .args(["update", "v9.9.9"])
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .env("VAULTED_AGENT_UPDATE_ASSET", archive)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("binary updated, but Harness setup failed"),
        "{stderr}"
    );
    assert!(stderr.contains("va update --sync-harnesses"), "{stderr}");
    let version = Command::new(dest).arg("version").output().unwrap();
    assert!(String::from_utf8_lossy(&version.stdout).contains("9.9.9"));
    assert_eq!(
        fs::read_dir(seam.config_dir.join("harnesses.d"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn unreadable_custom_config_does_not_escalate_or_redirect_to_machine_config() {
    if Command::new("id").arg("-u").output().unwrap().stdout == b"0\n" {
        return;
    }
    let seam = CliSeam::new();
    seam.install_stub_agent("muse");
    let marker = seam.root.join("sudo-called");
    seam.write_executable(
        "sudo",
        &format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
    );
    fs::set_permissions(&seam.config_dir, fs::Permissions::from_mode(0o000)).unwrap();
    let out = isolated_update(&seam)
        .args(["update", "--sync-harnesses"])
        .output()
        .unwrap();
    fs::set_permissions(&seam.config_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("custom config directory"));
    assert!(!marker.exists());
}

#[test]
fn update_uses_the_target_catalog_without_passing_manager_tokens() {
    let seam = CliSeam::new();
    seam.install_stub_agent("muse");
    let dest = seam.root.join("installed/vaulted-agent");
    let archive = pack_asset(
        &seam.root,
        "vaulted-agent",
        r#"#!/bin/sh
set -eu
test -z "${BWS_ACCESS_TOKEN+set}"
test -z "${OP_SERVICE_ACCOUNT_TOKEN+set}"
case "$*" in
  'version') echo 'vaulted-agent 9.9.9' ;;
  'update --help') echo --sync-harnesses ;;
  'update --sync-harnesses')
    printf 'command = future-agent\nmanifest = future.refs\n' > "$VAULTED_AGENT_CONFIG_DIR/harnesses.d/future-agent.conf"
    ;;
  *) exit 9 ;;
esac
"#,
    );
    let out = isolated_update(&seam)
        .args(["update", "v9.9.9"])
        .env("BWS_ACCESS_TOKEN", "synthetic-manager")
        .env("OP_SERVICE_ACCOUNT_TOKEN", "synthetic-manager")
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .env("VAULTED_AGENT_UPDATE_ASSET", archive)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(seam
        .config_dir
        .join("harnesses.d/future-agent.conf")
        .is_file());
    assert!(!seam.config_dir.join("harnesses.d/muse.conf").exists());
}

#[test]
fn failed_binary_validation_leaves_config_untouched() {
    let seam = CliSeam::new();
    seam.install_stub_agent("muse");
    let dest = seam.root.join("installed/vaulted-agent");
    let archive = pack_asset(&seam.root, "vaulted-agent", "#!/bin/sh\nexit 8\n");
    let out = isolated_update(&seam)
        .args(["update", "v9.9.9"])
        .env("VAULTED_AGENT_UPDATE_DEST", &dest)
        .env("VAULTED_AGENT_UPDATE_ASSET", archive)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!dest.exists());
    assert_eq!(
        fs::read_dir(seam.config_dir.join("harnesses.d"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        fs::read_dir(seam.config_dir.join("manifests"))
            .unwrap()
            .count(),
        0
    );
}
