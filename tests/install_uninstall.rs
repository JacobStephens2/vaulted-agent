//! Issue #162: `install.sh --uninstall` delegates to the Launcher's
//! `uninstall`, so it keeps credential files under `--purge` and leaves
//! links that are not ours alone.
//!
//! Each test runs `install.sh` for real against a temp `--prefix` / `--config`.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Tree {
    tmp: tempfile::TempDir,
    prefix: PathBuf,
    config: PathBuf,
}

impl Tree {
    /// A config dir holding `op.env` and `defaults.conf`, a foreign
    /// `other-conductor` link, and an empty prefix.
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let prefix = tmp.path().join("prefix");
        let config = tmp.path().join("etc");
        fs::create_dir_all(&prefix).unwrap();
        fs::create_dir_all(config.join("harnesses.d")).unwrap();
        fs::write(config.join("op.env"), "OP_SERVICE_ACCOUNT_TOKEN=ops_fake\n").unwrap();
        fs::write(config.join("defaults.conf"), "auth_mode = file\n").unwrap();
        symlink("/bin/true", prefix.join("other-conductor")).unwrap();
        Self {
            tmp,
            prefix,
            config,
        }
    }

    fn uninstall(&self, extra_env: &[(&str, &Path)]) -> Output {
        let mut cmd = Command::new("/bin/bash");
        cmd.arg(format!("{}/install.sh", env!("CARGO_MANIFEST_DIR")))
            .args(["--uninstall", "--purge", "-y"])
            .arg("--prefix")
            .arg(&self.prefix)
            .arg("--config")
            .arg(&self.config)
            .env_clear()
            .env("HOME", self.tmp.path().join("home"))
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.output().expect("install.sh")
    }
}

fn assert_ok(out: &Output) -> String {
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{all}");
    all
}

fn assert_credentials_and_foreign_link_survive(tree: &Tree, out: &str) {
    assert!(tree.config.join("op.env").is_file(), "{out}");
    assert!(!tree.config.join("defaults.conf").exists(), "{out}");
    assert!(!tree.config.join("harnesses.d").exists(), "{out}");
    assert!(tree.prefix.join("other-conductor").is_symlink(), "{out}");
    assert!(out.contains("(not ours)"), "{out}");
}

#[test]
fn uninstall_runs_the_installed_launcher() {
    let tree = Tree::new();
    let launcher = tree.prefix.join("vaulted-agent");
    fs::copy(env!("CARGO_BIN_EXE_vaulted-agent"), &launcher).unwrap();
    symlink(&launcher, tree.prefix.join("va")).unwrap();

    let out = assert_ok(&tree.uninstall(&[]));

    assert_credentials_and_foreign_link_survive(&tree, &out);
    assert!(launcher.symlink_metadata().is_err(), "{out}");
    assert!(tree.prefix.join("va").symlink_metadata().is_err(), "{out}");
}

#[test]
fn uninstall_without_an_install_runs_the_binary_an_install_would_use() {
    let tree = Tree::new();
    let bin = Path::new(env!("CARGO_BIN_EXE_vaulted-agent"));

    let out = assert_ok(&tree.uninstall(&[("VAULTED_AGENT_BIN", bin)]));

    assert_credentials_and_foreign_link_survive(&tree, &out);
    assert!(bin.is_file(), "the binary outside the prefix is not ours");
}
