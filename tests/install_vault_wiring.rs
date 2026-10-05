//! Issue #151: the installer delegates Vault wiring and Token capture to the
//! Launcher it just installed.
//!
//! Each test runs `install.sh` for real against a temp `--config` / `--prefix`,
//! with a fictitious agent name (via VAULTED_AGENT_AUTO_HARNESSES) so no agent
//! installed on the developer's machine can interfere, and fake `bws` / `op`
//! on PATH so no vault is ever contacted.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A shape-valid Bitwarden Secrets Manager access token (not a real one).
const BWS_TOKEN: &str = "0.11111111-1111-1111-1111-111111111111.clientsecret:enckey";
const OP_TOKEN: &str = "ops_fake-service-account-token";

struct Install {
    tmp: tempfile::TempDir,
    bin: PathBuf,
    config: PathBuf,
}

impl Install {
    /// One detected day-one agent, `fakeagent`, and no vault CLIs yet.
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin = tmp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let config = tmp.path().join("etc");
        let me = Self { tmp, bin, config };
        me.executable("fakeagent", "#!/bin/sh\nexit 0\n");
        fs::write(me.tmp.path().join("auto-harnesses"), "fakeagent\n").unwrap();
        me
    }

    fn executable(&self, name: &str, body: &str) {
        let p = self.bin.join(name);
        fs::write(&p, body).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A fake `bws` whose `secret list` accepts the token (an empty vault)
    /// or rejects it the way the real one does on a bad token.
    fn fake_bws(&self, accept: bool) {
        let body = if accept {
            "#!/bin/sh\n[ -n \"$BWS_ACCESS_TOKEN\" ] || exit 9\n\
             case \"$1 $2\" in 'secret list') echo '[]' ;; *) exit 1 ;; esac\n"
        } else {
            "#!/bin/sh\necho 'Error: invalid access token' >&2\nexit 1\n"
        };
        self.executable("bws", body);
    }

    /// A fake `op` whose `whoami` accepts any exported service-account token.
    fn fake_op(&self) {
        self.executable(
            "op",
            "#!/bin/sh\n[ -n \"$OP_SERVICE_ACCOUNT_TOKEN\" ] || exit 9\n\
             case \"$1\" in whoami) echo '{}' ;; *) exit 1 ;; esac\n",
        );
    }

    fn path_var(&self) -> std::ffi::OsString {
        std::env::join_paths([
            self.bin.as_path(),
            Path::new("/usr/bin"),
            Path::new("/bin"),
            Path::new("/usr/sbin"),
            Path::new("/sbin"),
        ])
        .unwrap()
    }

    fn installer(&self, args: &[&str]) -> Command {
        let user_out = Command::new("id").arg("-un").output().unwrap();
        let user = String::from_utf8(user_out.stdout).unwrap();
        let mut cmd = Command::new("/bin/bash");
        cmd.arg(format!("{}/install.sh", env!("CARGO_MANIFEST_DIR")))
            .args(["--user", user.trim(), "--no-link", "--no-va"])
            .arg("--prefix")
            .arg(self.tmp.path().join("prefix"))
            .arg("--config")
            .arg(&self.config)
            .arg("--workdir")
            .arg(self.tmp.path())
            .args(args)
            .env_clear()
            .env("HOME", self.tmp.path().join("home"))
            .env("PATH", self.path_var())
            .env(
                "VAULTED_AGENT_AUTO_HARNESSES",
                self.tmp.path().join("auto-harnesses"),
            )
            .env("VAULTED_AGENT_BIN", env!("CARGO_BIN_EXE_vaulted-agent"));
        cmd
    }

    fn install(&self, args: &[&str]) -> String {
        let out = self.installer(args).output().expect("install");
        assert_ok(&out)
    }

    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.config.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    fn launcher(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vaulted-agent"))
            .args(args)
            .env_clear()
            .env("HOME", self.tmp.path().join("home"))
            .env("PATH", self.path_var())
            .env("VAULTED_AGENT_CONFIG_DIR", &self.config)
            .env("VAULTED_AGENT_NO_REEXEC", "1")
            .output()
            .expect("launcher")
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

fn has_kv(contents: &str, key: &str, value: &str) -> bool {
    contents.lines().any(|line| {
        line.split_once('=')
            .is_some_and(|(k, v)| k.trim() == key && v.trim() == value)
    })
}

fn assert_wired(install: &Install, backend: &str, refs: &str) {
    let conf = install.read("harnesses.d/fakeagent.conf");
    assert!(has_kv(&conf, "backend", backend), "{conf}");
    assert!(has_kv(&conf, "manifest", refs), "{conf}");
    assert!(has_kv(&conf, "workdir", "caller"), "{conf}");
    assert!(install.config.join("manifests").join(refs).is_file());
}

#[test]
fn backend_with_no_setup_wires_the_detected_harness() {
    let install = Install::new();
    install.install(&["--backend", "bitwarden", "--no-setup"]);

    assert_wired(&install, "bitwarden", "openai.env.refs");
    let defaults = install.read("defaults.conf");
    assert!(
        has_kv(&defaults, "default_backend", "bitwarden"),
        "{defaults}"
    );

    let out = install.launcher(&["secrets", "validate", "--offline"]);
    assert_ok(&out);
}

#[test]
fn rerun_without_backend_leaves_default_backend_alone() {
    // #76: a non-interactive re-install used to rewrite it to onepassword.
    let install = Install::new();
    install.install(&["--backend", "bitwarden", "--no-setup"]);
    install.install(&["--no-setup"]);
    install.install(&[]);

    let defaults = install.read("defaults.conf");
    assert!(
        has_kv(&defaults, "default_backend", "bitwarden"),
        "{defaults}"
    );
    assert_wired(&install, "bitwarden", "openai.env.refs");
}

#[test]
fn rejected_token_finishes_the_install_and_stores_nothing() {
    let install = Install::new();
    install.fake_bws(false);
    let token_file = install.tmp.path().join("bws-token");
    fs::write(&token_file, format!("{BWS_TOKEN}\n")).unwrap();

    let all = install.install(&[
        "--backend",
        "bitwarden",
        "--bws-token-file",
        token_file.to_str().unwrap(),
        "--no-setup",
    ]);

    assert!(!install.config.join("bws.env").exists(), "{all}");
    assert!(all.contains("token was not stored"), "{all}");
    // The Launcher's own reason stays visible.
    assert!(all.contains("invalid access token"), "{all}");
    assert_wired(&install, "bitwarden", "openai.env.refs");
    assert!(!all.contains(BWS_TOKEN), "token leaked into output:\n{all}");
}

#[test]
fn accepted_token_is_stored_0640() {
    let install = Install::new();
    install.fake_bws(true);
    let token_file = install.tmp.path().join("bws-token");
    fs::write(&token_file, format!("{BWS_TOKEN}\n")).unwrap();

    let all = install.install(&[
        "--backend",
        "bitwarden",
        "--bws-token-file",
        token_file.to_str().unwrap(),
        "--no-setup",
    ]);

    let stored = install.config.join("bws.env");
    let meta = fs::metadata(&stored).unwrap_or_else(|e| panic!("bws.env: {e}\n{all}"));
    assert_eq!(meta.permissions().mode() & 0o777, 0o640);
    assert_eq!(
        install.read("bws.env"),
        format!("BWS_ACCESS_TOKEN={BWS_TOKEN}\n")
    );
    assert!(!all.contains(BWS_TOKEN), "token leaked into output:\n{all}");
}

#[test]
fn prompt_mode_wires_and_stores_no_token() {
    let install = Install::new();
    install.fake_op();
    let out = install
        .installer(&[
            "--auth-mode",
            "prompt",
            "--backend",
            "onepassword",
            "--no-setup",
        ])
        // An exported token is a token source in file mode; prompt mode
        // must still store nothing.
        .env("OP_SERVICE_ACCOUNT_TOKEN", OP_TOKEN)
        .output()
        .expect("install");
    let all = assert_ok(&out);

    assert_wired(&install, "onepassword", "onepassword.refs");
    assert!(!install.config.join("op.env").exists(), "{all}");
    let defaults = install.read("defaults.conf");
    assert!(has_kv(&defaults, "auth_mode", "prompt"), "{defaults}");
}

#[test]
fn op_env_is_a_token_source_stored_where_the_launcher_reads() {
    let install = Install::new();
    install.fake_op();
    let orchestration = install.tmp.path().join("orchestration-op.env");
    fs::write(
        &orchestration,
        format!("# predates the install\nOP_SERVICE_ACCOUNT_TOKEN={OP_TOKEN}\n"),
    )
    .unwrap();

    let all = install.install(&[
        "--backend",
        "onepassword",
        "--op-env",
        orchestration.to_str().unwrap(),
        "--no-setup",
    ]);

    assert_eq!(
        install.read("op.env"),
        format!("OP_SERVICE_ACCOUNT_TOKEN={OP_TOKEN}\n")
    );
    assert!(
        all.contains(&format!(
            "reads only {}",
            install.config.join("op.env").display()
        )),
        "{all}"
    );
    assert!(!all.contains(OP_TOKEN), "token leaked into output:\n{all}");
}

#[test]
fn dry_run_prints_the_launcher_commands_and_runs_nothing() {
    let install = Install::new();
    let token_file = install.tmp.path().join("bws-token");
    fs::write(&token_file, format!("{BWS_TOKEN}\n")).unwrap();

    let all = install.install(&[
        "--dry-run",
        "--backend",
        "bitwarden",
        "--bws-token-file",
        token_file.to_str().unwrap(),
        "--no-setup",
    ]);

    assert!(all.contains("setup bitwarden --wire-only"), "{all}");
    assert!(all.contains("setup bitwarden --set-token"), "{all}");
    assert!(!all.contains(BWS_TOKEN), "token leaked into output:\n{all}");
    assert!(!install.config.exists(), "dry run wrote config:\n{all}");
}

#[test]
fn dry_run_over_prompt_mode_stores_no_token() {
    let install = Install::new();
    fs::create_dir_all(&install.config).unwrap();
    fs::write(install.config.join("defaults.conf"), "auth_mode = prompt\n").unwrap();
    let token_file = install.tmp.path().join("bws-token");
    fs::write(&token_file, format!("{BWS_TOKEN}\n")).unwrap();

    let all = install.install(&[
        "--dry-run",
        "--backend",
        "bitwarden",
        "--bws-token-file",
        token_file.to_str().unwrap(),
        "--no-setup",
    ]);

    assert!(all.contains("setup bitwarden --wire-only"), "{all}");
    assert!(!all.contains("--set-token"), "{all}");
    assert!(all.contains("auth_mode=prompt"), "{all}");
}
