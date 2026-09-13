//! Add missing, detected Harnesses without changing existing configuration.

use std::env;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{self, Backend, Harness, Paths};
use crate::error::{Error, Result};

const AUTO_HARNESSES: &str = include_str!("../etc/auto-harnesses");

pub(crate) fn sync(paths: &Paths, dry_run: bool) -> Result<()> {
    match sync_local(paths, dry_run) {
        Err(Error::Io { source, .. })
            if source.kind() == ErrorKind::PermissionDenied && !dry_run =>
        {
            if paths.config_dir != Path::new("/etc/vaulted-agent") {
                return Err(Error::Message(format!(
                    "update: cannot write {}; make this custom config directory writable and retry va update --sync-harnesses",
                    paths.config_dir.display()
                )));
            }
            if crate::privilege::current_user() == "root" {
                return Err(Error::Message(
                    "update: cannot write machine Harness configuration as root".into(),
                ));
            }
            eprintln!("update: machine config is not writable; retrying Harness setup with sudo");
            let exe = env::current_exe()
                .map_err(|e| Error::Message(format!("update: current exe: {e}")))?;
            let status = Command::new("sudo")
                .arg(exe)
                .args(["update", "--sync-harnesses"])
                .env_remove("VAULTED_AGENT_CONFIG_DIR")
                .env_remove("BWS_ACCESS_TOKEN")
                .env_remove("OP_SERVICE_ACCOUNT_TOKEN")
                .status()
                .map_err(|e| Error::Message(format!("update: sudo Harness setup: {e}")))?;
            if !status.success() {
                return Err(Error::Message("update: Harness setup needs write access; retry sudo va update --sync-harnesses".into()));
            }
            Ok(())
        }
        result => result,
    }
}

fn sync_local(paths: &Paths, dry_run: bool) -> Result<()> {
    let shared = shared_manifest(paths)?;
    let dirs = search_dirs(paths)?;
    for command in AUTO_HARNESSES.lines().map(str::trim) {
        if command.is_empty() || command.starts_with('#') {
            continue;
        }
        let name = command.split_whitespace().next().unwrap();
        let profile = paths.harness_dir.join(format!("{name}.conf"));
        // Includes dangling symlinks and directories: every existing entry is
        // operator-owned, even if it cannot currently be launched.
        if fs::symlink_metadata(&profile).is_ok() {
            continue;
        }
        let Some(binary) = find_binary(name, &dirs) else {
            continue;
        };
        let binding = if config::is_env_blind_agent(name) {
            None
        } else {
            shared.as_ref()
        };
        let (backend, manifest) = binding
            .map(|(backend, manifest)| (*backend, manifest.as_str()))
            .unwrap_or((Backend::Plainfile, "empty.env"));
        let bin = binary.parent().unwrap().to_string_lossy();
        if bin.contains(['\n', '\r']) {
            return Err(Error::Message(
                "update: agent directory contains a newline".into(),
            ));
        }
        let body = format!(
            "# Added by va update; existing profiles are preserved.\nbackend = {backend}\nmanifest = {manifest}\nworkdir = caller\nbin = {bin}\nlabels = no\ncommand = {command}\n"
        );
        if dry_run {
            println!(
                "dry-run: would add {} (backend={backend} manifest={manifest})",
                profile.display()
            );
            continue;
        }
        if binding.is_none() {
            ensure_empty_manifest(paths)?;
        }
        if create_profile(&profile, &body)? {
            println!(
                "added {} (backend={backend} manifest={manifest})",
                profile.display()
            );
            if binding.is_none() {
                println!("  {name} starts without secrets; choose its backend and manifest to enable injection");
            }
        }
    }
    Ok(())
}

fn shared_manifest(paths: &Paths) -> Result<Option<(Backend, String)>> {
    let mut shared: Option<(Backend, String)> = None;
    for name in config::list_harness_names(paths)? {
        let Ok(harness) = Harness::load(paths, &name) else {
            eprintln!(
                "update: cannot read Harness {name}; new Harnesses will start without secrets"
            );
            return Ok(None);
        };
        let candidate = (
            harness
                .backend
                .unwrap_or_else(|| config::load_default_backend(paths)),
            harness.manifest,
        );
        if let Some(previous) = &shared {
            if previous != &candidate {
                return Ok(None);
            }
        } else {
            shared = Some(candidate);
        }
    }
    Ok(shared)
}

fn search_dirs(paths: &Paths) -> Result<Vec<PathBuf>> {
    let current = crate::privilege::current_user();
    let account = config::load_default(paths, "service_user").or_else(|| {
        (current == "root")
            .then(|| env::var("SUDO_USER").ok())
            .flatten()
    });
    let other_account = account.as_deref().filter(|user| *user != current);
    let home = if let Some(user) = other_account {
        account_home(user)
    } else {
        env::var_os("HOME").map(PathBuf::from)
    };
    let mut dirs = if other_account.is_none() {
        env::split_paths(&env::var_os("PATH").unwrap_or_default()).collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if let Some(home) = &home {
        dirs.push(home.join(".local/bin"));
        dirs.push(home.join(".grok/bin"));
    }
    for name in config::list_harness_names(paths)? {
        if let Ok(harness) = Harness::load(paths, &name) {
            if let Some(bin) = harness.bin_dir {
                let expanded = if let Some(home) = &home {
                    bin.replace("$HOME", &home.to_string_lossy())
                } else {
                    bin
                };
                if Path::new(&expanded).is_absolute() {
                    dirs.push(expanded.into());
                }
            }
        }
    }
    dirs.extend(["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"].map(PathBuf::from));
    Ok(dirs)
}

fn account_home(user: &str) -> Option<PathBuf> {
    // Pass account names as data, never interpolate them into a shell command.
    let output = if cfg!(target_os = "macos") {
        Command::new("dscl")
            .args([".", "-read", &format!("/Users/{user}"), "NFSHomeDirectory"])
            .output()
            .ok()?
    } else {
        Command::new("getent")
            .args(["passwd", user])
            .output()
            .ok()?
    };
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let home = if cfg!(target_os = "macos") {
        text.trim().strip_prefix("NFSHomeDirectory:")?.trim()
    } else {
        text.split(':').nth(5)?
    };
    Path::new(home).is_absolute().then(|| PathBuf::from(home))
}

fn find_binary(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    for dir in dirs {
        let candidate = dir.join(name);
        if fs::metadata(&candidate)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        {
            return Some(if candidate.is_absolute() {
                candidate
            } else {
                env::current_dir().ok()?.join(candidate)
            });
        }
    }
    None
}

fn ensure_empty_manifest(paths: &Paths) -> Result<()> {
    let path = paths.manifest_dir.join("empty.env");
    create_profile(
        &path,
        "# Empty starter manifest; configure the Harness to inject secrets.\n",
    )?;
    let text = fs::read_to_string(&path).map_err(|source| Error::Io {
        path: path.clone(),
        source,
    })?;
    if !text
        .lines()
        .all(|line| line.trim().is_empty() || line.trim().starts_with('#'))
    {
        return Err(Error::Message(format!(
            "update: {} is not empty; refusing to use it as a no-secret starter",
            path.display()
        )));
    }
    Ok(())
}

fn create_profile(path: &Path, body: &str) -> Result<bool> {
    let parent = path.parent().unwrap();
    let write = || -> std::io::Result<bool> {
        fs::create_dir_all(parent)?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        temp.write_all(body.as_bytes())?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
        match temp.persist_noclobber(path) {
            Ok(_) => Ok(true),
            Err(e) if e.error.kind() == ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e.error),
        }
    };
    write().map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}
