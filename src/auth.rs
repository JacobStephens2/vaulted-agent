//! Load vault manager tokens from env, file, or TTY prompt.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::config::{AuthMode, Paths};
use crate::error::{Error, Result};
use crate::secret::ManagerToken;

#[derive(Debug, Clone, Copy)]
pub enum TokenKind {
    Bws,
    Op,
}

impl TokenKind {
    pub fn env_var(self) -> &'static str {
        match self {
            Self::Bws => "BWS_ACCESS_TOKEN",
            Self::Op => "OP_SERVICE_ACCOUNT_TOKEN",
        }
    }

    pub fn file(self, paths: &Paths) -> &Path {
        match self {
            Self::Bws => &paths.bws_env_file,
            Self::Op => &paths.op_env_file,
        }
    }

    pub fn prompt_label(self) -> &'static str {
        match self {
            Self::Bws => {
                "Bitwarden Secrets Manager access token (Machine Accounts → Access Tokens; not your vault password)"
            }
            Self::Op => "1Password service-account token (OP_SERVICE_ACCOUNT_TOKEN)",
        }
    }
}

fn read_token_file(path: &Path, key: &str) -> Result<Option<ManagerToken>> {
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    // Shared dotenv policy with validate/resolve (quotes stripped).
    Ok(crate::config::parse_dotenv_var(&text, key)?.map(ManagerToken::new))
}

/// True when /dev/tty can actually be opened (not merely present on the filesystem).
fn tty_usable() -> bool {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
}

fn prompt_token(kind: TokenKind) -> Result<ManagerToken> {
    // Prefer /dev/tty so prompts work when stdout is piped (bash parity).
    // Gate on open(), not Path::exists() — exists is true on every Unix even
    // without a controlling terminal (ticket #10 / story #48 guidance path).
    if !tty_usable() {
        return Err(Error::Message(format!(
            "auth_mode=prompt needs a terminal (or export {})\n  For agent→agent launches: auth-mode file + token file, or export {}",
            kind.env_var(),
            kind.env_var()
        )));
    }
    if let Ok(mut tty) = fs::OpenOptions::new().write(true).open("/dev/tty") {
        writeln!(
            tty,
            "{}\n(hidden, not written to disk): ",
            kind.prompt_label()
        )
        .map_err(|e| Error::Message(format!("tty write: {e}")))?;
        tty.flush().ok();
    }
    // No-echo read (bash `read -rs` parity). rpassword uses termios when available.
    let token = rpassword::read_password().map_err(|e| {
        Error::Message(format!(
            "could not read {} from terminal: {e}\n  export {} or write token file",
            kind.env_var(),
            kind.env_var()
        ))
    })?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(Error::Message(format!("empty {}", kind.env_var())));
    }
    Ok(ManagerToken::new(token))
}

/// force_prompt: -p / --prompt-auth
pub fn load_manager_token(
    paths: &Paths,
    mode: AuthMode,
    kind: TokenKind,
    force_prompt: bool,
) -> Result<ManagerToken> {
    let key = kind.env_var();
    if let Ok(v) = std::env::var(key) {
        if !v.is_empty() {
            return Ok(ManagerToken::new(v));
        }
    }

    let prompt = force_prompt || mode == AuthMode::Prompt;
    if prompt {
        return prompt_token(kind);
    }

    if let Some(t) = read_token_file(kind.file(paths), key)? {
        return Ok(t);
    }

    // One-shot prompt if TTY available (match bash behavior when file missing)
    if tty_usable() {
        eprintln!(
            "vaulted-agent: {} missing {}",
            match kind {
                TokenKind::Bws => "bitwarden",
                TokenKind::Op => "onepassword",
            },
            kind.file(paths).display()
        );
        return prompt_token(kind);
    }

    Err(Error::Message(format!(
        "backend needs {} (or export {} / auth-mode prompt)",
        kind.file(paths).display(),
        key
    )))
}

/// Write `KEY=token` with mode 0640. When running as root and `service_user` is
/// set, chown to `root:service_user` so the service account can read the file
/// after sudo re-exec (stories #11, #40).
///
/// Creates the file with mode 0600 first so it is never briefly world-readable.
pub fn write_token_file(
    path: &Path,
    key: &str,
    token: &ManagerToken,
    service_user: Option<&str>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::config_write(parent, e))?;
    }
    let body = format!("{}={}\n", key, token.expose());

    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| Error::config_write(path, e))?;
        f.write_all(body.as_bytes())
            .map_err(|e| Error::config_write(path, e))?;
        f.sync_all().ok();
        drop(f);
        let mut perms = fs::metadata(path)
            .map_err(|e| Error::config_write(path, e))?
            .permissions();
        perms.set_mode(0o640);
        fs::set_permissions(path, perms).map_err(|e| Error::config_write(path, e))?;

        // root:SERVICE_USER so mode 0640 is useful under a service-account install.
        if is_euid_root() {
            if let Some(user) = service_user.filter(|u| !u.is_empty()) {
                if let Some(gid) = gid_for_user(user) {
                    if let Err(e) = std::os::unix::fs::chown(path, Some(0), Some(gid)) {
                        eprintln!(
                            "vaulted-agent: warn: could not chown root:{user} on {}: {e}",
                            path.display()
                        );
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        fs::write(path, body).map_err(|e| Error::config_write(path, e))?;
        let _ = service_user;
    }

    Ok(())
}

#[cfg(unix)]
fn is_euid_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
            } else {
                None
            }
        })
        .unwrap_or(1)
        == 0
}

#[cfg(unix)]
fn gid_for_user(user: &str) -> Option<u32> {
    // Prefer primary group of the service account (`id -g user`).
    let out = std::process::Command::new("id")
        .args(["-g", user])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}
