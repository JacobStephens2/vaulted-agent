//! Load vault manager tokens from env, file, or TTY prompt.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::config::{self, AuthMode, Paths};
use crate::error::{Error, Result};
use crate::privilege;
use crate::secret::ManagerToken;

/// Whether a vault token file can be read by this process.
///
/// `Path::is_file()` collapses `ENOENT` and `EACCES` into `false`, so a
/// permission-denied token file used to look identical to a missing one
/// (issue #51). These three states keep that distinction.
#[derive(Debug)]
pub(crate) enum TokenFileStatus {
    Present,
    Missing,
    Unreadable { source: io::Error },
}

/// Classify a token path without treating permission errors as absence.
pub(crate) fn token_file_status(path: &Path) -> TokenFileStatus {
    match fs::metadata(path) {
        Ok(m) if !m.is_file() => TokenFileStatus::Missing,
        Ok(_) => {
            // Stat can succeed while open fails (directory is traversable but
            // the file mode forbids this user). Confirm open, not just type.
            match fs::File::open(path) {
                Ok(_) => TokenFileStatus::Present,
                Err(e) if e.kind() == io::ErrorKind::NotFound => TokenFileStatus::Missing,
                Err(e) => TokenFileStatus::Unreadable { source: e },
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => TokenFileStatus::Missing,
        Err(e) => TokenFileStatus::Unreadable { source: e },
    }
}

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
    match fs::metadata(path) {
        Ok(m) if !m.is_file() => return Ok(None),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        // EACCES / other failures: do not collapse into "missing".
        Err(e) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source: e,
            })
        }
    }
    let text = fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    // Shared dotenv policy with validate/resolve (quotes stripped).
    Ok(crate::config::parse_dotenv_var(&text, key)?.map(ManagerToken::new))
}

/// Turn a token-file IO failure into a message that names the effective user
/// and, when relevant, points at a missing `service_user` hop.
fn token_file_unreadable(paths: &Paths, path: &Path, source: io::Error) -> Error {
    let who = privilege::current_user();
    let who = if who.is_empty() {
        "this process".to_string()
    } else {
        format!("`{who}`")
    };
    let mut msg = format!(
        "cannot read {} as {who} ({source})\n  \
         Token files are often root:<service_user> mode 0640 so only that account can read them.",
        path.display()
    );
    match config::load_service_user(paths) {
        None => msg.push_str(
            "\n  No service_user in defaults.conf — the launcher never re-execs as the account \
             that can read this file.\n  \
             Fix: set `service_user = <account>` in defaults.conf, or grant this user group read.",
        ),
        Some(svc) => msg.push_str(&format!(
            "\n  service_user={svc} is configured; if this process is not that account, the \
             privilege hop did not run (check sudoers / VAULTED_AGENT_NO_REEXEC)."
        )),
    }
    Error::Message(msg)
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

    let path = kind.file(paths);
    match read_token_file(path, key) {
        Ok(Some(t)) => return Ok(t),
        Ok(None) => {}
        // Unreadable is not missing: fail closed instead of prompting for a
        // paste of the vault service-account token (issue #51).
        Err(Error::Io { path, source }) => {
            return Err(token_file_unreadable(paths, &path, source));
        }
        Err(e) => return Err(e),
    }

    // One-shot prompt if TTY available (match bash behavior when file missing)
    if tty_usable() {
        eprintln!(
            "vaulted-agent: {} missing {}",
            match kind {
                TokenKind::Bws => "bitwarden",
                TokenKind::Op => "onepassword",
            },
            path.display()
        );
        return prompt_token(kind);
    }

    Err(Error::Message(format!(
        "backend needs {} (or export {} / auth-mode prompt)",
        path.display(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn token_file_status_missing_is_not_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.env");
        assert!(matches!(token_file_status(&path), TokenFileStatus::Missing));
    }

    #[test]
    fn token_file_status_present_when_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.env");
        fs::write(&path, "OP_SERVICE_ACCOUNT_TOKEN=x\n").unwrap();
        assert!(matches!(token_file_status(&path), TokenFileStatus::Present));
    }

    #[test]
    fn token_file_status_unreadable_when_mode_forbids() {
        // Skip when the suite runs as root: chmod 000 does not stop root.
        if is_euid_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.env");
        fs::write(&path, "OP_SERVICE_ACCOUNT_TOKEN=x\n").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&path, perms).unwrap();
        match token_file_status(&path) {
            TokenFileStatus::Unreadable { source } => {
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
        // Restore so tempfile cleanup can remove the file.
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).unwrap();
    }

    #[test]
    fn read_token_file_errors_on_permission_denied() {
        if is_euid_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.env");
        fs::write(&path, "OP_SERVICE_ACCOUNT_TOKEN=x\n").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&path, perms).unwrap();
        let err = read_token_file(&path, "OP_SERVICE_ACCOUNT_TOKEN").unwrap_err();
        match err {
            Error::Io { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected Io, got {other}"),
        }
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).unwrap();
    }

    #[test]
    fn read_token_file_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.env");
        assert!(matches!(
            read_token_file(&path, "OP_SERVICE_ACCOUNT_TOKEN"),
            Ok(None)
        ));
    }
}
