//! Load vault manager tokens from env, file, or TTY prompt.

use std::fs;
use std::io::{self, BufRead, Write};
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

    pub fn file<'a>(self, paths: &'a Paths) -> &'a Path {
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

fn parse_dotenv_var(text: &str, key: &str) -> Option<String> {
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim() == key {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn read_token_file(path: &Path, key: &str) -> Result<Option<ManagerToken>> {
    if !path.is_file() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(parse_dotenv_var(&text, key).map(ManagerToken::new))
}

fn prompt_token(kind: TokenKind) -> Result<ManagerToken> {
    let tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty");
    let Ok(mut tty) = tty else {
        return Err(Error::Message(format!(
            "auth_mode=prompt needs a terminal (or export {})\n  For agent→agent launches: auth-mode file + token file, or export {}",
            kind.env_var(),
            kind.env_var()
        )));
    };
    writeln!(tty, "{}\n(hidden, not written to disk): ", kind.prompt_label())
        .map_err(|e| Error::Message(format!("tty write: {e}")))?;
    // Best-effort: read a line (echo may still be on without termios; acceptable for v1)
    let mut line = String::new();
    let mut reader = io::BufReader::new(
        fs::File::open("/dev/tty").map_err(|e| Error::Message(format!("tty open: {e}")))?,
    );
    reader
        .read_line(&mut line)
        .map_err(|e| Error::Message(format!("tty read: {e}")))?;
    let token = line.trim().to_string();
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
    if Path::new("/dev/tty").exists() {
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

pub fn write_token_file(path: &Path, key: &str, token: &ManagerToken) -> Result<()> {
    let body = format!("{}={}\n", key, token.expose());
    fs::write(path, body).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|e| Error::Io {
                path: path.to_path_buf(),
                source: e,
            })?
            .permissions();
        perms.set_mode(0o640);
        fs::set_permissions(path, perms).map_err(|e| Error::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    }
    Ok(())
}
