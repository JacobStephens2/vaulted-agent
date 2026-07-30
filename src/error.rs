use std::io;
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidHarnessName(String),
    UnknownHarness {
        name: String,
        path: PathBuf,
    },
    UnknownBackend(String),
    HarnessParse {
        name: String,
        lineno: usize,
        msg: String,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Message(String),
}

impl Error {
    /// Map a write failure on machine config (defaults.conf, token files, …).
    /// Permission denied gets a sudo hint (system install under /etc is root-owned).
    pub fn config_write(path: impl Into<PathBuf>, source: io::Error) -> Self {
        let path = path.into();
        if source.kind() == io::ErrorKind::PermissionDenied {
            Self::Message(format!(
                "{}: Permission denied\n  \
                 Machine config is root-owned. Re-run with sudo, e.g.:\n  \
                   sudo vaulted-agent setup\n  \
                   sudo vaulted-agent auth-mode file|prompt",
                path.display()
            ))
        } else {
            Self::Io { path, source }
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidHarnessName(n) => write!(f, "invalid harness name '{n}'"),
            Error::UnknownHarness { name, path } => {
                write!(
                    f,
                    "unknown harness '{name}' (no readable {})",
                    path.display()
                )
            }
            Error::UnknownBackend(b) => write!(
                f,
                "unknown backend '{b}' (want bitwarden, onepassword, pass, sops, plainfile)"
            ),
            Error::HarnessParse { name, lineno, msg } => {
                if *lineno > 0 {
                    write!(f, "harness {name}:{lineno}: {msg}")
                } else {
                    write!(f, "harness {name}: {msg}")
                }
            }
            Error::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Error::Message(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}
