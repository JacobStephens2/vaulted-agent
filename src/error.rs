use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidHarnessName(String),
    UnknownHarness { name: String, path: PathBuf },
    HarnessParse { name: String, lineno: usize, msg: String },
    Io { path: PathBuf, source: std::io::Error },
    Message(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidHarnessName(n) => write!(f, "invalid harness name '{n}'"),
            Error::UnknownHarness { name, path } => {
                write!(f, "unknown harness '{name}' (no readable {})", path.display())
            }
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
