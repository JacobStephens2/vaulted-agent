//! Machine defaults, harness definitions, and manifest path resolution.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    File,
    Prompt,
}

impl AuthMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "file" => Some(Self::File),
            "prompt" => Some(Self::Prompt),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Prompt => "prompt",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub harness_dir: PathBuf,
    pub manifest_dir: PathBuf,
    pub defaults_file: PathBuf,
    pub op_env_file: PathBuf,
    pub bws_env_file: PathBuf,
    pub age_key_file: PathBuf,
}

impl Paths {
    pub fn from_config_dir(config_dir: impl Into<PathBuf>) -> Self {
        let config_dir = config_dir.into();
        Self {
            harness_dir: config_dir.join("harnesses.d"),
            manifest_dir: config_dir.join("manifests"),
            defaults_file: config_dir.join("defaults.conf"),
            op_env_file: config_dir.join("op.env"),
            bws_env_file: config_dir.join("bws.env"),
            age_key_file: config_dir.join("age.key"),
            config_dir,
        }
    }

    /// Resolve config dir: VAULTED_AGENT_CONFIG_DIR, else default /etc/vaulted-agent.
    pub fn discover() -> Self {
        let dir = std::env::var_os("VAULTED_AGENT_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/etc/vaulted-agent"));
        Self::from_config_dir(dir)
    }
}

#[derive(Debug, Clone)]
pub struct Harness {
    pub name: String,
    pub backend: Option<String>,
    pub manifest: String,
    pub bin_dir: Option<String>,
    pub workdir: Option<String>,
    pub labels: bool,
    pub keep: Vec<String>,
    pub command: Vec<String>,
}

impl Harness {
    pub fn load(paths: &Paths, name: &str) -> Result<Self> {
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(Error::InvalidHarnessName(name.to_string()));
        }
        let conf = paths.harness_dir.join(format!("{name}.conf"));
        if !conf.is_file() {
            return Err(Error::UnknownHarness {
                name: name.to_string(),
                path: conf,
            });
        }
        let text = fs::read_to_string(&conf).map_err(|e| Error::Io {
            path: conf.clone(),
            source: e,
        })?;
        Self::parse(name, &text)
    }

    pub fn parse(name: &str, text: &str) -> Result<Self> {
        let mut backend = None;
        let mut manifest = None;
        let mut bin_dir = None;
        let mut workdir = None;
        let mut labels = false;
        let mut keep = Vec::new();
        let mut command = Vec::new();
        let mut extra_args = Vec::new();

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim().trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                return Err(Error::HarnessParse {
                    name: name.to_string(),
                    lineno: lineno + 1,
                    msg: "expected key = value".into(),
                });
            };
            let key = k.trim();
            let val = v.trim();
            match key {
                "backend" => backend = Some(val.to_string()),
                "manifest" => manifest = Some(val.to_string()),
                "bin" => bin_dir = Some(val.to_string()),
                "workdir" => workdir = Some(val.to_string()),
                "labels" => labels = matches!(val, "yes" | "true" | "1"),
                "keep" => {
                    keep.extend(
                        val.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                    );
                }
                "command" => {
                    command = val.split_whitespace().map(|s| s.to_string()).collect();
                }
                "arg" => extra_args.push(val.to_string()),
                _ => {
                    return Err(Error::HarnessParse {
                        name: name.to_string(),
                        lineno: lineno + 1,
                        msg: format!("unknown key '{key}'"),
                    });
                }
            }
        }

        if command.is_empty() {
            return Err(Error::HarnessParse {
                name: name.to_string(),
                lineno: 0,
                msg: "no command = line".into(),
            });
        }
        let Some(manifest) = manifest else {
            return Err(Error::HarnessParse {
                name: name.to_string(),
                lineno: 0,
                msg: "no manifest = line".into(),
            });
        };
        command.extend(extra_args);

        Ok(Self {
            name: name.to_string(),
            backend,
            manifest,
            bin_dir,
            workdir,
            labels,
            keep,
            command,
        })
    }

    pub fn resolve_manifest_path(&self, paths: &Paths) -> PathBuf {
        let p = Path::new(&self.manifest);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            paths.manifest_dir.join(p)
        }
    }
}

pub fn load_auth_mode(paths: &Paths) -> AuthMode {
    let Ok(text) = fs::read_to_string(&paths.defaults_file) else {
        return AuthMode::File;
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim() == "auth_mode" {
            if let Some(mode) = AuthMode::parse(v) {
                return mode;
            }
        }
    }
    AuthMode::File
}

pub fn list_harness_names(paths: &Paths) -> Result<Vec<String>> {
    let mut names = Vec::new();
    let rd = match fs::read_dir(&paths.harness_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(names),
        Err(e) => {
            return Err(Error::Io {
                path: paths.harness_dir.clone(),
                source: e,
            });
        }
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".conf") {
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// Parse KEY=value dotenv-style lines into a map (for plainfile later).
pub fn parse_dotenv_keys(text: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim().trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        if key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        {
            m.insert(key.to_string(), v.trim().to_string());
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_harness_minimal() {
        let h = Harness::parse(
            "claude",
            "manifest = empty.env\ncommand = claude --permission-mode auto\n",
        )
        .unwrap();
        assert_eq!(h.manifest, "empty.env");
        assert_eq!(h.command, vec!["claude", "--permission-mode", "auto"]);
    }

    #[test]
    fn parse_harness_rejects_unknown_key() {
        let err = Harness::parse("x", "manifest = a\ncommand = true\nfoo = bar\n").unwrap_err();
        assert!(format!("{err}").contains("unknown key"));
    }

    #[test]
    fn auth_mode_from_defaults_text() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        fs::create_dir_all(&paths.config_dir).unwrap();
        fs::write(&paths.defaults_file, "auth_mode = prompt\n").unwrap();
        assert_eq!(load_auth_mode(&paths), AuthMode::Prompt);
    }

    #[test]
    fn resolve_manifest_relative() {
        let paths = Paths::from_config_dir("/etc/vaulted-agent");
        let h = Harness::parse("h", "manifest = openai.env.refs\ncommand = true\n").unwrap();
        assert_eq!(
            h.resolve_manifest_path(&paths),
            PathBuf::from("/etc/vaulted-agent/manifests/openai.env.refs")
        );
    }
}
