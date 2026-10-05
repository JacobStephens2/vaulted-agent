//! **Machine defaults**: what `defaults.conf` says, read once per load.
//!
//! Every reader of `defaults.conf` goes through [`Defaults::load`], which reads
//! the file once and settles every key; callers load it where they need it. The pure
//! step, [`Defaults::parse`], takes the conf text and the two env overrides
//! and returns the typed keys or an error; the adapter reads the file and the
//! real environment.
//!
//! The rules, stated once:
//!
//! - A missing file is the built-in values: auth mode `file`, Backend
//!   `onepassword`, no Service user, `run` not allowed, no Extra manifests.
//! - A file that exists but cannot be read is an error naming its path, never
//!   "empty": an EACCES read used to drop `service_user`, and with it the
//!   Service-user re-exec, so the agent ran as the caller.
//! - An empty value (`default_backend =`) counts as unset. Single-valued keys
//!   take the first non-empty value; later ones are ignored. Unknown keys are
//!   ignored, so an older binary still reads a newer file.
//! - A malformed line, or a value a key does not recognise, is an error with
//!   its line (invariant 4).
//!
//! Env override policy:
//!
//! - `VAULTED_AGENT_SERVICE_USER` and `VAULTED_AGENT_DEFAULT_BACKEND` override
//!   their key when non-empty. An override that names no Backend is an error.
//! - `allow_run` has none on purpose: it bounds what a caller can ask for, and
//!   a caller controls their own environment.
//! - `VAULTED_AGENT_AUTH_MODE` is not read here. The Token source settles it
//!   against the configured auth mode this module returns.

use crate::conf_file::{ConfFile, Line};
use crate::config::{AuthMode, Backend, Paths};
use crate::error::{Error, Result};

const SERVICE_USER_ENV: &str = "VAULTED_AGENT_SERVICE_USER";
const DEFAULT_BACKEND_ENV: &str = "VAULTED_AGENT_DEFAULT_BACKEND";

/// The env overrides [`Defaults::parse`] settles, as read from the environment.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnvOverrides<'a> {
    /// `VAULTED_AGENT_SERVICE_USER`
    pub service_user: Option<&'a str>,
    /// `VAULTED_AGENT_DEFAULT_BACKEND`
    pub default_backend: Option<&'a str>,
}

/// The machine's `defaults.conf`, typed, with env overrides applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Defaults {
    /// The configured auth mode (before the Token source's env override).
    pub auth_mode: AuthMode,
    /// The Backend a Harness or Extra manifest without one uses.
    pub default_backend: Backend,
    pub service_user: Option<String>,
    /// Whether `run` may execute while a Service user is configured.
    pub allow_run: bool,
    /// Every `extra_manifest =` value as written, in file order. Inventory
    /// parses each one, so one bad line is one failing row (ADR-0006).
    pub extra_manifests: Vec<String>,
}

impl Default for Defaults {
    /// The built-in values: what a machine without `defaults.conf` gets.
    fn default() -> Self {
        Self {
            auth_mode: AuthMode::File,
            default_backend: Backend::OnePassword,
            service_user: None,
            allow_run: false,
            extra_manifests: Vec::new(),
        }
    }
}

impl Defaults {
    /// Thin adapter: read `defaults.conf` and the real environment.
    pub fn load(paths: &Paths) -> Result<Self> {
        let conf = ConfFile::read(&paths.defaults_file)?;
        let service_user = std::env::var(SERVICE_USER_ENV).ok();
        let default_backend = std::env::var(DEFAULT_BACKEND_ENV).ok();
        Self::parse(
            conf.text(),
            EnvOverrides {
                service_user: service_user.as_deref(),
                default_backend: default_backend.as_deref(),
            },
        )
    }

    /// The pure step: `text` is the conf (empty when the file is missing).
    pub fn parse(text: &str, env: EnvOverrides<'_>) -> Result<Self> {
        let conf = ConfFile::parse(text);
        let mut auth_mode = None;
        let mut default_backend = None;
        let mut service_user = None;
        let mut allow_run = None;
        let mut extra_manifests = Vec::new();
        for line in conf.lines() {
            let (lineno, key, value) = match line {
                Line::Comment => continue,
                Line::Malformed { lineno } => {
                    return Err(invalid(lineno, "expected key = value".into()));
                }
                Line::Entry { value: "", .. } => continue,
                Line::Entry { lineno, key, value } => (lineno, key, value),
            };
            match key {
                "auth_mode" if auth_mode.is_none() => {
                    auth_mode = Some(AuthMode::parse(value).ok_or_else(|| {
                        invalid(lineno, format!("auth_mode '{value}' is not file or prompt"))
                    })?);
                }
                "default_backend" if default_backend.is_none() => {
                    default_backend = Some(
                        value
                            .parse()
                            .map_err(|e| invalid(lineno, format!("default_backend: {e}")))?,
                    );
                }
                "service_user" if service_user.is_none() => {
                    service_user = Some(value.to_string());
                }
                "allow_run" if allow_run.is_none() => {
                    allow_run = Some(match value {
                        "yes" | "true" | "1" => true,
                        "no" | "false" | "0" => false,
                        _ => {
                            return Err(invalid(
                                lineno,
                                format!("allow_run '{value}' is not yes, true, 1, no, false or 0"),
                            ));
                        }
                    });
                }
                "extra_manifest" => extra_manifests.push(value.to_string()),
                _ => {}
            }
        }

        let builtin = Self::default();
        let default_backend = match env.default_backend.filter(|v| !v.is_empty()) {
            Some(v) => v
                .parse()
                .map_err(|e| Error::Message(format!("{DEFAULT_BACKEND_ENV}: {e}")))?,
            None => default_backend.unwrap_or(builtin.default_backend),
        };
        let service_user = match env.service_user.filter(|v| !v.is_empty()) {
            Some(v) => Some(v.to_string()),
            None => service_user,
        };
        Ok(Self {
            auth_mode: auth_mode.unwrap_or(builtin.auth_mode),
            default_backend,
            service_user,
            allow_run: allow_run.unwrap_or(builtin.allow_run),
            extra_manifests,
        })
    }
}

fn invalid(lineno: usize, msg: String) -> Error {
    Error::Message(format!("defaults.conf:{lineno}: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn parse(text: &str) -> Result<Defaults> {
        Defaults::parse(text, EnvOverrides::default())
    }

    fn err(text: &str) -> String {
        parse(text).expect_err("should not load").to_string()
    }

    #[test]
    fn a_missing_file_is_the_built_in_values() {
        let d = parse("").unwrap();
        assert_eq!(d.auth_mode, AuthMode::File);
        assert_eq!(d.default_backend, Backend::OnePassword);
        assert_eq!(d.service_user, None);
        assert!(!d.allow_run);
        assert!(d.extra_manifests.is_empty());
        assert_eq!(d, Defaults::default());
    }

    #[test]
    fn a_missing_file_on_disk_is_the_built_in_values() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        let d = Defaults::load(&paths).unwrap();
        assert_eq!(d.auth_mode, AuthMode::File);
        assert!(d.extra_manifests.is_empty());
    }

    #[test]
    fn each_key_is_read() {
        let d = parse(
            "# Machine-wide launcher defaults.\n\
             auth_mode = prompt\n\
             default_backend = bws\n\
             service_user = conductor\n\
             allow_run = yes\n\
             extra_manifest = /srv/a.env\n",
        )
        .unwrap();
        assert_eq!(
            d,
            Defaults {
                auth_mode: AuthMode::Prompt,
                default_backend: Backend::Bitwarden,
                service_user: Some("conductor".into()),
                allow_run: true,
                extra_manifests: vec!["/srv/a.env".into()],
            }
        );
    }

    #[test]
    fn allow_run_reads_each_accepted_spelling() {
        for v in ["yes", "true", "1"] {
            assert!(
                parse(&format!("allow_run = {v}\n")).unwrap().allow_run,
                "{v}"
            );
        }
        for v in ["no", "false", "0"] {
            assert!(
                !parse(&format!("allow_run = {v}\n")).unwrap().allow_run,
                "{v}"
            );
        }
    }

    #[test]
    fn an_empty_value_counts_as_unset() {
        // The shipped templates and install.sh write `key =` lines.
        let d = parse(
            "auth_mode =\ndefault_backend =\nservice_user =\nallow_run =\nextra_manifest =\n",
        )
        .unwrap();
        assert_eq!(d, Defaults::default());
    }

    #[test]
    fn an_empty_value_does_not_shadow_a_later_one() {
        let d = parse("default_backend =\ndefault_backend = plainfile\n").unwrap();
        assert_eq!(d.default_backend, Backend::Plainfile);
    }

    #[test]
    fn single_valued_keys_keep_the_first() {
        let d = parse(
            "auth_mode = prompt\nauth_mode = file\n\
             service_user = a\nservice_user = b\n\
             default_backend = pass\ndefault_backend = sops\n\
             allow_run = no\nallow_run = yes\n",
        )
        .unwrap();
        assert_eq!(d.auth_mode, AuthMode::Prompt);
        assert_eq!(d.service_user.as_deref(), Some("a"));
        assert_eq!(d.default_backend, Backend::Pass);
        assert!(!d.allow_run);
    }

    #[test]
    fn an_unknown_key_is_ignored() {
        // install.sh carries unmanaged keys forward; an older binary must not
        // refuse a newer file.
        let d = parse("future_key = whatever\nauth_mode = prompt\n").unwrap();
        assert_eq!(d.auth_mode, AuthMode::Prompt);
    }

    #[test]
    fn extra_manifests_keep_file_order() {
        let d = parse(
            "extra_manifest = /b\nauth_mode = file\nextra_manifest = /a = plainfile\n\
             extra_manifest = /c\n",
        )
        .unwrap();
        assert_eq!(d.extra_manifests, vec!["/b", "/a = plainfile", "/c"]);
    }

    #[test]
    fn an_invalid_auth_mode_names_its_line() {
        let msg = err("# c\nauth_mode = promt\n");
        assert_eq!(
            msg,
            "defaults.conf:2: auth_mode 'promt' is not file or prompt"
        );
    }

    #[test]
    fn an_unknown_default_backend_names_its_line() {
        let msg = err("\n\ndefault_backend = bitwarde\n");
        assert!(
            msg.starts_with("defaults.conf:3: default_backend: unknown backend 'bitwarde'"),
            "{msg}"
        );
        assert!(msg.contains("onepassword"), "{msg}");
    }

    #[test]
    fn an_unrecognised_allow_run_names_its_line() {
        let msg = err("allow_run = maybe\n");
        assert!(
            msg.starts_with("defaults.conf:1: allow_run 'maybe'"),
            "{msg}"
        );
        assert!(msg.contains("yes, true, 1, no, false or 0"), "{msg}");
    }

    #[test]
    fn a_malformed_line_names_its_line() {
        assert_eq!(
            err("auth_mode = file\nservice_user conductor\n"),
            "defaults.conf:2: expected key = value"
        );
    }

    #[test]
    fn env_overrides_win_when_non_empty() {
        let text = "service_user = conductor\ndefault_backend = pass\n";
        let d = Defaults::parse(
            text,
            EnvOverrides {
                service_user: Some("other"),
                default_backend: Some("op"),
            },
        )
        .unwrap();
        assert_eq!(d.service_user.as_deref(), Some("other"));
        assert_eq!(d.default_backend, Backend::OnePassword);

        let d = Defaults::parse(
            text,
            EnvOverrides {
                service_user: Some(""),
                default_backend: Some(""),
            },
        )
        .unwrap();
        assert_eq!(d.service_user.as_deref(), Some("conductor"));
        assert_eq!(d.default_backend, Backend::Pass);
    }

    #[test]
    fn an_env_override_names_a_service_user_with_no_file() {
        let d = Defaults::parse(
            "",
            EnvOverrides {
                service_user: Some("svc"),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(d.service_user.as_deref(), Some("svc"));
    }

    #[test]
    fn an_invalid_default_backend_override_names_the_variable() {
        let msg = Defaults::parse(
            "",
            EnvOverrides {
                default_backend: Some("vault"),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(
            msg.starts_with("VAULTED_AGENT_DEFAULT_BACKEND: unknown backend 'vault'"),
            "{msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_file_is_an_error_not_the_built_ins() {
        use std::os::unix::fs::PermissionsExt;
        if crate::token_file::is_euid_root() {
            // chmod 000 does not deny root; nothing useful to assert.
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        fs::write(&paths.defaults_file, "service_user = conductor\n").unwrap();
        fs::set_permissions(&paths.defaults_file, fs::Permissions::from_mode(0o000)).unwrap();
        let msg = Defaults::load(&paths).unwrap_err().to_string();
        assert!(
            msg.contains(&paths.defaults_file.display().to_string()),
            "{msg}"
        );
        assert!(msg.contains("Permission denied"), "{msg}");
    }
}
