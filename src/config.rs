//! Machine defaults, harness definitions, and manifest path resolution.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::conf_file::{ConfFile, Line};
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

/// Vault backend. Exhaustive matching is the story #46 compile-time guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backend {
    Bitwarden,
    OnePassword,
    Pass,
    Sops,
    Plainfile,
}

impl Backend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bitwarden => "bitwarden",
            Self::OnePassword => "onepassword",
            Self::Pass => "pass",
            Self::Sops => "sops",
            Self::Plainfile => "plainfile",
        }
    }

    pub fn needs_manager_token(self) -> bool {
        matches!(self, Self::Bitwarden | Self::OnePassword)
    }

    /// Accept install/setup aliases (`bws`, `op`, `1password`).
    pub fn parse_loose(s: &str) -> Option<Self> {
        match s.trim() {
            "bitwarden" | "bws" => Some(Self::Bitwarden),
            "onepassword" | "op" | "1password" => Some(Self::OnePassword),
            "pass" => Some(Self::Pass),
            "sops" => Some(Self::Sops),
            "plainfile" => Some(Self::Plainfile),
            _ => None,
        }
    }
}

impl FromStr for Backend {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Backend::parse_loose(s).ok_or_else(|| Error::UnknownBackend(s.trim().to_string()))
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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

    /// Where the Harness named `name` is defined.
    pub fn harness_conf(&self, name: &str) -> PathBuf {
        self.harness_dir.join(format!("{name}.conf"))
    }

    /// Where a Manifest named by `manifest` lives: an absolute path as given,
    /// anything else under the manifest directory. The rule for a Harness's
    /// `manifest =` line and for a manifest named on the command line.
    pub fn resolve_manifest(&self, manifest: impl AsRef<Path>) -> PathBuf {
        let p = manifest.as_ref();
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.manifest_dir.join(p)
        }
    }
}

#[derive(Debug, Clone)]
pub struct Harness {
    pub name: String,
    pub backend: Option<Backend>,
    pub manifest: String,
    pub bin_dir: Option<String>,
    pub workdir: Option<String>,
    pub labels: bool,
    pub keep: Vec<String>,
    /// Child-env renames: `(target, source)`. Target gets a copy of source's
    /// resolved secret. Applied after inject, this harness only. See issue #66.
    pub aliases: Vec<(String, String)>,
    /// Non-secret child-env pairs (`env = NAME = value`). Applied after inject
    /// and aliases. Not for secrets (use the manifest). See issue #70 LEGACY flag.
    pub env_sets: Vec<(String, String)>,
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
        let conf = paths.harness_conf(name);
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
        let mut aliases: Vec<(String, String)> = Vec::new();
        let mut env_sets: Vec<(String, String)> = Vec::new();
        let mut command = Vec::new();
        let mut extra_args = Vec::new();

        let conf = ConfFile::parse(text);
        for line in conf.lines() {
            let (lineno, key, val) = match line {
                Line::Comment => continue,
                Line::Malformed { lineno } => {
                    return Err(Error::HarnessParse {
                        name: name.to_string(),
                        lineno,
                        msg: "expected key = value".into(),
                    });
                }
                Line::Entry { lineno, key, value } => (lineno, key, value),
            };
            match key {
                "backend" => {
                    backend = Some(val.parse().map_err(|_| Error::HarnessParse {
                        name: name.to_string(),
                        lineno,
                        msg: format!("unknown backend '{val}'"),
                    })?);
                }
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
                "alias" => {
                    // `alias = TARGET = SOURCE` — same shape as a shell assignment:
                    // TARGET takes the value of SOURCE in this harness's child env.
                    let Some((target, source)) = val.split_once('=') else {
                        return Err(Error::HarnessParse {
                            name: name.to_string(),
                            lineno,
                            msg: "alias expects TARGET = SOURCE (e.g. alias = OPENAI_API_KEY = FIREWORKS_AI_API_KEY)".into(),
                        });
                    };
                    let (target, source) = (target.trim(), source.trim());
                    if target.is_empty() || source.is_empty() {
                        return Err(Error::HarnessParse {
                            name: name.to_string(),
                            lineno,
                            msg: "alias needs both TARGET and SOURCE names".into(),
                        });
                    }
                    if !crate::validate::validate_var_name(target)
                        || !crate::validate::validate_var_name(source)
                    {
                        return Err(Error::HarnessParse {
                            name: name.to_string(),
                            lineno,
                            msg: format!(
                                "alias names must be shell-safe identifiers (got '{target}' / '{source}')"
                            ),
                        });
                    }
                    if target == source {
                        return Err(Error::HarnessParse {
                            name: name.to_string(),
                            lineno,
                            msg: format!(
                                "alias {target} = {source}: target and source are the same"
                            ),
                        });
                    }
                    aliases.push((target.to_string(), source.to_string()));
                }
                "env" => {
                    // `env = NAME = value` — non-secret child env (not vault material).
                    // Used e.g. for KIMI_CODE_LEGACY_FLAG until kimi-code#2746 ships.
                    let Some((name, value)) = val.split_once('=') else {
                        return Err(Error::HarnessParse {
                            name: name.to_string(),
                            lineno,
                            msg: "env expects NAME = value (e.g. env = KIMI_CODE_LEGACY_FLAG = 1)"
                                .into(),
                        });
                    };
                    let (ename, evalue) = (name.trim(), value.trim());
                    if ename.is_empty() {
                        return Err(Error::HarnessParse {
                            name: name.to_string(),
                            lineno,
                            msg: "env needs a variable name".into(),
                        });
                    }
                    if !crate::validate::validate_var_name(ename) {
                        return Err(Error::HarnessParse {
                            name: name.to_string(),
                            lineno,
                            msg: format!(
                                "env name must be a shell-safe identifier (got '{ename}')"
                            ),
                        });
                    }
                    if crate::env_scrub::MANAGER_TOKEN_VARS.contains(&ename) {
                        return Err(Error::HarnessParse {
                            name: name.to_string(),
                            lineno,
                            msg: format!("env cannot set manager-token name '{ename}'"),
                        });
                    }
                    env_sets.push((ename.to_string(), evalue.to_string()));
                }
                "command" => {
                    command = val.split_whitespace().map(|s| s.to_string()).collect();
                }
                "arg" => extra_args.push(val.to_string()),
                // These are real settings, just not per-harness ones. Saying
                // only "unknown key" sends people looking for a typo in a line
                // that is spelled correctly and merely in the wrong file.
                "service_user" | "auth_mode" | "default_backend" | "allow_run"
                | "extra_manifest" => {
                    return Err(Error::HarnessParse {
                        name: name.to_string(),
                        lineno,
                        msg: format!(
                            "'{key}' is a launcher-wide setting: move it to defaults.conf (it is not a per-harness key)"
                        ),
                    });
                }
                _ => {
                    return Err(Error::HarnessParse {
                        name: name.to_string(),
                        lineno,
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
            aliases,
            env_sets,
            command,
        })
    }

    pub fn resolve_manifest_path(&self, paths: &Paths) -> PathBuf {
        paths.resolve_manifest(&self.manifest)
    }

    /// Basename of the first command token (`kimi`, `claude`, …).
    pub fn command_basename(&self) -> Option<&str> {
        let prog = self.command.first()?;
        Path::new(prog).file_name().and_then(|s| s.to_str())
    }
}

/// Shared list of env-blind agent basenames (`etc/env-blind-agents`).
///
/// Install (`wire_day_one_harnesses`) reads the same file from the tree so
/// doctor and install cannot drift (PR #69 review).
const ENV_BLIND_AGENTS_LIST: &str = include_str!("../etc/env-blind-agents");

/// True when `name` is a command basename (or harness stem) listed in
/// `etc/env-blind-agents`.
pub fn is_env_blind_agent(name: &str) -> bool {
    for raw in ENV_BLIND_AGENTS_LIST.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if !line.is_empty() && line == name {
            return true;
        }
    }
    false
}

/// Doctor copy when `command_basename` is listed in `etc/env-blind-agents`.
pub fn env_blind_agent_reason(command_basename: &str) -> Option<&'static str> {
    is_env_blind_agent(command_basename).then_some(
        "this agent is listed in etc/env-blind-agents: it does not consume \
         vault-injected process-env credentials for the usual provider path. \
         Keep an empty manifest or put secrets where the tool actually reads them.",
    )
}

/// Read a single `key = value` from defaults.conf (first match wins).
pub fn load_default(paths: &Paths, key: &str) -> Option<String> {
    ConfFile::read(&paths.defaults_file)
        .ok()?
        .first(key)
        .map(str::to_string)
}

/// Every value recorded for `key` in defaults.conf, in file order.
///
/// `load_default` takes the first and stops, which is right for a setting that
/// has one value. A machine can read more than one manifest, so that key is
/// repeatable and the whole list matters.
pub fn load_defaults_all(paths: &Paths, key: &str) -> Vec<String> {
    ConfFile::read(&paths.defaults_file)
        .map(|c| c.all(key).into_iter().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Set (`Some`) or remove (`None`) a single-valued key in defaults.conf,
/// changing only that key's line. A new or empty file gets the header.
pub fn set_default(paths: &Paths, key: &str, value: Option<&str>) -> Result<()> {
    let mut conf = ConfFile::read(&paths.defaults_file)?;
    match value {
        Some(v) => conf.set(key, v)?,
        None => conf.remove(key),
    }
    if conf.is_changed() && conf.was_blank() {
        conf.prepend_comment("Machine-wide launcher defaults.");
    }
    conf.write(&paths.defaults_file)
}

/// A manifest something on this machine reads that no Harness launches from.
///
/// Systemd units, cron jobs and deploy scripts on a box commonly read a second
/// refs file of their own. It is a manifest in every sense that matters here —
/// the same references, resolved against the same vault, fail-closed in the
/// same way — and it is invisible to a check that walks harness profiles. That
/// invisibility is the whole defect: a deleted vault item took four units down
/// while `secrets validate` reported every harness green.
///
/// Recorded in defaults.conf, repeatable:
///
/// ```text
/// extra_manifest = /srv/orchestration/env.tpl
/// extra_manifest = /etc/other/refs.env = plainfile
/// ```
///
/// Deliberately not modelled as a harness with a `command`: nothing launches
/// it, and inventing a fake profile would put it in `secrets which`, in the
/// harness picker, and one `-H` away from being launched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraManifest {
    pub path: PathBuf,
    /// `None` means the machine default at the time of use.
    pub backend: Option<Backend>,
}

impl ExtraManifest {
    /// Parse one `extra_manifest =` value: `<path>` or `<path> = <backend>`.
    pub(crate) fn parse(value: &str, paths: &Paths) -> Result<Self> {
        let (path, backend) = match value.split_once('=') {
            Some((p, b)) => (p.trim(), Some(b.trim().parse::<Backend>()?)),
            None => (value.trim(), None),
        };
        if path.is_empty() {
            return Err(Error::Message(
                "extra_manifest needs a path (defaults.conf)".into(),
            ));
        }
        Ok(Self {
            path: paths.resolve_manifest(path),
            backend,
        })
    }
}

pub fn load_auth_mode(paths: &Paths) -> AuthMode {
    load_default(paths, "auth_mode")
        .and_then(|s| AuthMode::parse(&s))
        .unwrap_or(AuthMode::File)
}

/// Expand a leading `$HOME` or `${HOME}` in a harness value with `home`.
/// Anything else, including `$HOME` later in the value, is left as written.
pub(crate) fn expand_home(value: &str, home: &str) -> String {
    match value
        .strip_prefix("${HOME}")
        .or_else(|| value.strip_prefix("$HOME"))
    {
        Some(rest) => format!("{home}{rest}"),
        None => value.to_string(),
    }
}

/// Service account for sudo re-exec (optional). Env VAULTED_AGENT_SERVICE_USER wins.
pub fn load_service_user(paths: &Paths) -> Option<String> {
    if let Ok(v) = std::env::var("VAULTED_AGENT_SERVICE_USER") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    load_default(paths, "service_user")
}

/// Whether `run` may execute an arbitrary command on a machine that has a
/// service account configured. Defaults to false.
///
/// Deliberately config-file only, with no environment override: the whole point
/// is to bound what a caller can ask for, and a caller controls their own
/// environment.
pub fn load_allow_run(paths: &Paths) -> bool {
    load_default(paths, "allow_run")
        .map(|v| matches!(v.trim(), "yes" | "true" | "1"))
        .unwrap_or(false)
}

/// Default vault backend when harness omits backend=.
pub fn load_default_backend(paths: &Paths) -> Backend {
    if let Ok(v) = std::env::var("VAULTED_AGENT_DEFAULT_BACKEND") {
        if !v.is_empty() {
            if let Ok(b) = v.parse() {
                return b;
            }
        }
    }
    load_default(paths, "default_backend")
        .and_then(|s| s.parse().ok())
        .unwrap_or(Backend::OnePassword)
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

/// Set `workdir` on every Harness [`list_harness_names`] finds, appending the
/// line where a conf has none. Returns how many Harnesses now carry it.
pub fn set_harnesses_workdir(paths: &Paths, workdir: &str) -> Result<usize> {
    let names = list_harness_names(paths)?;
    for name in &names {
        let path = paths.harness_conf(name);
        let mut conf = ConfFile::read(&path)?;
        conf.set("workdir", workdir)?;
        conf.write(&path)?;
    }
    Ok(names.len())
}

/// Ordered KEY=value pairs (shared policy for validate + resolve).
///
/// The launch's projection of [`crate::manifest_entry`], where the line rules
/// (quotes, multi-line values, variable names) live. Fails closed on the first
/// fault (story #37).
pub fn parse_dotenv_pairs(text: &str) -> Result<Vec<(String, String)>> {
    let parsed = crate::manifest_entry::parse(text);
    if let Some(fault) = parsed.faults.into_iter().next() {
        return Err(Error::Message(fault.message));
    }
    Ok(parsed
        .entries
        .into_iter()
        .map(|e| (e.var, e.value))
        .collect())
}

/// Parse KEY=value dotenv-style lines into a map (last key wins).
pub fn parse_dotenv_keys(text: &str) -> Result<HashMap<String, String>> {
    let mut m = HashMap::new();
    for (k, v) in parse_dotenv_pairs(text)? {
        m.insert(k, v);
    }
    Ok(m)
}

/// First value for `key` in dotenv text, using the shared parse policy.
pub fn parse_dotenv_var(text: &str, key: &str) -> Result<Option<String>> {
    for (k, v) in parse_dotenv_pairs(text)? {
        if k == key {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_home_replaces_only_a_leading_home() {
        assert_eq!(expand_home("$HOME/bin", "/home/op"), "/home/op/bin");
        assert_eq!(expand_home("${HOME}/bin", "/home/op"), "/home/op/bin");
        assert_eq!(expand_home("$HOME", "/home/op"), "/home/op");
        assert_eq!(expand_home("/opt/$HOME/bin", "/home/op"), "/opt/$HOME/bin");
        assert_eq!(expand_home("claude", "/home/op"), "claude");
        assert_eq!(expand_home("$HOME/bin", ""), "/bin");
    }

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
    fn env_blind_list_does_not_classify_kimi_as_structurally_blind() {
        // Issue #70: kimi reads process.env; 0.33–0.34 only fail on kimi-code#2745.
        assert!(!is_env_blind_agent("kimi"));
        assert!(!is_env_blind_agent("claude"));
        assert!(env_blind_agent_reason("kimi").is_none());
        assert!(env_blind_agent_reason("claude").is_none());
    }

    #[test]
    fn parse_harness_rejects_unknown_key() {
        let err = Harness::parse("x", "manifest = a\ncommand = true\nfoo = bar\n").unwrap_err();
        assert!(format!("{err}").contains("unknown key"));
    }

    #[test]
    fn parse_harness_alias_lines() {
        let h = Harness::parse(
            "kimi",
            "manifest = full.env.tpl\n\
             alias = OPENAI_API_KEY = FIREWORKS_AI_API_KEY\n\
             alias = ANTHROPIC_API_KEY = OTHER_KEY\n\
             command = kimi --auto\n",
        )
        .unwrap();
        assert_eq!(
            h.aliases,
            vec![
                ("OPENAI_API_KEY".into(), "FIREWORKS_AI_API_KEY".into()),
                ("ANTHROPIC_API_KEY".into(), "OTHER_KEY".into()),
            ]
        );
    }

    #[test]
    fn parse_harness_env_sets_non_secret_child_vars() {
        let h = Harness::parse(
            "kimi",
            "manifest = empty.env\n\
             env = KIMI_CODE_LEGACY_FLAG = 1\n\
             command = kimi --auto\n",
        )
        .unwrap();
        assert_eq!(
            h.env_sets,
            vec![("KIMI_CODE_LEGACY_FLAG".into(), "1".into())]
        );
    }

    #[test]
    fn parse_harness_env_refuses_manager_token_names() {
        let err = Harness::parse(
            "x",
            "manifest = m\ncommand = true\nenv = OP_SERVICE_ACCOUNT_TOKEN = x\n",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("manager-token"), "{err}");
    }

    #[test]
    fn parse_harness_alias_requires_target_and_source() {
        let err = Harness::parse(
            "kimi",
            "manifest = m\ncommand = true\nalias = OPENAI_API_KEY\n",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("TARGET = SOURCE"), "{err}");
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
    fn set_default_writes_the_header_into_a_new_file() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path().join("etc"));
        set_default(&paths, "auth_mode", Some("prompt")).unwrap();
        assert_eq!(
            fs::read_to_string(&paths.defaults_file).unwrap(),
            "# Machine-wide launcher defaults.\nauth_mode = prompt\n"
        );
        assert_eq!(load_auth_mode(&paths), AuthMode::Prompt);
    }

    #[test]
    fn set_default_none_removes_only_that_key() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        fs::write(
            &paths.defaults_file,
            "# mine\nservice_user = svc\nextra_manifest = /a\nextra_manifest = /b\n",
        )
        .unwrap();
        set_default(&paths, "service_user", None).unwrap();
        assert_eq!(
            fs::read_to_string(&paths.defaults_file).unwrap(),
            "# mine\nextra_manifest = /a\nextra_manifest = /b\n"
        );
        assert_eq!(
            load_defaults_all(&paths, "extra_manifest"),
            vec!["/a", "/b"]
        );
    }

    #[test]
    fn removing_an_absent_default_creates_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        set_default(&paths, "service_user", None).unwrap();
        assert!(!paths.defaults_file.exists());
    }

    #[test]
    fn set_default_refuses_a_line_break() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        assert!(set_default(&paths, "service_user", Some("svc\nallow_run = yes")).is_err());
        assert!(!load_allow_run(&paths));
    }

    #[test]
    fn set_harnesses_workdir_edits_every_listed_harness() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        fs::create_dir_all(&paths.harness_dir).unwrap();
        fs::write(
            paths.harness_conf("claude"),
            "# shipped\nmanifest = empty.env\nworkdir  = /old\ncommand  = claude\n",
        )
        .unwrap();
        fs::write(
            paths.harness_conf("codex"),
            "manifest = empty.env\ncommand = codex\n",
        )
        .unwrap();
        fs::write(paths.harness_dir.join("notes.txt"), "workdir = untouched\n").unwrap();

        assert_eq!(set_harnesses_workdir(&paths, "caller").unwrap(), 2);
        assert_eq!(
            fs::read_to_string(paths.harness_conf("claude")).unwrap(),
            "# shipped\nmanifest = empty.env\nworkdir  = caller\ncommand  = claude\n"
        );
        assert_eq!(
            fs::read_to_string(paths.harness_conf("codex")).unwrap(),
            "manifest = empty.env\ncommand = codex\nworkdir = caller\n"
        );
        assert_eq!(
            fs::read_to_string(paths.harness_dir.join("notes.txt")).unwrap(),
            "workdir = untouched\n"
        );
        let h = Harness::load(&paths, "codex").unwrap();
        assert_eq!(h.workdir.as_deref(), Some("caller"));
    }

    #[test]
    fn set_harnesses_workdir_without_a_harness_directory_is_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        assert_eq!(set_harnesses_workdir(&paths, "caller").unwrap(), 0);
    }

    #[test]
    fn a_malformed_harness_line_keeps_its_line_number() {
        let err = Harness::parse("x", "# c\n\nmanifest = a\noops\ncommand = true\n").unwrap_err();
        assert_eq!(err.to_string(), "harness x:4: expected key = value");
    }

    #[test]
    fn an_extra_manifest_may_name_a_backend() {
        let paths = Paths::from_config_dir("/etc/vaulted-agent");
        let plain = ExtraManifest::parse("/srv/orchestration/env.tpl", &paths).unwrap();
        assert_eq!(plain.path, PathBuf::from("/srv/orchestration/env.tpl"));
        assert_eq!(plain.backend, None);
        let named = ExtraManifest::parse("/etc/other/refs.env = plainfile", &paths).unwrap();
        assert_eq!(named.path, PathBuf::from("/etc/other/refs.env"));
        assert_eq!(named.backend, Some(Backend::Plainfile));
    }

    #[test]
    fn a_relative_extra_manifest_resolves_like_a_harness_manifest() {
        let paths = Paths::from_config_dir("/etc/vaulted-agent");
        let extra = ExtraManifest::parse("other.env.tpl", &paths).unwrap();
        assert_eq!(extra.path, paths.manifest_dir.join("other.env.tpl"));
    }

    #[test]
    fn an_unreadable_extra_manifest_line_is_an_error() {
        // Reporting green because a line could not be parsed is the exact
        // shape of the fault this concept exists to prevent.
        let paths = Paths::from_config_dir("/etc/vaulted-agent");
        assert!(ExtraManifest::parse("/x = nosuch", &paths).is_err());
        assert!(ExtraManifest::parse(" = plainfile", &paths).is_err());
    }

    #[test]
    fn extra_manifest_in_a_harness_file_says_where_it_belongs() {
        let err = Harness::parse(
            "claude",
            "extra_manifest = /x
command = claude
",
        )
        .expect_err("extra_manifest is not a harness key");
        assert!(err.to_string().contains("defaults.conf"), "{err}");
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

    #[test]
    fn parse_dotenv_strips_quotes() {
        let m = parse_dotenv_keys("QUOTED=\"hello world\"\nSINGLE='x y'\n").unwrap();
        assert_eq!(m.get("QUOTED").map(String::as_str), Some("hello world"));
        assert_eq!(m.get("SINGLE").map(String::as_str), Some("x y"));
    }

    #[test]
    fn parse_dotenv_multiline_double_quoted() {
        let m = parse_dotenv_keys("PEM=\"line1\nline2\"\n").unwrap();
        assert_eq!(m.get("PEM").map(String::as_str), Some("line1\nline2"));
    }

    #[test]
    fn parse_dotenv_rejects_bad_var_name() {
        assert!(parse_dotenv_keys("MY-VAR=secret\n").is_err());
    }

    #[test]
    fn launcher_wide_key_in_a_harness_says_where_it_belongs() {
        let err = Harness::parse("claude", "service_user = conductor\ncommand = claude\n")
            .expect_err("service_user is not a harness key");
        let msg = err.to_string();
        assert!(msg.contains("defaults.conf"), "{msg}");
        // The old text was a bare "unknown key", which reads as a typo in a
        // line that is spelled correctly and merely in the wrong file.
        assert!(!msg.contains("unknown key"), "{msg}");
    }

    #[test]
    fn a_genuinely_unknown_key_still_reads_as_unknown() {
        let err = Harness::parse("claude", "wat = 1\ncommand = claude\n").expect_err("unknown key");
        assert!(err.to_string().contains("unknown key"), "{err}");
    }

    #[test]
    fn parse_dotenv_pairs_preserves_order() {
        let p = parse_dotenv_pairs("A=1\nB=2\n").unwrap();
        assert_eq!(p, vec![("A".into(), "1".into()), ("B".into(), "2".into())]);
    }

    #[test]
    fn parse_dotenv_carries_bare_multiline_json() {
        // What `op inject` emits for a pretty-printed service-account key. The
        // inner line containing '=' must stay part of the value.
        let text = "A=1\nSA={\n  \"type\": \"service_account\",\n  \"tok\": \"ab==\"\n}\n\nB=2\n";
        let p = parse_dotenv_pairs(text).unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p[0], ("A".into(), "1".into()));
        assert_eq!(p[2], ("B".into(), "2".into()));
        assert_eq!(p[1].0, "SA");
        assert_eq!(
            p[1].1,
            "{\n  \"type\": \"service_account\",\n  \"tok\": \"ab==\"\n}"
        );
    }

    #[test]
    fn parse_dotenv_carries_bare_multiline_pem() {
        let text = "K=-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n";
        let p = parse_dotenv_pairs(text).unwrap();
        assert_eq!(p.len(), 1);
        assert!(p[0].1.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(p[0].1.ends_with("-----END RSA PRIVATE KEY-----"));
        assert_eq!(p[0].1.lines().count(), 3);
    }

    #[test]
    fn parse_dotenv_blank_line_closes_a_bare_value() {
        // A stray line after the value has ended is an error, not a silent
        // append onto the secret above it.
        assert!(parse_dotenv_pairs("A=1\n\noops\n").is_err());
    }

    #[test]
    fn parse_dotenv_comment_closes_a_bare_value() {
        assert!(parse_dotenv_pairs("A=1\n# note\noops\n").is_err());
    }

    #[test]
    fn parse_dotenv_still_rejects_a_leading_bad_name() {
        // Nothing is open, so this stays the fail-closed error of story #37.
        assert!(parse_dotenv_pairs("MY-VAR=secret\n").is_err());
    }

    #[test]
    fn parse_dotenv_double_quoted_value_does_not_absorb_later_lines() {
        let p = parse_dotenv_pairs("A=\"one\ntwo\"\nB=2\n").unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0], ("A".into(), "one\ntwo".into()));
        assert_eq!(p[1], ("B".into(), "2".into()));
    }

    #[test]
    fn parse_dotenv_var_uses_shared_policy() {
        assert_eq!(
            parse_dotenv_var("X=\"hi there\"\n", "X")
                .unwrap()
                .as_deref(),
            Some("hi there")
        );
    }

    #[test]
    fn harness_rejects_unknown_backend() {
        let err =
            Harness::parse("x", "backend = bitwarde\nmanifest = a\ncommand = true\n").unwrap_err();
        assert!(format!("{err}").contains("unknown backend"));
    }
}
