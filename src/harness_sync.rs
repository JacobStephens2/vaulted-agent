//! **Harness discovery**: what adds a Harness conf for each auto-harness agent
//! found for the launch account and lacking an entry. `update
//! --sync-harnesses` runs it, and `install.sh` runs that, keeping no detection
//! of its own.
//!
//! Three steps. [`Facts::gather`] reads the machine: the auto-harness list,
//! which names already have an entry, the shared binding and the two accounts.
//! [`plan`] gives each auto-harness one fate (added, kept, found only for the
//! invoking account, not found), purely, with binary location and the
//! env-blind predicate passed in. [`Plan::apply`] writes the additions through
//! File replace's create-new; the report is rendered from the plan.

use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config::{self, Backend, Paths};
use crate::defaults::Defaults;
use crate::env_scrub::MANAGER_TOKEN_VARS;
use crate::error::{Error, Result};
use crate::inventory::Inventory;
use crate::vault_wiring::EMPTY_MANIFEST;

const AUTO_HARNESSES: &str = include_str!("../etc/auto-harnesses");

/// Tests only, like `VAULTED_AGENT_HANDOFF`: a file read as the auto-harness
/// list in place of the built-in one.
const AUTO_HARNESSES_ENV: &str = "VAULTED_AGENT_AUTO_HARNESSES";

/// Where binaries are searched after the account's own directories.
const SYSTEM_DIRS: [&str; 4] = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"];

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
            let mut retry = Command::new("sudo");
            retry
                .arg(exe)
                .args(["update", "--sync-harnesses"])
                .env_remove("VAULTED_AGENT_CONFIG_DIR");
            for name in MANAGER_TOKEN_VARS {
                retry.env_remove(name);
            }
            let status = retry
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
    let inventory = Inventory::load(paths)?;
    let facts = Facts::gather(paths, &inventory)?;
    let search = Search::new(&facts.accounts, &inventory);
    let plan = plan(
        paths,
        &facts,
        |name| search.locate(name),
        config::is_env_blind_agent,
    )?;
    let plan = if dry_run { plan } else { plan.apply(paths)? };
    print!("{}", plan.report(dry_run));
    Ok(())
}

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

/// The account a Harness launches as, and the one that ran this command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Accounts {
    pub launch: String,
    pub invoking: String,
}

impl Accounts {
    /// The launch account is the Service user (env override included); else
    /// `SUDO_USER` when running as root; else the current account. The
    /// invoking account is `SUDO_USER`, else the current account.
    fn settle(service_user: Option<String>, current: &str, sudo_user: Option<String>) -> Self {
        let sudo_user = sudo_user.filter(|u| !u.is_empty());
        let launch = service_user
            .or_else(|| sudo_user.clone().filter(|_| current == "root"))
            .unwrap_or_else(|| current.to_string());
        Self {
            launch,
            invoking: sudo_user.unwrap_or_else(|| current.to_string()),
        }
    }
}

/// Everything [`plan`] needs except binary location and env-blindness.
#[derive(Debug)]
pub(crate) struct Facts<'a> {
    /// Auto-harness commands, in list order; the first word names the Harness.
    pub auto: Vec<String>,
    /// Auto-harness names whose conf path already has an entry of any kind.
    pub existing: BTreeSet<String>,
    /// The Backend and `manifest =` text every Harness shares, if they agree.
    pub shared: Option<(Backend, &'a str)>,
    pub accounts: Accounts,
}

impl<'a> Facts<'a> {
    fn gather(paths: &Paths, inventory: &'a Inventory) -> Result<Self> {
        let list = match env::var_os(AUTO_HARNESSES_ENV) {
            Some(path) => fs::read_to_string(&path).map_err(|source| Error::Io {
                path: path.into(),
                source,
            })?,
            None => AUTO_HARNESSES.to_string(),
        };
        let auto = auto_harnesses(&list);
        // Includes dangling symlinks and directories: every existing entry is
        // operator-owned, even if it cannot currently be launched.
        let existing = auto
            .iter()
            .map(|command| harness_name(command))
            .filter(|name| fs::symlink_metadata(paths.harness_conf(name)).is_ok())
            .map(str::to_string)
            .collect();
        let shared = match inventory.shared_binding() {
            Ok(shared) => shared,
            Err(name) => {
                eprintln!(
                    "update: cannot read Harness {name}; new Harnesses will start without secrets"
                );
                None
            }
        };
        let accounts = Accounts::settle(
            Defaults::load(paths)?.service_user,
            &crate::privilege::current_user(),
            env::var("SUDO_USER").ok(),
        );
        Ok(Self {
            auto,
            existing,
            shared,
            accounts,
        })
    }
}

/// The commands of an auto-harness list: one per line, `#` comments and blank
/// lines skipped.
fn auto_harnesses(list: &str) -> Vec<String> {
    list.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

fn harness_name(command: &str) -> &str {
    command.split_whitespace().next().unwrap_or(command)
}

/// Where an auto-harness binary was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Located {
    /// For the launch account.
    Launch(PathBuf),
    /// Only for the invoking account, which is not the launch account.
    InvokerOnly(PathBuf),
    NotFound,
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// What one discovery run adds and why it leaves the rest.
#[derive(Debug)]
pub(crate) struct Plan {
    accounts: Accounts,
    entries: Vec<Entry>,
    /// Some addition starts on `plainfile` + `empty.env`.
    empty_starter: bool,
}

#[derive(Debug)]
struct Entry {
    name: String,
    conf: PathBuf,
    fate: Fate,
}

#[derive(Debug, PartialEq, Eq)]
enum Fate {
    Add(Addition),
    /// An entry already exists at the conf path.
    Kept,
    /// Found only for the invoking account, at this path.
    InvokerOnly(PathBuf),
    NotFound,
}

#[derive(Debug, PartialEq, Eq)]
struct Addition {
    backend: Backend,
    manifest: String,
    bin: PathBuf,
    /// The whole conf, as written.
    body: String,
}

impl Addition {
    fn without_secrets(&self) -> bool {
        self.backend == Backend::Plainfile && self.manifest == EMPTY_MANIFEST
    }
}

/// Give each auto-harness its fate. `locate` is asked only for names with no
/// entry; `env_blind` is matched against the command's basename and the
/// Harness name, as Vault wiring matches it.
pub(crate) fn plan(
    paths: &Paths,
    facts: &Facts,
    locate: impl Fn(&str) -> Located,
    env_blind: impl Fn(&str) -> bool,
) -> Result<Plan> {
    let mut entries = Vec::new();
    for command in &facts.auto {
        let name = harness_name(command);
        let fate = if facts.existing.contains(name) {
            Fate::Kept
        } else {
            match locate(name) {
                Located::Launch(binary) => {
                    Fate::Add(addition(command, &binary, facts, &env_blind)?)
                }
                Located::InvokerOnly(binary) => Fate::InvokerOnly(binary),
                Located::NotFound => Fate::NotFound,
            }
        };
        entries.push(Entry {
            name: name.to_string(),
            conf: paths.harness_conf(name),
            fate,
        });
    }
    let empty_starter = entries
        .iter()
        .any(|e| matches!(&e.fate, Fate::Add(a) if a.without_secrets()));
    Ok(Plan {
        accounts: facts.accounts.clone(),
        entries,
        empty_starter,
    })
}

fn addition(
    command: &str,
    binary: &Path,
    facts: &Facts,
    env_blind: impl Fn(&str) -> bool,
) -> Result<Addition> {
    let name = harness_name(command);
    let basename = Path::new(name).file_name().and_then(|b| b.to_str());
    let blind = [basename, Some(name)].into_iter().flatten().any(&env_blind);
    let (backend, manifest) = facts
        .shared
        .filter(|_| !blind)
        .unwrap_or((Backend::Plainfile, EMPTY_MANIFEST));
    let bin = binary.parent().unwrap_or(Path::new("/")).to_path_buf();
    let shown = bin.to_string_lossy();
    if shown.contains(['\n', '\r']) || manifest.contains(['\n', '\r']) {
        return Err(Error::Message(format!(
            "update: the directory or manifest for {name} contains a newline"
        )));
    }
    let body = format!(
        "# Added by Harness discovery: {name} was found for the launch account.\n\
         # Edit freely; discovery never rewrites an existing Harness.\n\
         backend = {backend}\n\
         manifest = {manifest}\n\
         workdir = caller\n\
         bin = {shown}\n\
         labels = no\n\
         command = {command}\n"
    );
    Ok(Addition {
        backend,
        manifest: manifest.to_string(),
        bin,
        body,
    })
}

impl Plan {
    /// Write the additions, `empty.env` first when one needs it. An entry that
    /// appeared since the plan was made is kept, not replaced.
    fn apply(mut self, paths: &Paths) -> Result<Self> {
        if self.empty_starter {
            ensure_empty_manifest(paths)?;
        }
        for entry in &mut self.entries {
            if let Fate::Add(addition) = &entry.fate {
                if !create(&entry.conf, &addition.body)? {
                    entry.fate = Fate::Kept;
                }
            }
        }
        Ok(self)
    }

    /// The per-agent report, then the `Try: va …` next step.
    fn report(&self, dry_run: bool) -> String {
        let Accounts { launch, invoking } = &self.accounts;
        let mut out = format!("Harness discovery for launch account {launch}:\n");
        for Entry { name, conf, fate } in &self.entries {
            let conf_shown = conf.display();
            match fate {
                Fate::Add(a) => {
                    let verb = if dry_run { "would add" } else { "added" };
                    let _ = writeln!(
                        out,
                        "  {name:<8} {verb} {conf_shown}  (backend={} manifest={} bin={})",
                        a.backend,
                        a.manifest,
                        a.bin.display()
                    );
                    if a.without_secrets() {
                        let _ = writeln!(
                            out,
                            "           {name} starts without secrets; choose its backend and manifest to enable injection"
                        );
                    }
                }
                Fate::Kept => {
                    let _ = writeln!(out, "  {name:<8} kept existing {conf_shown}");
                }
                Fate::InvokerOnly(binary) => {
                    let _ = writeln!(
                        out,
                        "  {name:<8} skipped: found for {invoking} but not for launch account {launch} ({})\n\
                         \x20          install {name} for {launch} (so `sudo -u {launch} command -v {name}` finds it),\n\
                         \x20          or configure {conf_shown} explicitly",
                        binary.display()
                    );
                }
                Fate::NotFound => {
                    let _ = writeln!(out, "  {name:<8} not found");
                }
            }
        }
        let ready: Vec<&str> = self
            .entries
            .iter()
            .filter(|e| matches!(e.fate, Fate::Add(_) | Fate::Kept))
            .map(|e| e.name.as_str())
            .collect();
        if !ready.is_empty() {
            let tries: Vec<String> = ready.iter().map(|n| format!("va {n}")).collect();
            let _ = writeln!(out, "  Try:  {}", tries.join("   /   "));
        }
        // bash is useful, but does not count as finding an agent CLI.
        if !ready.iter().any(|n| *n != "bash") {
            let _ = writeln!(
                out,
                "  No agent CLI found for {launch}. Install one, then run: va update --sync-harnesses\n\
                 \x20 or copy a harnesses.d/*.conf.example and drop the .example suffix."
            );
        }
        out
    }
}

// ---------------------------------------------------------------------------
// The adapter: binary search and writes
// ---------------------------------------------------------------------------

/// One search policy, for the launch account and, when it differs, the
/// invoking account.
struct Search {
    launch: AccountSearch,
    invoking: Option<AccountSearch>,
}

impl Search {
    fn new(accounts: &Accounts, inventory: &Inventory) -> Self {
        let current = crate::privilege::current_user();
        let bins: Vec<&str> = inventory
            .loaded()
            .filter_map(|v| v.harness.bin_dir.as_deref())
            .collect();
        Self {
            launch: AccountSearch::new(&accounts.launch, &current, &bins),
            invoking: (accounts.invoking != accounts.launch)
                .then(|| AccountSearch::new(&accounts.invoking, &current, &bins)),
        }
    }

    fn locate(&self, name: &str) -> Located {
        if let Some(binary) = self.launch.find(name) {
            return Located::Launch(binary);
        }
        match self.invoking.as_ref().and_then(|s| s.find(name)) {
            Some(binary) => Located::InvokerOnly(binary),
            None => Located::NotFound,
        }
    }
}

struct AccountSearch {
    /// Another account, whose `PATH` is probed through `sudo -n`.
    other: Option<String>,
    dirs: Vec<PathBuf>,
}

impl AccountSearch {
    /// The current account's `PATH`, or nothing here for another account (the
    /// probe covers it); then `~/.local/bin` and `~/.grok/bin` under that
    /// account's home, the `bin` dirs of loaded Harnesses, and the system dirs.
    fn new(account: &str, current: &str, bins: &[&str]) -> Self {
        let other = (account != current).then(|| account.to_string());
        let home = match &other {
            Some(user) => crate::privilege::account_home(user),
            None => env::var_os("HOME").map(PathBuf::from),
        };
        let mut dirs = match other {
            Some(_) => Vec::new(),
            None => env::split_paths(&env::var_os("PATH").unwrap_or_default()).collect(),
        };
        if let Some(home) = &home {
            dirs.push(home.join(".local/bin"));
            dirs.push(home.join(".grok/bin"));
        }
        for bin in bins {
            let expanded = match &home {
                Some(home) => config::expand_home(bin, &home.to_string_lossy()),
                None => bin.to_string(),
            };
            if Path::new(&expanded).is_absolute() {
                dirs.push(expanded.into());
            }
        }
        dirs.extend(SYSTEM_DIRS.map(PathBuf::from));
        Self { other, dirs }
    }

    fn find(&self, name: &str) -> Option<PathBuf> {
        self.other
            .as_deref()
            .and_then(|user| probe_path(user, name))
            .or_else(|| find_binary(name, &self.dirs))
    }
}

/// `command -v <name>` on another account's `PATH`, through a non-interactive
/// `sudo -n`. `command` is a shell builtin, so it runs under `sh -c`; the name
/// is an argument, never interpolated. Any failure is silent: the home and
/// system dirs still follow.
fn probe_path(user: &str, name: &str) -> Option<PathBuf> {
    let out = Command::new("sudo")
        .args([
            "-n",
            "-u",
            user,
            "sh",
            "-c",
            "command -v \"$1\"",
            "sh",
            name,
        ])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    path.is_absolute().then_some(path)
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
    let path = paths.manifest_dir.join(EMPTY_MANIFEST);
    create(
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

fn create(path: &Path, body: &str) -> Result<bool> {
    crate::file_replace::create_new(path, body.as_bytes(), 0o644).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        Paths::from_config_dir("/cfg")
    }

    fn accounts(launch: &str, invoking: &str) -> Accounts {
        Accounts {
            launch: launch.into(),
            invoking: invoking.into(),
        }
    }

    fn facts<'a>(
        auto: &[&str],
        existing: &[&str],
        shared: Option<(Backend, &'a str)>,
    ) -> Facts<'a> {
        Facts {
            auto: auto.iter().map(|s| s.to_string()).collect(),
            existing: existing.iter().map(|s| s.to_string()).collect(),
            shared,
            accounts: accounts("svc", "svc"),
        }
    }

    fn at(dir: &str) -> impl Fn(&str) -> Located + '_ {
        move |name| Located::Launch(Path::new(dir).join(name))
    }

    fn never(_: &str) -> bool {
        false
    }

    fn fates(plan: &Plan) -> Vec<(&str, &Fate)> {
        plan.entries
            .iter()
            .map(|e| (e.name.as_str(), &e.fate))
            .collect()
    }

    #[test]
    fn a_found_agent_without_an_entry_is_added_with_the_whole_conf_body() {
        let f = facts(&["claude --permission-mode auto"], &[], None);
        let plan = plan(&paths(), &f, at("/opt/bin"), never).unwrap();
        let Fate::Add(a) = &plan.entries[0].fate else {
            panic!("{plan:?}")
        };
        assert_eq!(
            plan.entries[0].conf,
            Path::new("/cfg/harnesses.d/claude.conf")
        );
        assert_eq!(a.bin, Path::new("/opt/bin"));
        assert_eq!(
            a.body,
            "# Added by Harness discovery: claude was found for the launch account.\n\
             # Edit freely; discovery never rewrites an existing Harness.\n\
             backend = plainfile\n\
             manifest = empty.env\n\
             workdir = caller\n\
             bin = /opt/bin\n\
             labels = no\n\
             command = claude --permission-mode auto\n"
        );
        assert!(plan.empty_starter);
    }

    #[test]
    fn an_existing_entry_is_kept_without_looking_for_the_binary() {
        let f = facts(&["muse"], &["muse"], None);
        let plan = plan(&paths(), &f, |_| panic!("located a kept name"), never).unwrap();
        assert_eq!(fates(&plan), [("muse", &Fate::Kept)]);
        assert!(!plan.empty_starter);
    }

    #[test]
    fn found_only_for_the_invoker_and_not_found_write_nothing() {
        let f = facts(&["a", "b"], &[], None);
        let plan = plan(
            &paths(),
            &f,
            |name| match name {
                "a" => Located::InvokerOnly("/home/op/.local/bin/a".into()),
                _ => Located::NotFound,
            },
            never,
        )
        .unwrap();
        assert_eq!(
            fates(&plan),
            [
                ("a", &Fate::InvokerOnly("/home/op/.local/bin/a".into())),
                ("b", &Fate::NotFound),
            ]
        );
        assert!(!plan.empty_starter);
    }

    #[test]
    fn a_new_harness_reuses_the_shared_binding_and_needs_no_starter() {
        let f = facts(
            &["codex"],
            &[],
            Some((Backend::Bitwarden, "openai.env.refs")),
        );
        let plan = plan(&paths(), &f, at("/usr/bin"), never).unwrap();
        let Fate::Add(a) = &plan.entries[0].fate else {
            panic!("{plan:?}")
        };
        assert_eq!(
            (a.backend, a.manifest.as_str()),
            (Backend::Bitwarden, "openai.env.refs")
        );
        assert!(a
            .body
            .contains("backend = bitwarden\nmanifest = openai.env.refs\n"));
        assert!(!plan.empty_starter);
    }

    #[test]
    fn an_env_blind_agent_starts_on_empty_env_by_command_basename_or_harness_name() {
        let shared = Some((Backend::Bitwarden, "openai.env.refs"));
        for (command, listed) in [("/opt/x/blind", "blind"), ("blind --flag", "blind")] {
            let f = facts(&[command], &[], shared);
            let plan = plan(&paths(), &f, at("/usr/bin"), |n| n == listed).unwrap();
            let Fate::Add(a) = &plan.entries[0].fate else {
                panic!("{plan:?}")
            };
            assert!(a.without_secrets(), "{command}");
            assert!(plan.empty_starter, "{command}");
        }
    }

    #[test]
    fn a_binary_directory_with_a_newline_is_refused() {
        let f = facts(&["muse"], &[], None);
        let err = plan(&paths(), &f, at("/tmp/a\nb"), never).unwrap_err();
        assert!(err.to_string().contains("newline"), "{err}");
    }

    #[test]
    fn the_report_names_every_fate_and_the_next_step() {
        let mut f = facts(&["claude", "muse", "inv", "gone", "bash"], &["muse"], None);
        f.accounts = accounts("svc", "operator");
        let plan = plan(
            &paths(),
            &f,
            |name| match name {
                "inv" => Located::InvokerOnly("/home/operator/.local/bin/inv".into()),
                "gone" => Located::NotFound,
                _ => Located::Launch(Path::new("/usr/bin").join(name)),
            },
            never,
        )
        .unwrap();
        let report = plan.report(false);
        assert!(
            report.starts_with("Harness discovery for launch account svc:\n"),
            "{report}"
        );
        assert!(report.contains("  claude   added /cfg/harnesses.d/claude.conf  (backend=plainfile manifest=empty.env bin=/usr/bin)\n"), "{report}");
        assert!(report.contains("claude starts without secrets"), "{report}");
        assert!(
            report.contains("  muse     kept existing /cfg/harnesses.d/muse.conf\n"),
            "{report}"
        );
        assert!(report.contains("  inv      skipped: found for operator but not for launch account svc (/home/operator/.local/bin/inv)\n"), "{report}");
        assert!(report.contains("install inv for svc"), "{report}");
        assert!(
            report.contains("or configure /cfg/harnesses.d/inv.conf explicitly"),
            "{report}"
        );
        assert!(report.contains("  gone     not found\n"), "{report}");
        assert!(
            report.contains("  Try:  va claude   /   va muse   /   va bash\n"),
            "{report}"
        );
        assert!(!report.contains("No agent CLI found"), "{report}");
        assert!(
            plan.report(true).contains("  claude   would add "),
            "dry run"
        );
    }

    #[test]
    fn bash_alone_is_not_an_agent_cli() {
        let f = facts(&["claude", "bash"], &[], None);
        let plan = plan(
            &paths(),
            &f,
            |name| match name {
                "bash" => Located::Launch("/bin/bash".into()),
                _ => Located::NotFound,
            },
            never,
        )
        .unwrap();
        let report = plan.report(false);
        assert!(report.contains("  Try:  va bash\n"), "{report}");
        assert!(report.contains("No agent CLI found for svc"), "{report}");
    }

    #[test]
    fn the_launch_account_is_the_service_user_else_sudo_user_as_root_else_current() {
        let s = |v: &str| Some(v.to_string());
        assert_eq!(
            Accounts::settle(s("svc"), "root", s("op")),
            accounts("svc", "op")
        );
        assert_eq!(
            Accounts::settle(None, "root", s("op")),
            accounts("op", "op")
        );
        assert_eq!(
            Accounts::settle(None, "root", None),
            accounts("root", "root")
        );
        assert_eq!(Accounts::settle(None, "me", s("op")), accounts("me", "op"));
        assert_eq!(Accounts::settle(None, "me", s("")), accounts("me", "me"));
    }

    #[test]
    fn the_auto_harness_list_skips_comments_and_blank_lines() {
        assert_eq!(
            auto_harnesses("# header\n\nclaude --x\n  muse  \n"),
            ["claude --x", "muse"]
        );
    }

    #[test]
    fn a_harness_bin_expands_only_a_leading_home() {
        let s = AccountSearch::new("me", "me", &["$HOME/bin", "/opt/$HOME/bin"]);
        if let Some(home) = env::var_os("HOME") {
            let home = PathBuf::from(home);
            assert!(s.dirs.contains(&home.join("bin")), "{:?}", s.dirs);
        }
        assert!(
            s.dirs.contains(&PathBuf::from("/opt/$HOME/bin")),
            "{:?}",
            s.dirs
        );
    }
}
