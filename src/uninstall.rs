//! **Uninstall plan**: what one `uninstall` run would remove, leave alone
//! ("not ours") and keep — Backend credentials always, and config unless
//! `--purge`.
//!
//! Three steps. [`Facts::gather`] reads the disk: what is at each candidate
//! path, and what the config directory holds. [`plan`] decides everything from
//! those facts, purely. The report — "Found:", "About to remove:", the dry run
//! and the outcome — is rendered from the plan, and [`apply`] carries it out.
//! The Launcher's `uninstall` and `install.sh --uninstall` both run this.
//!
//! The menu and the final confirmation are asked through the Setup interview's
//! line-reading seam; each reply is parsed by a pure function (`*_reply`).

use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::config::Paths;
use crate::error::{Error, Result};
use crate::setup_interview::{ask, LineReader};

/// The sudoers rule `install.sh --allow-user` writes.
pub(crate) const SUDOERS_FILE: &str = "/etc/sudoers.d/vaulted-agent";

/// The launcher's file name, and the short alias the installer links to it.
const LAUNCHER: &str = "vaulted-agent";
const SHORT_NAME: &str = "va";

// ---------------------------------------------------------------------------
// The command line
// ---------------------------------------------------------------------------

/// `uninstall`'s command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Command {
    pub purge: bool,
    pub dry_run: bool,
    pub yes: bool,
    /// `--link-user` values, in the order given.
    pub link_users: Vec<String>,
}

pub(crate) const USAGE: &str =
    "usage: vaulted-agent uninstall [--purge] [--dry-run] [-y|--yes] [--link-user USER]\n\
     Removes the launcher, the symlinks that resolve to it, the sudoers rule, and\n\
     the user-local links of --link-user (and of SUDO_USER).\n\
     Keeps config unless --purge. Never removes op.env / bws.env / age.key.";

impl Command {
    /// `None` for `-h` / `--help`.
    pub(crate) fn parse(args: &[String]) -> Result<Option<Self>> {
        let mut cmd = Self::default();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--purge" => cmd.purge = true,
                "--dry-run" => cmd.dry_run = true,
                "-y" | "--yes" => cmd.yes = true,
                "-h" | "--help" => return Ok(None),
                "--link-user" => {
                    let user = args.next().filter(|u| !u.is_empty()).ok_or_else(|| {
                        Error::Message("uninstall: --link-user needs a username".into())
                    })?;
                    cmd.link_users.push(user.clone());
                }
                s if s.starts_with("--link-user=") => {
                    cmd.link_users.push(s["--link-user=".len()..].to_string());
                }
                other => {
                    return Err(Error::Message(format!(
                        "uninstall: unknown option '{other}'"
                    )))
                }
            }
        }
        Ok(Some(cmd))
    }
}

/// The users whose `~/.local/bin` links are candidates: every `--link-user`,
/// then `SUDO_USER`, each once.
pub(crate) fn link_users(given: &[String], sudo_user: Option<&str>) -> Vec<String> {
    let mut seen = HashSet::new();
    given
        .iter()
        .map(String::as_str)
        .chain(sudo_user)
        .filter(|u| !u.is_empty() && seen.insert(*u))
        .map(str::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// Facts
// ---------------------------------------------------------------------------

/// What is at one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Found {
    Nothing,
    /// A file or directory, not a symlink.
    Thing,
    /// A symlink and its canonical target; `None` when it dangles.
    Link(Option<PathBuf>),
}

impl Found {
    fn at(path: &Path) -> Self {
        match fs::symlink_metadata(path) {
            Err(_) => Self::Nothing,
            Ok(m) if m.file_type().is_symlink() => Self::Link(fs::canonicalize(path).ok()),
            Ok(_) => Self::Thing,
        }
    }
}

/// One entry directly inside the config directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigEntry {
    pub path: PathBuf,
    /// A real directory (not a symlink to one): removed as a tree.
    pub dir: bool,
}

/// What the config directory holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigFacts {
    pub dir: PathBuf,
    /// `harnesses.d/*.conf` and `manifests/*`, for the "Found:" line.
    pub harnesses: usize,
    pub manifests: usize,
    pub entries: Vec<ConfigEntry>,
}

/// Everything the plan is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Facts {
    /// `<bin>/vaulted-agent`, what is there, and its canonical path.
    pub launcher: (PathBuf, Found),
    pub launcher_canonical: Option<PathBuf>,
    /// Paths that are ours only as a symlink to the launcher: `<bin>/va`,
    /// `<bin>/*-conductor`, and `~/.local/bin/{vaulted-agent,va}` per link user.
    pub links: Vec<(PathBuf, Found)>,
    pub sudoers: (PathBuf, Found),
    /// `None` when there is no config directory.
    pub config: Option<ConfigFacts>,
    /// Never removed, even under `--purge`: the Manager-token files and the
    /// age key, from [`Paths`].
    pub credentials: Vec<PathBuf>,
    pub purge: bool,
}

impl Facts {
    /// Read the disk. `homes` are the link users' home directories.
    pub(crate) fn gather(bin_dir: &Path, paths: &Paths, homes: &[PathBuf], purge: bool) -> Self {
        let launcher = bin_dir.join(LAUNCHER);

        let mut link_paths = conductors(bin_dir);
        link_paths.push(bin_dir.join(SHORT_NAME));
        for home in homes {
            let local = home.join(".local/bin");
            link_paths.push(local.join(LAUNCHER));
            link_paths.push(local.join(SHORT_NAME));
        }
        let mut seen = HashSet::new();
        let links = link_paths
            .into_iter()
            .filter(|p| *p != launcher && seen.insert(p.clone()))
            .map(|p| {
                let found = Found::at(&p);
                (p, found)
            })
            .collect();

        let sudoers = PathBuf::from(SUDOERS_FILE);
        Self {
            launcher_canonical: fs::canonicalize(&launcher).ok(),
            launcher: (launcher.clone(), Found::at(&launcher)),
            links,
            sudoers: (sudoers.clone(), Found::at(&sudoers)),
            config: config_facts(&paths.config_dir),
            credentials: credentials(paths),
            purge,
        }
    }
}

/// The files `--purge` keeps.
pub(crate) fn credentials(paths: &Paths) -> Vec<PathBuf> {
    vec![
        paths.op_env_file.clone(),
        paths.bws_env_file.clone(),
        paths.age_key_file.clone(),
    ]
}

/// `<bin>/*-conductor`, sorted.
fn conductors(bin_dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(bin_dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with("-conductor"))
        .map(|e| e.path())
        .collect();
    found.sort();
    found
}

fn config_facts(dir: &Path) -> Option<ConfigFacts> {
    if !dir.is_dir() {
        return None;
    }
    let count = |sub: &str, keep: fn(&Path) -> bool| {
        fs::read_dir(dir.join(sub))
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| keep(&e.path()))
            .count()
    };
    let mut entries: Vec<ConfigEntry> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| ConfigEntry {
            dir: e.file_type().is_ok_and(|t| t.is_dir()),
            path: e.path(),
        })
        .collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Some(ConfigFacts {
        dir: dir.to_path_buf(),
        harnesses: count("harnesses.d", |p| {
            p.extension().is_some_and(|x| x == "conf")
        }),
        manifests: count("manifests", |_| true),
        entries,
    })
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

/// How one path is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum How {
    /// A file or a symlink.
    File,
    /// A directory and everything in it.
    Tree,
    /// The config directory, once its entries are gone.
    EmptyDir,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Removal {
    pub path: PathBuf,
    pub how: How,
}

/// What becomes of the config directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfigPlan {
    Absent,
    /// No `--purge`: kept as it is.
    Kept {
        dir: PathBuf,
        harnesses: usize,
        manifests: usize,
    },
    /// `--purge`: every entry but the credentials, and the directory itself
    /// only when nothing was kept in it.
    Purged {
        dir: PathBuf,
        harnesses: usize,
        manifests: usize,
        remove: Vec<Removal>,
        kept: Vec<PathBuf>,
    },
}

/// What one `uninstall` run would do, decided before anything is removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Ours, outside the config directory.
    pub remove: Vec<Removal>,
    /// At a candidate path, but not ours: left alone.
    pub not_ours: Vec<PathBuf>,
    pub config: ConfigPlan,
    /// Every credential file name, for the closing line.
    pub credential_names: Vec<String>,
}

/// Build the plan from facts. Reads nothing.
pub(crate) fn plan(facts: &Facts) -> Plan {
    let mut remove = Vec::new();
    let mut not_ours = Vec::new();

    let ours = |found: &Found| match found {
        Found::Link(Some(target)) => facts.launcher_canonical.as_ref() == Some(target),
        Found::Link(None) | Found::Thing | Found::Nothing => false,
    };
    for (path, found) in &facts.links {
        if ours(found) {
            remove.push(removal(path, How::File));
        } else if *found != Found::Nothing {
            not_ours.push(path.clone());
        }
    }

    // The launcher file is always ours; a symlink there dangling is not.
    let (launcher, found) = &facts.launcher;
    match found {
        Found::Thing | Found::Link(Some(_)) => remove.push(removal(launcher, How::File)),
        Found::Link(None) => not_ours.push(launcher.clone()),
        Found::Nothing => {}
    }
    // A dangling NOPASSWD rule is worse than none.
    let (sudoers, found) = &facts.sudoers;
    if *found != Found::Nothing {
        remove.push(removal(sudoers, How::File));
    }

    let config = match &facts.config {
        None => ConfigPlan::Absent,
        Some(c) if !facts.purge => ConfigPlan::Kept {
            dir: c.dir.clone(),
            harnesses: c.harnesses,
            manifests: c.manifests,
        },
        Some(c) => {
            let (kept, purged): (Vec<&ConfigEntry>, Vec<&ConfigEntry>) = c
                .entries
                .iter()
                .partition(|e| facts.credentials.contains(&e.path));
            let mut remove: Vec<Removal> = purged
                .iter()
                .map(|e| removal(&e.path, if e.dir { How::Tree } else { How::File }))
                .collect();
            if kept.is_empty() {
                remove.push(removal(&c.dir, How::EmptyDir));
            }
            ConfigPlan::Purged {
                dir: c.dir.clone(),
                harnesses: c.harnesses,
                manifests: c.manifests,
                remove,
                kept: kept.iter().map(|e| e.path.clone()).collect(),
            }
        }
    };

    Plan {
        remove,
        not_ours,
        config,
        credential_names: facts
            .credentials
            .iter()
            .filter_map(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .collect(),
    }
}

fn removal(path: &Path, how: How) -> Removal {
    Removal {
        path: path.to_path_buf(),
        how,
    }
}

impl Plan {
    /// Nothing of ours, and no config directory.
    pub(crate) fn is_empty(&self) -> bool {
        self.remove.is_empty() && self.config == ConfigPlan::Absent
    }

    /// Every removal, in order: ours first, then the purged config.
    pub(crate) fn removals(&self) -> impl Iterator<Item = &Removal> {
        let purged = match &self.config {
            ConfigPlan::Purged { remove, .. } => remove.as_slice(),
            ConfigPlan::Absent | ConfigPlan::Kept { .. } => &[],
        };
        self.remove.iter().chain(purged)
    }

    /// "Found:" — ours, the config directory, and what is not ours.
    pub(crate) fn found(&self) -> String {
        let mut out = String::from("Found:\n");
        for r in &self.remove {
            let _ = writeln!(out, "  {}", r.path.display());
        }
        match &self.config {
            ConfigPlan::Absent => {}
            ConfigPlan::Kept {
                dir,
                harnesses,
                manifests,
            }
            | ConfigPlan::Purged {
                dir,
                harnesses,
                manifests,
                ..
            } => {
                let _ = writeln!(
                    out,
                    "  {}  ({harnesses} live harnesses, {manifests} manifests)",
                    dir.display()
                );
            }
        }
        for p in &self.not_ours {
            let _ = writeln!(out, "  {}  (not ours, will be left alone)", p.display());
        }
        out
    }

    /// "About to remove:" — the exact paths.
    pub(crate) fn about_to_remove(&self) -> String {
        let mut out = String::from("About to remove:\n");
        for r in self.removals() {
            let _ = writeln!(out, "  {}", r.path.display());
        }
        out
    }

    /// The dry run: "would remove …" for each planned path.
    pub(crate) fn dry_run(&self) -> String {
        let mut out = String::new();
        for r in self.removals() {
            let _ = writeln!(out, "would remove {}", r.path.display());
        }
        out + &self.closing()
    }

    /// What happened: one line per removal, with `failed` naming the paths
    /// that could not be removed and why.
    pub(crate) fn outcome(&self, failed: &[(PathBuf, String)]) -> String {
        let mut out = String::new();
        for r in self.removals() {
            match failed.iter().find(|(p, _)| *p == r.path) {
                Some((p, why)) => {
                    let _ = writeln!(out, "could not remove {}: {why}", p.display());
                }
                None => {
                    let _ = writeln!(out, "removed {}", r.path.display());
                }
            }
        }
        out + &self.closing()
    }

    /// "left alone …", what became of the config, and the credentials line.
    fn closing(&self) -> String {
        let mut out = String::new();
        for p in &self.not_ours {
            let _ = writeln!(out, "left alone {} (not ours)", p.display());
        }
        match &self.config {
            ConfigPlan::Absent => {}
            ConfigPlan::Kept { dir, .. } => {
                let _ = writeln!(
                    out,
                    "\nkept {}. Add --purge, or choose 2 interactively, to remove it too.",
                    dir.display()
                );
            }
            ConfigPlan::Purged { kept, .. } if kept.is_empty() => {}
            ConfigPlan::Purged { dir, kept, .. } => {
                let names: Vec<String> = kept
                    .iter()
                    .filter_map(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .collect();
                let _ = writeln!(
                    out,
                    "\nkept {}: it still holds {}.",
                    dir.display(),
                    names.join(", ")
                );
            }
        }
        let _ = writeln!(
            out,
            "\nNot touched: any backend credential ({}).\n  \
             Those are often shared with other tooling; remove by hand if you want them gone.",
            self.credential_names.join(" / ")
        );
        out
    }
}

// ---------------------------------------------------------------------------
// Applying the plan
// ---------------------------------------------------------------------------

/// Remove every planned path, in order, carrying on past a failure. Returns
/// the paths that could not be removed and why.
pub(crate) fn apply(plan: &Plan) -> Vec<(PathBuf, String)> {
    plan.removals()
        .filter_map(|r| {
            let result = match r.how {
                How::File => fs::remove_file(&r.path),
                How::Tree => fs::remove_dir_all(&r.path),
                How::EmptyDir => fs::remove_dir(&r.path),
            };
            result
                .err()
                .map(|e: io::Error| (r.path.clone(), e.to_string()))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The questions. `ask_*` asks; `*_reply` parses, purely.
// ---------------------------------------------------------------------------

/// The menu's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Choice {
    /// Remove ours; keep config.
    Keep,
    /// Remove ours, and purge config.
    Purge,
    DryRun,
    Quit,
}

/// Menu reply. `Err` is the note shown before the menu is asked again.
pub(crate) fn menu_reply(reply: &str, has_config: bool) -> std::result::Result<Choice, String> {
    match reply.trim() {
        "1" => Ok(Choice::Keep),
        "2" if has_config => Ok(Choice::Purge),
        "2" => Err("no config directory to remove".into()),
        "3" => Ok(Choice::DryRun),
        "q" | "Q" => Ok(Choice::Quit),
        _ => Err("enter 1, 2, 3 or q".into()),
    }
}

/// Final confirmation reply. Anything but yes is no.
pub(crate) fn confirm_reply(reply: &str) -> bool {
    matches!(reply.trim(), "y" | "Y" | "yes" | "YES")
}

/// Offer keep config / also purge config / dry run / quit until a reply
/// parses. End of input quits.
pub(crate) fn ask_menu(plan: &Plan, read: &mut LineReader) -> Result<Choice> {
    let config = match &plan.config {
        ConfigPlan::Kept { dir, .. } | ConfigPlan::Purged { dir, .. } => Some(dir),
        ConfigPlan::Absent => None,
    };
    println!("\n  1) Remove the launcher, its symlinks and the sudoers rule; keep config");
    if let Some(dir) = config {
        println!(
            "  2) Remove all of that, and {} as well (credential files are kept)",
            dir.display()
        );
    }
    println!("  3) Show what would happen, change nothing");
    println!("  q) Quit\n");
    loop {
        let line = ask(read, "choice [1-3, q]: ")?;
        if line.is_empty() {
            return Ok(Choice::Quit);
        }
        match menu_reply(&line, config.is_some()) {
            Ok(choice) => return Ok(choice),
            Err(note) => println!("  {note}"),
        }
    }
}

/// Show the exact paths, then ask `[y/N]`.
pub(crate) fn ask_confirm(plan: &Plan, read: &mut LineReader) -> Result<bool> {
    println!("\n{}", plan.about_to_remove());
    Ok(confirm_reply(&ask(read, "Proceed? [y/N]: ")?))
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// One `uninstall` run. `interactive` is whether a human can answer; the
/// menu and the confirmation are asked only then, and never under `--yes`
/// or `--dry-run`.
pub(crate) fn run(
    cmd: &Command,
    mut facts: Facts,
    interactive: bool,
    read: &mut LineReader,
) -> Result<()> {
    let interactive = interactive && !cmd.yes && !cmd.dry_run;
    let mut dry = cmd.dry_run;
    let mut plan = plan(&facts);

    println!("vaulted-agent uninstall\n");
    if plan.is_empty() {
        println!("Nothing to remove: no launcher and no config directory found.");
        return Ok(());
    }
    print!("{}", plan.found());

    if interactive {
        if facts.purge {
            if let ConfigPlan::Purged { dir, .. } = &plan.config {
                println!(
                    "\n--purge given: {} will be removed too (credential files are kept).",
                    dir.display()
                );
            }
        } else {
            match ask_menu(&plan, read)? {
                Choice::Keep => {}
                Choice::Purge => {
                    facts.purge = true;
                    plan = self::plan(&facts);
                }
                Choice::DryRun => dry = true,
                Choice::Quit => {
                    println!("Nothing removed.");
                    return Ok(());
                }
            }
        }
        if !dry && !ask_confirm(&plan, read)? {
            println!("Nothing removed.");
            return Ok(());
        }
    }

    println!();
    if dry {
        print!("{}", plan.dry_run());
        return Ok(());
    }
    let failed = apply(&plan);
    print!("{}", plan.outcome(&failed));
    if failed.is_empty() {
        Ok(())
    } else {
        Err(Error::Message(format!(
            "uninstall: {} path(s) could not be removed",
            failed.len()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    const LAUNCHER_PATH: &str = "/bin-dir/vaulted-agent";

    fn ours() -> Found {
        Found::Link(Some(p(LAUNCHER_PATH)))
    }

    /// A machine with the launcher installed, no links, no config.
    fn facts() -> Facts {
        let paths = Paths::from_config_dir("/cfg");
        Facts {
            launcher: (p(LAUNCHER_PATH), Found::Thing),
            launcher_canonical: Some(p(LAUNCHER_PATH)),
            links: vec![],
            sudoers: (p(SUDOERS_FILE), Found::Nothing),
            config: None,
            credentials: credentials(&paths),
            purge: false,
        }
    }

    fn config(entries: &[(&str, bool)]) -> Option<ConfigFacts> {
        Some(ConfigFacts {
            dir: p("/cfg"),
            harnesses: 2,
            manifests: 1,
            entries: entries
                .iter()
                .map(|(name, dir)| ConfigEntry {
                    path: p("/cfg").join(name),
                    dir: *dir,
                })
                .collect(),
        })
    }

    fn removed(plan: &Plan) -> Vec<PathBuf> {
        plan.removals().map(|r| r.path.clone()).collect()
    }

    // --- ownership ----------------------------------------------------------

    #[test]
    fn only_a_link_to_the_launcher_is_ours() {
        let mut f = facts();
        f.links = vec![
            (p("/bin-dir/claude-conductor"), ours()),
            (
                p("/bin-dir/other-conductor"),
                Found::Link(Some(p("/bin/true"))),
            ),
            (p("/bin-dir/dangling-conductor"), Found::Link(None)),
            (p("/bin-dir/file-conductor"), Found::Thing),
            (p("/bin-dir/va"), Found::Nothing),
            (
                p("/home/alice/.local/bin/va"),
                Found::Link(Some(p("/usr/bin/va"))),
            ),
            (p("/home/alice/.local/bin/vaulted-agent"), ours()),
        ];
        let plan = plan(&f);
        assert_eq!(
            removed(&plan),
            vec![
                p("/bin-dir/claude-conductor"),
                p("/home/alice/.local/bin/vaulted-agent"),
                p(LAUNCHER_PATH),
            ]
        );
        assert_eq!(
            plan.not_ours,
            vec![
                p("/bin-dir/other-conductor"),
                p("/bin-dir/dangling-conductor"),
                p("/bin-dir/file-conductor"),
                p("/home/alice/.local/bin/va"),
            ]
        );
    }

    #[test]
    fn without_a_launcher_no_link_is_ours() {
        let mut f = facts();
        f.launcher = (p(LAUNCHER_PATH), Found::Nothing);
        f.launcher_canonical = None;
        f.links = vec![(p("/bin-dir/va"), Found::Link(None))];
        let plan = plan(&f);
        assert!(plan.remove.is_empty());
        assert_eq!(plan.not_ours, vec![p("/bin-dir/va")]);
        assert!(plan.is_empty(), "nothing of ours and no config");
    }

    #[test]
    fn a_launcher_file_and_the_sudoers_rule_are_always_removed() {
        let mut f = facts();
        f.sudoers.1 = Found::Thing;
        assert_eq!(removed(&plan(&f)), vec![p(LAUNCHER_PATH), p(SUDOERS_FILE)]);
    }

    #[test]
    fn a_dangling_launcher_link_is_not_ours() {
        let mut f = facts();
        f.launcher.1 = Found::Link(None);
        f.launcher_canonical = None;
        let plan = plan(&f);
        assert!(plan.remove.is_empty());
        assert_eq!(plan.not_ours, vec![p(LAUNCHER_PATH)]);
    }

    // --- config ---------------------------------------------------------------

    #[test]
    fn config_is_kept_without_purge() {
        let mut f = facts();
        f.config = config(&[("defaults.conf", false), ("op.env", false)]);
        let plan = plan(&f);
        assert_eq!(removed(&plan), vec![p(LAUNCHER_PATH)]);
        assert!(matches!(plan.config, ConfigPlan::Kept { .. }));
    }

    #[test]
    fn purge_keeps_the_credential_files_and_the_directory_holding_them() {
        let mut f = facts();
        f.purge = true;
        f.config = config(&[
            ("defaults.conf", false),
            ("harnesses.d", true),
            ("op.env", false),
        ]);
        let plan = plan(&f);
        assert_eq!(
            removed(&plan),
            vec![
                p(LAUNCHER_PATH),
                p("/cfg/defaults.conf"),
                p("/cfg/harnesses.d")
            ]
        );
        let ConfigPlan::Purged { remove, kept, .. } = &plan.config else {
            panic!("{:?}", plan.config);
        };
        assert_eq!(remove[1].how, How::Tree);
        assert_eq!(kept, &vec![p("/cfg/op.env")]);
        assert!(plan.dry_run().contains("kept /cfg: it still holds op.env."));
    }

    #[test]
    fn the_keep_set_comes_from_paths() {
        let mut f = facts();
        f.purge = true;
        f.config = config(&[("bws.env", false), ("age.key", false), ("other.env", false)]);
        let ConfigPlan::Purged { remove, kept, .. } = plan(&f).config else {
            panic!();
        };
        assert_eq!(kept, vec![p("/cfg/bws.env"), p("/cfg/age.key")]);
        assert_eq!(remove, vec![removal(&p("/cfg/other.env"), How::File)]);
    }

    #[test]
    fn purge_removes_the_directory_when_nothing_is_kept() {
        let mut f = facts();
        f.purge = true;
        f.config = config(&[("defaults.conf", false)]);
        let plan = plan(&f);
        assert_eq!(
            plan.removals().last(),
            Some(&removal(&p("/cfg"), How::EmptyDir))
        );
        assert!(!plan.dry_run().contains("kept /cfg"));
    }

    // --- report ---------------------------------------------------------------

    #[test]
    fn the_report_has_the_installer_shape() {
        let mut f = facts();
        f.config = config(&[]);
        f.links = vec![(p("/bin-dir/x-conductor"), Found::Link(Some(p("/bin/true"))))];
        let plan = plan(&f);
        let found = plan.found();
        assert!(
            found.starts_with("Found:\n  /bin-dir/vaulted-agent\n"),
            "{found}"
        );
        assert!(
            found.contains("  /cfg  (2 live harnesses, 1 manifests)"),
            "{found}"
        );
        assert!(found.contains("/bin-dir/x-conductor  (not ours, will be left alone)"));

        let dry = plan.dry_run();
        assert!(
            dry.contains("would remove /bin-dir/vaulted-agent\n"),
            "{dry}"
        );
        assert!(
            dry.contains("left alone /bin-dir/x-conductor (not ours)"),
            "{dry}"
        );
        assert!(dry.contains("kept /cfg. Add --purge"), "{dry}");
        assert!(dry.contains("(op.env / bws.env / age.key)"), "{dry}");

        let failed = vec![(p(LAUNCHER_PATH), "Permission denied".to_string())];
        let out = plan.outcome(&failed);
        assert!(out.contains("could not remove /bin-dir/vaulted-agent: Permission denied"));
    }

    // --- link users -----------------------------------------------------------

    #[test]
    fn sudo_user_is_deduplicated_against_link_users() {
        let given = args(&["alice", "bob", "alice"]);
        assert_eq!(link_users(&given, Some("alice")), args(&["alice", "bob"]));
        assert_eq!(
            link_users(&given, Some("carol")),
            args(&["alice", "bob", "carol"])
        );
        assert_eq!(link_users(&[], Some("")), Vec::<String>::new());
        assert_eq!(link_users(&[], None), Vec::<String>::new());
    }

    // --- the command line -------------------------------------------------------

    #[test]
    fn command_line() {
        let cmd = Command::parse(&args(&[
            "--purge",
            "-y",
            "--dry-run",
            "--link-user",
            "alice",
            "--link-user=bob",
        ]))
        .unwrap()
        .unwrap();
        assert!(cmd.purge && cmd.yes && cmd.dry_run);
        assert_eq!(cmd.link_users, args(&["alice", "bob"]));
        assert_eq!(Command::parse(&args(&["--help"])).unwrap(), None);
        assert!(Command::parse(&args(&["--link-user"])).is_err());
        assert!(Command::parse(&args(&["--nope"])).is_err());
    }

    // --- replies --------------------------------------------------------------

    #[test]
    fn menu_replies() {
        assert_eq!(menu_reply("1\n", true), Ok(Choice::Keep));
        assert_eq!(menu_reply(" 2 ", true), Ok(Choice::Purge));
        assert_eq!(
            menu_reply("2", false),
            Err("no config directory to remove".into())
        );
        assert_eq!(menu_reply("3", false), Ok(Choice::DryRun));
        assert_eq!(menu_reply("q", true), Ok(Choice::Quit));
        assert_eq!(menu_reply("Q", true), Ok(Choice::Quit));
        assert_eq!(menu_reply("", true), Err("enter 1, 2, 3 or q".into()));
        assert_eq!(menu_reply("yes", true), Err("enter 1, 2, 3 or q".into()));
    }

    #[test]
    fn confirm_replies() {
        for yes in ["y", "Y", "yes", "YES", " y\n"] {
            assert!(confirm_reply(yes), "{yes:?}");
        }
        for no in ["", "n", "no", "Yes", "q"] {
            assert!(!confirm_reply(no), "{no:?}");
        }
    }

    // --- the questions --------------------------------------------------------

    fn scripted(lines: &[&str]) -> impl FnMut() -> Result<String> {
        let mut lines: VecDeque<String> = lines.iter().map(|l| format!("{l}\n")).collect();
        move || Ok(lines.pop_front().expect("asked one question too many"))
    }

    #[test]
    fn the_menu_asks_again_until_a_reply_parses() {
        let mut f = facts();
        f.config = config(&[]);
        let plan = plan(&f);
        let mut read = scripted(&["", "9", "2"]);
        assert_eq!(ask_menu(&plan, &mut read).unwrap(), Choice::Purge);
    }

    #[test]
    fn end_of_input_quits_the_menu() {
        let plan = plan(&facts());
        let mut read = || Ok(String::new());
        assert_eq!(ask_menu(&plan, &mut read).unwrap(), Choice::Quit);
    }

    #[test]
    fn quitting_or_declining_removes_nothing() {
        let cmd = Command::default();
        // `run` would fail to remove /bin-dir/vaulted-agent if it got that far.
        run(&cmd, facts(), true, &mut scripted(&["q"])).unwrap();
        run(&cmd, facts(), true, &mut scripted(&["1", "n"])).unwrap();
        run(&cmd, facts(), true, &mut scripted(&["3"])).unwrap();
    }

    #[test]
    fn yes_and_dry_run_ask_nothing() {
        let never = &mut || -> Result<String> { panic!("the reader was called") };
        let dry = Command {
            dry_run: true,
            ..Command::default()
        };
        run(&dry, facts(), true, never).unwrap();
        let yes = Command {
            yes: true,
            ..Command::default()
        };
        // Asks nothing, then fails to remove the fictitious launcher.
        assert!(run(&yes, facts(), true, never).is_err());
    }

    #[test]
    fn a_failed_removal_fails_the_run() {
        assert!(run(&Command::default(), facts(), false, &mut scripted(&[])).is_err());
    }

    #[test]
    fn the_bin_dir_is_where_the_launcher_is_looked_for() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::write(bin.join(LAUNCHER), "").unwrap();
        std::os::unix::fs::symlink(bin.join(LAUNCHER), bin.join("a-conductor")).unwrap();
        std::os::unix::fs::symlink("/bin/true", bin.join("b-conductor")).unwrap();
        let paths = Paths::from_config_dir(tmp.path().join("cfg"));
        let f = Facts::gather(&bin, &paths, &[], false);
        let plan = plan(&f);
        assert_eq!(
            removed(&plan),
            vec![bin.join("a-conductor"), bin.join(LAUNCHER)]
        );
        assert_eq!(plan.not_ours, vec![bin.join("b-conductor")]);
    }
}
