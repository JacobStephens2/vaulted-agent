//! **Vault wiring**: what makes a machine use a Backend after `setup` —
//! `default_backend`, a starter Refs file, and every day-one Harness switched
//! from `plainfile` + `empty.env` to that Backend and Refs file, with
//! `workdir = caller` where it has none.
//!
//! Two calls. [`plan`] reads the Inventory and decides everything, as data:
//! each Harness with its fate, wired or left with a reason. [`Plan::apply`]
//! writes that plan through the Conf file module and File replace. The Manager
//! token is not part of it: wiring needs none, so a missing or rejected token
//! still leaves the machine wired.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::conf_file::ConfFile;
use crate::config::{self, Backend, Paths};
use crate::error::{Error, Result};
use crate::file_replace;
use crate::inventory::{HarnessView, Inventory};

/// The Manifest the installer and `update --sync-harnesses` give a Harness
/// that has no vault yet.
pub(crate) const EMPTY_MANIFEST: &str = "empty.env";

/// The Refs file wiring and `refresh` use on `be` when no Harness on `be`
/// names one; `None` for a Backend that wires no Harness.
fn fallback_refs_file(be: Backend) -> Option<&'static str> {
    match be {
        Backend::Bitwarden => Some("openai.env.refs"),
        Backend::OnePassword => Some("onepassword.refs"),
        Backend::Pass => Some("pass.refs"),
        Backend::Sops | Backend::Plainfile => None,
    }
}

/// The Refs file for `be`: the one Manifest the Harnesses on `be` already
/// use, else the Backend's fallback under the manifest directory. Refuses
/// when several Manifests are on `be`, or a Harness will not load (its
/// Backend is unknown). `None` for a Backend that wires no Harness.
pub(crate) fn refs_file(
    paths: &Paths,
    inventory: &Inventory,
    be: Backend,
) -> Result<Option<PathBuf>> {
    let Some(fallback) = fallback_refs_file(be) else {
        return Ok(None);
    };
    Ok(Some(
        inventory
            .manifest_for(be)?
            .unwrap_or_else(|| paths.manifest_dir.join(fallback)),
    ))
}

/// Everything one `setup <backend>` would change, decided before any write.
#[derive(Debug)]
pub(crate) struct Plan {
    backend: Backend,
    /// The machine default the Inventory read, before this plan.
    default_was: Backend,
    /// `None` when the Backend wires no Harness (`sops`).
    refs: Option<RefsTarget>,
    harnesses: Vec<HarnessFate>,
}

#[derive(Debug)]
struct RefsTarget {
    path: PathBuf,
    /// The `manifest =` text a wired Harness gets.
    manifest: String,
    /// Absent, so apply creates the starter.
    create: bool,
}

#[derive(Debug)]
struct HarnessFate {
    name: String,
    conf: PathBuf,
    fate: Fate,
}

#[derive(Debug, PartialEq, Eq)]
enum Fate {
    Wire { add_workdir: bool },
    Left(Left),
}

/// Why a Harness is left as it is.
#[derive(Debug, PartialEq, Eq)]
enum Left {
    /// Not `plainfile` + `empty.env`: operator intent, or already wired.
    NotDayOne { backend: Backend, manifest: String },
    /// Listed in `etc/env-blind-agents`, under this name.
    EnvBlind(String),
    /// The conf will not load.
    Unreadable(String),
    /// Day-one, but this Backend wires no Harness.
    NotWired,
}

/// The wiring `setup <backend>` would do on this machine.
pub(crate) fn plan(paths: &Paths, inventory: &Inventory, backend: Backend) -> Result<Plan> {
    plan_with(paths, inventory, backend, config::is_env_blind_agent)
}

/// [`plan`], with the env-blind list as a parameter: the shipped list may be
/// empty.
fn plan_with(
    paths: &Paths,
    inventory: &Inventory,
    backend: Backend,
    env_blind: impl Fn(&str) -> bool,
) -> Result<Plan> {
    let refs = refs_file(paths, inventory, backend)?.map(|path| RefsTarget {
        manifest: manifest_text(paths, &path),
        create: std::fs::symlink_metadata(&path).is_err(),
        path,
    });
    let empty = paths.resolve_manifest(EMPTY_MANIFEST);
    let harnesses = inventory
        .harnesses()
        .iter()
        .map(|e| HarnessFate {
            name: e.name.clone(),
            conf: e.conf.clone(),
            fate: match &e.loaded {
                Err(err) => Fate::Left(Left::Unreadable(err.to_string())),
                Ok(v) => fate(v, &empty, refs.is_some(), &env_blind),
            },
        })
        .collect();
    Ok(Plan {
        backend,
        default_was: inventory.default_backend(),
        refs,
        harnesses,
    })
}

fn fate(v: &HarnessView, empty: &Path, wires: bool, env_blind: impl Fn(&str) -> bool) -> Fate {
    if v.binding.backend != Backend::Plainfile || v.binding.manifest != empty {
        return Fate::Left(Left::NotDayOne {
            backend: v.binding.backend,
            manifest: v.harness.manifest.clone(),
        });
    }
    let listed = [v.harness.command_basename(), Some(v.harness.name.as_str())]
        .into_iter()
        .flatten()
        .find(|n| env_blind(n));
    if let Some(name) = listed {
        return Fate::Left(Left::EnvBlind(name.to_string()));
    }
    if !wires {
        return Fate::Left(Left::NotWired);
    }
    Fate::Wire {
        add_workdir: v.harness.workdir.is_none(),
    }
}

/// A Refs file under the manifest directory by its name, anything else by
/// its full path.
fn manifest_text(paths: &Paths, path: &Path) -> String {
    match path.strip_prefix(&paths.manifest_dir) {
        Ok(rel) => rel.display().to_string(),
        Err(_) => path.display().to_string(),
    }
}

/// The starter Refs file. No reference shape in it (`op://`, `name:`, a
/// uuid): `op inject` resolves comments too, and the Manifest check flags one.
/// Only a Backend with a fallback Refs file gets one, so sops never does.
fn starter(backend: Backend) -> String {
    let (what, fill) = match backend {
        Backend::Bitwarden => (
            "Bitwarden Secrets Manager",
            "Map secrets into it with: vaulted-agent refresh",
        ),
        Backend::OnePassword => (
            "1Password",
            "Map items into it with: vaulted-agent refresh --backend onepassword",
        ),
        Backend::Pass | Backend::Sops | Backend::Plainfile => (
            "pass (passwordstore.org)",
            "Add one line per secret, the variable and its store path: vaulted-agent edit-manifest",
        ),
    };
    format!(
        "# {what} Refs file, created by vaulted-agent setup.\n\
         # References only, never secret values. {fill}\n"
    )
}

impl Plan {
    /// True when applying would change nothing.
    fn is_empty(&self) -> bool {
        self.default_was == self.backend
            && !self.refs.as_ref().is_some_and(|r| r.create)
            && !self
                .harnesses
                .iter()
                .any(|h| matches!(h.fate, Fate::Wire { .. }))
    }

    /// Record `default_backend`, create the starter Refs file when absent,
    /// and rewire each Harness the plan wires.
    pub(crate) fn apply(&self, paths: &Paths) -> Result<()> {
        config::set_default(paths, "default_backend", Some(self.backend.as_str()))?;
        if let Some(r) = self.refs.as_ref().filter(|r| r.create) {
            file_replace::create_new(&r.path, starter(self.backend).as_bytes(), 0o644).map_err(
                |source| Error::Io {
                    path: r.path.clone(),
                    source,
                },
            )?;
        }
        for h in &self.harnesses {
            let (Fate::Wire { add_workdir }, Some(r)) = (&h.fate, &self.refs) else {
                continue;
            };
            let mut conf = ConfFile::read(&h.conf)?;
            conf.set("backend", self.backend.as_str())?;
            conf.set("manifest", &r.manifest)?;
            if *add_workdir {
                conf.set("workdir", "caller")?;
            }
            conf.write(&h.conf)?;
        }
        Ok(())
    }

    /// The wiring report, as applied: each Harness wired or left, and why.
    pub(crate) fn report(&self) -> String {
        let mut out = format!("\nVault wiring ({}):\n", self.backend);
        if self.is_empty() {
            out.push_str("  already wired; nothing changed\n");
        }
        if self.default_was == self.backend {
            let _ = writeln!(out, "  default_backend = {}", self.backend);
        } else {
            let _ = writeln!(
                out,
                "  default_backend = {} (was {})",
                self.backend, self.default_was
            );
        }
        if let Some(r) = &self.refs {
            let verb = if r.create { "created" } else { "using" };
            let _ = writeln!(out, "  {verb} {}", r.path.display());
        }
        if self.harnesses.is_empty() {
            out.push_str("  no Harnesses to wire\n");
        }
        for h in &self.harnesses {
            let conf = format!("{}.conf", h.name);
            let line = match &h.fate {
                Fate::Wire { add_workdir } => format!(
                    "wired {conf} -> backend={} manifest={}{}",
                    self.backend,
                    self.refs.as_ref().map_or("", |r| r.manifest.as_str()),
                    if *add_workdir { " workdir=caller" } else { "" }
                ),
                Fate::Left(Left::NotDayOne { backend, manifest }) => {
                    format!("left {conf} (backend={backend} manifest={manifest}: not day-one)")
                }
                Fate::Left(Left::EnvBlind(name)) => {
                    format!("left {conf} (listed in etc/env-blind-agents as {name}: not rewired)")
                }
                Fate::Left(Left::Unreadable(err)) => format!("left {conf} (unreadable: {err})"),
                Fate::Left(Left::NotWired) => format!(
                    "left {conf} ({} needs an encrypted manifest per Harness)",
                    self.backend
                ),
            };
            let _ = writeln!(out, "  {line}");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const DAY_ONE: &str = "backend = plainfile\nmanifest = empty.env\ncommand = claude\n";

    fn config(defaults: &str, harnesses: &[(&str, &str)]) -> (tempfile::TempDir, Paths) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        fs::create_dir_all(&paths.harness_dir).unwrap();
        fs::create_dir_all(&paths.manifest_dir).unwrap();
        fs::write(&paths.defaults_file, defaults).unwrap();
        for (name, body) in harnesses {
            fs::write(paths.harness_conf(name), body).unwrap();
        }
        (tmp, paths)
    }

    fn plan_of(paths: &Paths, be: Backend) -> Plan {
        plan(paths, &Inventory::load(paths).unwrap(), be).unwrap()
    }

    fn fate_of<'p>(plan: &'p Plan, name: &str) -> &'p Fate {
        &plan.harnesses.iter().find(|h| h.name == name).unwrap().fate
    }

    #[test]
    fn a_day_one_harness_is_wired_with_workdir_caller() {
        let (_tmp, paths) = config("default_backend = plainfile\n", &[("claude", DAY_ONE)]);
        let plan = plan_of(&paths, Backend::Bitwarden);
        assert_eq!(fate_of(&plan, "claude"), &Fate::Wire { add_workdir: true });
        plan.apply(&paths).unwrap();
        let conf = fs::read_to_string(paths.harness_conf("claude")).unwrap();
        assert_eq!(
            conf,
            "backend = bitwarden\nmanifest = openai.env.refs\ncommand = claude\nworkdir = caller\n"
        );
        let defaults = fs::read_to_string(&paths.defaults_file).unwrap();
        assert!(
            defaults.contains("default_backend = bitwarden"),
            "{defaults}"
        );
    }

    #[test]
    fn an_existing_workdir_is_kept() {
        let (_tmp, paths) = config(
            "",
            &[("claude", &format!("{DAY_ONE}workdir = /srv/work\n"))],
        );
        let plan = plan_of(&paths, Backend::Pass);
        assert_eq!(fate_of(&plan, "claude"), &Fate::Wire { add_workdir: false });
        plan.apply(&paths).unwrap();
        let conf = fs::read_to_string(paths.harness_conf("claude")).unwrap();
        assert!(conf.contains("workdir = /srv/work"), "{conf}");
        assert!(!conf.contains("caller"), "{conf}");
    }

    #[test]
    fn a_harness_that_is_not_day_one_is_left_with_the_reason() {
        let (_tmp, paths) = config(
            "default_backend = plainfile\n",
            &[
                ("claude", DAY_ONE),
                (
                    "codex",
                    "backend = onepassword\nmanifest = mine.refs\ncommand = codex\n",
                ),
                ("grok", "manifest = secrets.env\ncommand = grok\n"),
            ],
        );
        let plan = plan_of(&paths, Backend::OnePassword);
        assert_eq!(
            fate_of(&plan, "codex"),
            &Fate::Left(Left::NotDayOne {
                backend: Backend::OnePassword,
                manifest: "mine.refs".into()
            })
        );
        assert_eq!(
            fate_of(&plan, "grok"),
            &Fate::Left(Left::NotDayOne {
                backend: Backend::Plainfile,
                manifest: "secrets.env".into()
            })
        );
        let report = plan.report();
        assert!(
            report
                .contains("left codex.conf (backend=onepassword manifest=mine.refs: not day-one)"),
            "{report}"
        );
    }

    #[test]
    fn an_env_blind_harness_is_left_by_command_basename_or_by_harness_name() {
        let (_tmp, paths) = config(
            "",
            &[
                (
                    "blind",
                    "backend = plainfile\nmanifest = empty.env\ncommand = /opt/bin/seer --x\n",
                ),
                (
                    "nosy",
                    "backend = plainfile\nmanifest = empty.env\ncommand = other\n",
                ),
                ("claude", DAY_ONE),
            ],
        );
        let inv = Inventory::load(&paths).unwrap();
        let plan = plan_with(&paths, &inv, Backend::Bitwarden, |n| {
            n == "seer" || n == "nosy"
        })
        .unwrap();
        assert_eq!(
            fate_of(&plan, "blind"),
            &Fate::Left(Left::EnvBlind("seer".into()))
        );
        assert_eq!(
            fate_of(&plan, "nosy"),
            &Fate::Left(Left::EnvBlind("nosy".into()))
        );
        assert_eq!(fate_of(&plan, "claude"), &Fate::Wire { add_workdir: true });
    }

    #[test]
    fn an_unreadable_harness_is_left_with_its_error() {
        let (_tmp, paths) = config("", &[("broken", "wat = 1\n"), ("claude", DAY_ONE)]);
        let inv = Inventory::load(&paths).unwrap();
        // The Refs-file choice refuses an unreadable Harness; sops makes none.
        let sops = plan(&paths, &inv, Backend::Sops).unwrap();
        assert!(
            matches!(fate_of(&sops, "broken"), Fate::Left(Left::Unreadable(_))),
            "{sops:?}"
        );
        assert!(plan(&paths, &inv, Backend::Bitwarden).is_err());
    }

    #[test]
    fn the_refs_file_existing_harnesses_use_for_the_backend_is_reused() {
        let (_tmp, paths) = config(
            "",
            &[
                ("claude", DAY_ONE),
                (
                    "codex",
                    "backend = bitwarden\nmanifest = bitwarden.refs\ncommand = codex\n",
                ),
            ],
        );
        fs::write(paths.manifest_dir.join("bitwarden.refs"), "A=name:A\n").unwrap();
        let plan = plan_of(&paths, Backend::Bitwarden);
        plan.apply(&paths).unwrap();
        let conf = fs::read_to_string(paths.harness_conf("claude")).unwrap();
        assert!(conf.contains("manifest = bitwarden.refs"), "{conf}");
        assert_eq!(
            fs::read_to_string(paths.manifest_dir.join("bitwarden.refs")).unwrap(),
            "A=name:A\n"
        );
        assert!(!paths.manifest_dir.join("openai.env.refs").exists());
    }

    #[test]
    fn the_fallback_refs_file_is_chosen_per_backend() {
        let (_tmp, paths) = config("", &[]);
        let inv = Inventory::load(&paths).unwrap();
        for (be, name) in [
            (Backend::Bitwarden, "openai.env.refs"),
            (Backend::OnePassword, "onepassword.refs"),
            (Backend::Pass, "pass.refs"),
        ] {
            assert_eq!(
                refs_file(&paths, &inv, be).unwrap(),
                Some(paths.manifest_dir.join(name))
            );
        }
        assert_eq!(refs_file(&paths, &inv, Backend::Sops).unwrap(), None);
    }

    #[test]
    fn the_starter_refs_file_is_created_once_0644_with_no_reference_shape() {
        for be in [Backend::Bitwarden, Backend::OnePassword, Backend::Pass] {
            let (_tmp, paths) = config("", &[("claude", DAY_ONE)]);
            plan_of(&paths, be).apply(&paths).unwrap();
            let path = refs_file(&paths, &Inventory::load(&paths).unwrap(), be)
                .unwrap()
                .unwrap();
            let text = fs::read_to_string(&path).unwrap();
            assert!(
                !text.contains("op://") && !text.contains("name:") && !text.contains("uuid"),
                "{text}"
            );
            assert!(text.lines().all(|l| l.starts_with('#')), "{text}");
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
                0o644
            );
            // And it passes the Manifest check for its Backend.
            crate::validate::validate_manifest_file(&path, be).unwrap();
        }
    }

    #[test]
    fn an_existing_refs_file_is_never_overwritten() {
        let (_tmp, paths) = config("", &[("claude", DAY_ONE)]);
        let path = paths.manifest_dir.join("onepassword.refs");
        fs::write(&path, "A=op://V/i/f\n").unwrap();
        let plan = plan_of(&paths, Backend::OnePassword);
        assert!(!plan.refs.as_ref().unwrap().create);
        plan.apply(&paths).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "A=op://V/i/f\n");
    }

    #[test]
    fn sops_records_the_default_backend_and_wires_no_harness() {
        let (_tmp, paths) = config("default_backend = plainfile\n", &[("claude", DAY_ONE)]);
        let plan = plan_of(&paths, Backend::Sops);
        assert_eq!(fate_of(&plan, "claude"), &Fate::Left(Left::NotWired));
        plan.apply(&paths).unwrap();
        assert_eq!(
            fs::read_to_string(paths.harness_conf("claude")).unwrap(),
            DAY_ONE
        );
        assert_eq!(fs::read_dir(&paths.manifest_dir).unwrap().count(), 0);
        let defaults = fs::read_to_string(&paths.defaults_file).unwrap();
        assert!(defaults.contains("default_backend = sops"), "{defaults}");
    }

    #[test]
    fn a_second_plan_after_apply_is_empty() {
        for be in [
            Backend::Bitwarden,
            Backend::OnePassword,
            Backend::Pass,
            Backend::Sops,
        ] {
            let (_tmp, paths) = config(
                "default_backend = plainfile\n",
                &[
                    ("claude", DAY_ONE),
                    ("codex", "manifest = empty.env\ncommand = codex\n"),
                ],
            );
            let first = plan_of(&paths, be);
            assert!(!first.is_empty());
            first.apply(&paths).unwrap();
            let second = plan_of(&paths, be);
            assert!(second.is_empty(), "{be}: {second:?}");
        }
    }
}
