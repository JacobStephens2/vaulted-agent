//! Every Harness and Extra manifest this machine's config declares.
//!
//! The one walk that `secrets validate`, `secrets which`, `refresh`,
//! `edit-manifest`, `pick` and `update` share. Each entry carries its effective
//! Backend and resolved Manifest path, or the error that stopped it loading.
//! Load errors are data: each query below states its own policy for them,
//! rather than each caller hiding one in a `?` or a `let Ok(..) else`.
//!
//! Launch reads a single Harness by name and does not use this (story #44).

use std::path::{Path, PathBuf};

use crate::config::{self, Backend, ExtraManifest, Harness, Paths};
use crate::error::{Error, Result};

/// A Harness that loaded, bound to what it would launch with.
#[derive(Debug)]
pub struct HarnessView {
    pub harness: Harness,
    /// The Harness's `backend =`, else the machine default.
    pub backend: Backend,
    /// The `manifest =` line under [`Paths::resolve_manifest`].
    pub manifest: PathBuf,
}

/// One `harnesses.d/*.conf`, loaded or not.
#[derive(Debug)]
pub struct HarnessEntry {
    pub name: String,
    /// The `.conf` file, named when it will not load.
    pub conf: PathBuf,
    pub loaded: Result<HarnessView>,
}

/// An Extra manifest that parsed, bound to what it is checked against.
#[derive(Debug)]
pub struct ExtraView {
    /// The line's `= <backend>`, else the machine default.
    pub backend: Backend,
    pub manifest: PathBuf,
}

/// One `extra_manifest =` value from defaults.conf, parsed or not.
#[derive(Debug)]
pub struct ExtraEntry {
    /// The value as written, named when it will not parse.
    pub value: String,
    pub loaded: Result<ExtraView>,
}

/// One line of `secrets validate` with no target.
pub struct ValidateTarget<'a> {
    pub label: String,
    /// What to check, or why there is nothing to check (a `FAIL` line).
    pub check: std::result::Result<(Backend, &'a Path), &'a Error>,
}

#[derive(Debug)]
pub struct Inventory {
    harnesses: Vec<HarnessEntry>,
    extras: Vec<ExtraEntry>,
}

impl Inventory {
    /// Fails only when the harness directory cannot be read. An unloadable
    /// `.conf` or `extra_manifest` line is held as an entry.
    pub fn load(paths: &Paths) -> Result<Self> {
        // Read once, so every query gives the same answer.
        let default_backend = config::load_default_backend(paths);
        let harnesses = config::list_harness_names(paths)?
            .into_iter()
            .map(|name| {
                let loaded = Harness::load(paths, &name).map(|harness| HarnessView {
                    backend: harness.backend.unwrap_or(default_backend),
                    manifest: harness.resolve_manifest_path(paths),
                    harness,
                });
                HarnessEntry {
                    conf: paths.harness_dir.join(format!("{name}.conf")),
                    name,
                    loaded,
                }
            })
            .collect();
        let extras = config::load_defaults_all(paths, "extra_manifest")
            .into_iter()
            .map(|value| {
                let loaded = ExtraManifest::parse(&value, paths).map(|extra| ExtraView {
                    backend: extra.backend.unwrap_or(default_backend),
                    manifest: extra.path,
                });
                ExtraEntry { value, loaded }
            })
            .collect();
        Ok(Self { harnesses, extras })
    }

    /// Every Harness, in name order, loaded or not.
    pub fn harnesses(&self) -> &[HarnessEntry] {
        &self.harnesses
    }

    /// The Harnesses that loaded. For callers whose policy is to skip the rest.
    pub fn loaded(&self) -> impl Iterator<Item = &HarnessView> {
        self.harnesses.iter().filter_map(|e| e.loaded.as_ref().ok())
    }

    /// Everything `secrets validate` checks: each Harness, then each Extra
    /// manifest. One that will not load is a target of its own whose check is
    /// the load error, so it fails closed without hiding the others.
    pub fn validate_targets(&self) -> Vec<ValidateTarget<'_>> {
        let harnesses = self.harnesses.iter().map(|e| match &e.loaded {
            // The manifest is named on every line because several harnesses
            // commonly share one file: six green harnesses can be one file
            // checked six times, and the operator cannot see which files were
            // covered otherwise.
            Ok(v) => ValidateTarget {
                label: format!("{} ({})", e.name, v.manifest.display()),
                check: Ok((v.backend, &v.manifest)),
            },
            Err(err) => ValidateTarget {
                label: format!("{} ({})", e.name, e.conf.display()),
                check: Err(err),
            },
        });
        let extras = self.extras.iter().map(|e| match &e.loaded {
            Ok(v) => ValidateTarget {
                label: v.manifest.display().to_string(),
                check: Ok((v.backend, &v.manifest)),
            },
            Err(err) => ValidateTarget {
                label: format!("extra_manifest = {}", e.value),
                check: Err(err),
            },
        });
        harnesses.chain(extras).collect()
    }

    /// The one Manifest the Harnesses on `backend` use: `None` when no Harness
    /// is on it. Refuses when several Manifests are, and when any Harness will
    /// not load, since that one's Backend is unknown.
    pub fn manifest_for(&self, backend: Backend) -> Result<Option<PathBuf>> {
        let mut candidates: Vec<&Path> = Vec::new();
        for e in &self.harnesses {
            let v = e
                .loaded
                .as_ref()
                .map_err(|err| Error::Message(err.to_string()))?;
            if v.backend == backend {
                candidates.push(&v.manifest);
            }
        }
        candidates.sort();
        candidates.dedup();
        match candidates.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(one.to_path_buf())),
            many => Err(Error::Message(format!(
                "multiple {} manifests ({}); pass one explicitly: vaulted-agent refresh <file>",
                backend.as_str(),
                many.iter()
                    .map(|p| p
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("?")
                        .to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    }

    /// Backend for a bare `refresh`: whichever refs-using Backend the loaded
    /// Harnesses are on.
    ///
    /// Falls back to Bitwarden, NOT to the machine default, when there is no
    /// positive signal. `refresh` meant Bitwarden for its whole history, while
    /// the machine default is OnePassword when nothing is configured - so
    /// deferring to it here would silently retarget `refresh` on installs that
    /// have no harnesses and no defaults.conf. Ties break the same way.
    pub fn refresh_backend(&self) -> Backend {
        let mut seen: Vec<Backend> = Vec::new();
        for v in self.loaded() {
            if matches!(v.backend, Backend::Bitwarden | Backend::OnePassword)
                && !seen.contains(&v.backend)
            {
                seen.push(v.backend);
            }
        }
        match seen.as_slice() {
            [one] => *one,
            _ => Backend::Bitwarden,
        }
    }

    /// `(harness, target, source)` for each loaded Harness `alias =` whose
    /// source is one of `vars`.
    pub fn aliases_reading<'a>(&'a self, vars: &[&str]) -> Vec<(&'a str, &'a str, &'a str)> {
        let mut out = Vec::new();
        for v in self.loaded() {
            for (target, source) in &v.harness.aliases {
                if vars.contains(&source.as_str()) {
                    out.push((v.harness.name.as_str(), target.as_str(), source.as_str()));
                }
            }
        }
        out
    }

    /// Names of the loaded Harnesses whose Manifest resolves to `manifest`.
    pub fn harnesses_using(&self, manifest: &Path) -> Vec<&str> {
        self.loaded()
            .filter(|v| v.manifest == manifest)
            .map(|v| v.harness.name.as_str())
            .collect()
    }

    /// The Backend and `manifest =` text every Harness shares, for a new
    /// Harness to copy. Manifests compare by resolved path; the text is the
    /// first Harness's, so the operator's spelling is kept.
    ///
    /// `Ok(None)` when there are no Harnesses or they disagree; `Err(name)`
    /// naming a Harness that will not load, since it might disagree.
    pub fn shared_binding(&self) -> std::result::Result<Option<(Backend, &str)>, &str> {
        let mut shared: Option<&HarnessView> = None;
        for e in &self.harnesses {
            let Ok(v) = &e.loaded else {
                return Err(&e.name);
            };
            match shared {
                Some(first) if (first.backend, &first.manifest) != (v.backend, &v.manifest) => {
                    return Ok(None);
                }
                Some(_) => {}
                None => shared = Some(v),
            }
        }
        Ok(shared.map(|v| (v.backend, v.harness.manifest.as_str())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn config(defaults: &str, harnesses: &[(&str, &str)]) -> (tempfile::TempDir, Paths) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        fs::create_dir_all(&paths.harness_dir).unwrap();
        fs::write(&paths.defaults_file, defaults).unwrap();
        for (name, body) in harnesses {
            fs::write(paths.harness_dir.join(format!("{name}.conf")), body).unwrap();
        }
        (tmp, paths)
    }

    #[test]
    fn two_harnesses_on_one_manifest_give_one_manifest_for_that_backend() {
        let (_tmp, paths) = config(
            "default_backend = bitwarden\n",
            &[
                ("claude", "manifest = shared.env\ncommand = claude\n"),
                ("codex", "manifest = shared.env\ncommand = codex\n"),
            ],
        );
        let inv = Inventory::load(&paths).unwrap();
        assert_eq!(
            inv.manifest_for(Backend::Bitwarden).unwrap(),
            Some(paths.manifest_dir.join("shared.env"))
        );
        assert_eq!(inv.manifest_for(Backend::OnePassword).unwrap(), None);
    }

    #[test]
    fn several_manifests_on_one_backend_are_refused() {
        let (_tmp, paths) = config(
            "default_backend = bitwarden\n",
            &[
                ("claude", "manifest = a.env\ncommand = claude\n"),
                ("codex", "manifest = b.env\ncommand = codex\n"),
            ],
        );
        let err = Inventory::load(&paths)
            .unwrap()
            .manifest_for(Backend::Bitwarden)
            .unwrap_err();
        assert!(err.to_string().contains("a.env, b.env"), "{err}");
    }

    #[test]
    fn an_unloadable_harness_refuses_the_manifest_for_a_backend() {
        let (_tmp, paths) = config(
            "default_backend = bitwarden\n",
            &[
                ("claude", "manifest = a.env\ncommand = claude\n"),
                ("broken", "wat = 1\n"),
            ],
        );
        let inv = Inventory::load(&paths).unwrap();
        assert!(inv.manifest_for(Backend::Bitwarden).is_err());
    }

    #[test]
    fn harnesses_on_both_vault_backends_make_refresh_default_to_bitwarden() {
        let (_tmp, paths) = config(
            "default_backend = onepassword\n",
            &[
                ("claude", "manifest = a.env\ncommand = claude\n"),
                (
                    "codex",
                    "backend = bitwarden\nmanifest = b.env\ncommand = codex\n",
                ),
            ],
        );
        assert_eq!(
            Inventory::load(&paths).unwrap().refresh_backend(),
            Backend::Bitwarden
        );
    }

    #[test]
    fn refresh_follows_the_one_vault_backend_in_use_and_skips_unloadable_harnesses() {
        let (_tmp, paths) = config(
            "default_backend = onepassword\n",
            &[
                ("claude", "manifest = a.env\ncommand = claude\n"),
                ("broken", "backend = bitwarden\nwat = 1\n"),
            ],
        );
        assert_eq!(
            Inventory::load(&paths).unwrap().refresh_backend(),
            Backend::OnePassword
        );
    }

    #[test]
    fn an_absolute_manifest_is_found_by_its_resolved_path() {
        let (_tmp, paths) = config("", &[]);
        let abs = paths.manifest_dir.join("x.env");
        fs::write(
            paths.harness_dir.join("claude.conf"),
            format!("manifest = {}\ncommand = claude\n", abs.display()),
        )
        .unwrap();
        fs::write(
            paths.harness_dir.join("codex.conf"),
            "manifest = x.env\ncommand = codex\n",
        )
        .unwrap();
        let inv = Inventory::load(&paths).unwrap();
        assert_eq!(inv.harnesses_using(&abs), vec!["claude", "codex"]);
        assert!(inv
            .harnesses_using(&paths.manifest_dir.join("y.env"))
            .is_empty());
    }

    #[test]
    fn a_malformed_conf_is_an_error_target_alongside_the_healthy_ones() {
        let (_tmp, paths) = config(
            "default_backend = plainfile\n",
            &[
                ("broken", "manifest = a.env\nwat = 1\ncommand = x\n"),
                ("claude", "manifest = a.env\ncommand = claude\n"),
            ],
        );
        let inv = Inventory::load(&paths).unwrap();
        let targets = inv.validate_targets();
        assert_eq!(targets.len(), 2);
        assert!(
            targets[0].label.contains("broken.conf"),
            "{}",
            targets[0].label
        );
        assert!(targets[0].check.is_err());
        let (be, path) = targets[1].check.as_ref().unwrap();
        assert_eq!(*be, Backend::Plainfile);
        assert_eq!(*path, paths.manifest_dir.join("a.env"));
    }

    #[test]
    fn extra_manifests_follow_the_harnesses_and_an_unreadable_line_is_an_error_target() {
        let (_tmp, paths) = config(
            "default_backend = onepassword\n\
             extra_manifest = /srv/orchestration/env.tpl\n\
             extra_manifest = /x = nosuch\n\
             extra_manifest = other.env = plainfile\n",
            &[("claude", "manifest = a.env\ncommand = claude\n")],
        );
        let inv = Inventory::load(&paths).unwrap();
        let targets = inv.validate_targets();
        assert_eq!(targets.len(), 4);
        assert_eq!(
            targets[1].check.as_ref().unwrap(),
            &(
                Backend::OnePassword,
                Path::new("/srv/orchestration/env.tpl")
            )
        );
        assert!(targets[2].check.is_err());
        assert!(
            targets[2].label.contains("/x = nosuch"),
            "{}",
            targets[2].label
        );
        let other = paths.manifest_dir.join("other.env");
        assert_eq!(
            targets[3].check.as_ref().unwrap(),
            &(Backend::Plainfile, other.as_path())
        );
    }

    #[test]
    fn relative_and_absolute_naming_of_one_file_is_a_shared_binding() {
        let (_tmp, paths) = config("default_backend = bitwarden\n", &[]);
        let abs = paths.manifest_dir.join("shared.env");
        fs::write(
            paths.harness_dir.join("claude.conf"),
            "manifest = shared.env\ncommand = claude\n",
        )
        .unwrap();
        fs::write(
            paths.harness_dir.join("codex.conf"),
            format!(
                "backend = bitwarden\nmanifest = {}\ncommand = codex\n",
                abs.display()
            ),
        )
        .unwrap();
        assert_eq!(
            Inventory::load(&paths).unwrap().shared_binding(),
            Ok(Some((Backend::Bitwarden, "shared.env")))
        );
    }

    #[test]
    fn harnesses_on_different_manifests_share_no_binding() {
        let (_tmp, paths) = config(
            "",
            &[
                ("claude", "manifest = a.env\ncommand = claude\n"),
                ("codex", "manifest = b.env\ncommand = codex\n"),
            ],
        );
        assert_eq!(Inventory::load(&paths).unwrap().shared_binding(), Ok(None));
    }

    #[test]
    fn an_unloadable_harness_gives_up_on_the_shared_binding() {
        let (_tmp, paths) = config(
            "",
            &[
                ("broken", "wat = 1\n"),
                ("claude", "manifest = a.env\ncommand = claude\n"),
            ],
        );
        assert_eq!(
            Inventory::load(&paths).unwrap().shared_binding(),
            Err("broken")
        );
    }

    #[test]
    fn aliases_reading_names_the_harness_target_and_source() {
        let (_tmp, paths) = config(
            "",
            &[(
                "kimi",
                "manifest = a.env\nalias = OPENAI_API_KEY = FW_KEY\ncommand = kimi\n",
            )],
        );
        let inv = Inventory::load(&paths).unwrap();
        assert_eq!(
            inv.aliases_reading(&["FW_KEY"]),
            vec![("kimi", "OPENAI_API_KEY", "FW_KEY")]
        );
        assert!(inv.aliases_reading(&["OTHER"]).is_empty());
    }

    #[test]
    fn no_harness_directory_is_an_empty_inventory() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        let inv = Inventory::load(&paths).unwrap();
        assert!(inv.harnesses().is_empty());
        assert!(inv.validate_targets().is_empty());
    }
}
