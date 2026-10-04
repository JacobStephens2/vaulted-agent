//! Workdir: where a Harness's agent starts, and whether the launching account
//! can enter it.
//!
//! Launch, `doctor` and `setup` used to answer this each in their own way, and
//! the copies drifted: the doctor called an unset `workdir` under a Service
//! user healthy while the launch died at exec (issue #128). The setting rules,
//! the traversal probe and the remedy wording now live only here.
//!
//! The setting: unset, empty or `caller` is the Caller cwd; anything else is a
//! fixed path with a leading `$HOME` / `${HOME}` expanded.

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::expand_home;
use crate::error::{Error, Result};
use crate::privilege;

/// What the module needs to know about the invocation, read from the
/// environment once by the caller and passed in.
#[derive(Debug, Clone, Default)]
pub(crate) struct CallerContext {
    /// The Caller cwd: `VAULTED_AGENT_CALLER_CWD`, else the process cwd.
    pub cwd: Option<PathBuf>,
    /// `HOME` of this process, for `$HOME` in a fixed workdir.
    pub home: String,
    /// The operator's home when `SUDO_USER` names an account: after a hop to
    /// the Service user it is the usual 0700 directory a launch cannot enter.
    pub operator_home: Option<PathBuf>,
}

impl CallerContext {
    pub(crate) fn from_env() -> Self {
        let cwd = match env::var_os("VAULTED_AGENT_CALLER_CWD") {
            Some(c) if !c.is_empty() => Some(PathBuf::from(c)),
            _ => env::current_dir().ok(),
        };
        let operator_home = env::var("SUDO_USER")
            .ok()
            .filter(|u| !u.is_empty())
            .and_then(|u| privilege::account_home(&u));
        Self {
            cwd,
            home: env::var("HOME").unwrap_or_default(),
            operator_home,
        }
    }
}

/// A harness's `workdir =` value, interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Setting<'a> {
    /// `caller`, empty or unset: start in the Caller cwd.
    Caller,
    /// A fixed directory, as written in the harness conf.
    Fixed(&'a str),
}

impl<'a> Setting<'a> {
    pub(crate) fn interpret(raw: Option<&'a str>) -> Self {
        match raw {
            None | Some("") | Some("caller") => Setting::Caller,
            Some(p) => Setting::Fixed(p),
        }
    }

    /// The directory a launch starts in, or `None` for `caller` when the
    /// Caller cwd is unknown.
    pub(crate) fn resolve(self, ctx: &CallerContext) -> Option<PathBuf> {
        match self {
            Setting::Caller => ctx.cwd.clone(),
            Setting::Fixed(p) => Some(PathBuf::from(expand_home(p, &ctx.home))),
        }
    }
}

/// The remedy for an account that cannot enter `path`: the traverse-only ACL,
/// or one of the two ways around it. Multi-line; callers indent the first line.
pub(crate) fn remedy(service_user: &str, path: &Path) -> String {
    format!(
        "Fix one of:\n    \
         setfacl -m u:{service_user}:x {}   # traverse only — does not allow listing\n    \
         launch from a directory {service_user} can enter\n    \
         set an absolute `workdir` in the harness conf",
        path.display()
    )
}

/// Setup's note after choosing `workdir = caller` under a Service user.
pub(crate) fn setup_note(service_user: &str, ctx: &CallerContext) -> String {
    let home = ctx
        .operator_home
        .clone()
        .or_else(|| (!ctx.home.is_empty()).then(|| PathBuf::from(&ctx.home)))
        .unwrap_or_else(|| PathBuf::from("~"));
    format!(
        "NOTE: service_user={service_user} with workdir=caller needs {service_user} to traverse \
         your cwd. If launches fail at exec from a 0700 home:\n  {}",
        remedy(service_user, &home)
    )
}

/// Launch preflight: the directory to start in, once it is known to exist, to
/// be a directory and to be enterable by this process (which, after any hop,
/// is the launching account). Bare exec EACCES names neither the directory,
/// the account, nor the remedy (issue #56).
pub(crate) fn preflight(
    raw: Option<&str>,
    ctx: &CallerContext,
    service_user: Option<&str>,
) -> Result<PathBuf> {
    preflight_with(
        raw,
        ctx,
        service_user,
        &privilege::current_user(),
        &is_traversable,
    )
}

/// Doctor audit: probe the paths a launch is likely to use and return at most
/// one warning. Runs only under a Service user: without one the launch account
/// is the operator, who is already standing in the cwd.
pub(crate) fn audit(
    raw: Option<&str>,
    ctx: &CallerContext,
    service_user: Option<&str>,
) -> Option<String> {
    audit_with(raw, ctx, service_user, &is_traversable)
}

fn preflight_with(
    raw: Option<&str>,
    ctx: &CallerContext,
    service_user: Option<&str>,
    who: &str,
    can_enter: &dyn Fn(&Path) -> bool,
) -> Result<PathBuf> {
    let setting = Setting::interpret(raw);
    let workdir = setting
        .resolve(ctx)
        .ok_or_else(|| Error::Message("cwd: cannot determine the caller's directory".into()))?;
    match fs::metadata(&workdir) {
        Ok(m) if !m.is_dir() => {
            return Err(Error::Message(format!(
                "workdir {} is not a directory",
                workdir.display()
            )));
        }
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(Error::Message(format!(
                "workdir {} does not exist",
                workdir.display()
            )));
        }
        // Cannot even stat it: fall through to the traversal verdict.
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {}
        Err(e) => {
            return Err(Error::Message(format!(
                "workdir {}: {e}",
                workdir.display()
            )));
        }
    }

    if can_enter(&workdir) {
        return Ok(workdir);
    }

    let who = if who.is_empty() {
        "this process".to_string()
    } else {
        format!("`{who}`")
    };
    let mut msg = format!(
        "{who} cannot enter {} (Permission denied)",
        workdir.display()
    );
    match setting {
        Setting::Caller => {
            msg.push_str("\n  workdir resolved to your shell's cwd (workdir = caller)")
        }
        Setting::Fixed(p) => msg.push_str(&format!("\n  workdir is set to `{p}` in the harness")),
    }
    match service_user.filter(|s| !s.is_empty()) {
        Some(svc) => msg.push_str(&format!(
            ", but agents run as `{svc}` (service_user), which has no traverse permission there.\n  {}",
            remedy(svc, &workdir)
        )),
        None => msg.push_str(
            ".\n  Fix: grant this account execute (traverse) on the directory, or set an absolute \
             `workdir` the account can enter.",
        ),
    }
    Err(Error::Message(msg))
}

fn audit_with(
    raw: Option<&str>,
    ctx: &CallerContext,
    service_user: Option<&str>,
    can_enter: &dyn Fn(&Path) -> bool,
) -> Option<String> {
    let svc = service_user.filter(|s| !s.is_empty())?;
    let failed: Vec<PathBuf> = audit_paths(raw, ctx)
        .into_iter()
        .filter(|p| !can_enter(p))
        .collect();
    let first = failed.first()?;
    let paths = failed
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let shown = match (raw, Setting::interpret(raw)) {
        (None | Some(""), _) => "workdir unset (same as caller)".to_string(),
        (_, Setting::Caller) => "workdir=caller".to_string(),
        (_, Setting::Fixed(p)) => format!("workdir={p}"),
    };
    Some(format!(
        "{shown} with service_user={svc}, and {svc} cannot enter {paths} (Permission denied). \
         Launching fails at exec.\n  {}",
        remedy(svc, first)
    ))
}

/// The paths the doctor probes: for `caller`, the Caller cwd plus the
/// operator's home; for a fixed workdir, the resolved path.
fn audit_paths(raw: Option<&str>, ctx: &CallerContext) -> Vec<PathBuf> {
    let setting = Setting::interpret(raw);
    let mut out: Vec<PathBuf> = setting.resolve(ctx).into_iter().collect();
    if setting == Setting::Caller {
        if let Some(home) = &ctx.operator_home {
            if !out.contains(home) {
                out.push(home.clone());
            }
        }
    }
    out
}

/// True when this process can search (traverse) `path` — execute bit / ACL,
/// not necessarily list. `open()` would demand read permission and
/// false-negative a `setfacl …:x` fix (issue #56).
#[cfg(unix)]
fn is_traversable(path: &Path) -> bool {
    // `test -x` follows the same search rules as path resolution.
    Command::new("test")
        .arg("-x")
        .arg(path)
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(not(unix))]
fn is_traversable(path: &Path) -> bool {
    fs::metadata(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(cwd: &Path) -> CallerContext {
        CallerContext {
            cwd: Some(cwd.to_path_buf()),
            home: "/home/op".into(),
            operator_home: None,
        }
    }

    fn allow(_: &Path) -> bool {
        true
    }

    fn deny(_: &Path) -> bool {
        false
    }

    #[test]
    fn unset_empty_and_caller_all_mean_the_caller_cwd() {
        let c = ctx(Path::new("/work/proj"));
        for raw in [None, Some(""), Some("caller")] {
            assert_eq!(Setting::interpret(raw), Setting::Caller, "{raw:?}");
            assert_eq!(
                Setting::interpret(raw).resolve(&c),
                Some(PathBuf::from("/work/proj")),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn a_fixed_workdir_expands_a_leading_home() {
        let c = ctx(Path::new("/work/proj"));
        let resolve = |raw| Setting::interpret(Some(raw)).resolve(&c).unwrap();
        assert_eq!(resolve("/srv/agents"), PathBuf::from("/srv/agents"));
        assert_eq!(resolve("$HOME/code"), PathBuf::from("/home/op/code"));
        assert_eq!(resolve("${HOME}/code"), PathBuf::from("/home/op/code"));
    }

    #[test]
    fn caller_without_a_known_cwd_resolves_to_nothing() {
        let c = CallerContext::default();
        assert_eq!(Setting::Caller.resolve(&c), None);
        assert!(preflight_with(None, &c, None, "op", &allow).is_err());
    }

    #[test]
    fn preflight_returns_an_enterable_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let c = ctx(tmp.path());
        assert_eq!(
            preflight_with(None, &c, None, "op", &allow).unwrap(),
            tmp.path()
        );
        let fixed = tmp.path().to_str().unwrap();
        assert_eq!(
            preflight_with(Some(fixed), &c, Some("conductor"), "conductor", &allow).unwrap(),
            tmp.path()
        );
    }

    #[test]
    fn preflight_reports_a_missing_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope");
        let err = preflight_with(
            Some(missing.to_str().unwrap()),
            &ctx(tmp.path()),
            None,
            "op",
            &allow,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn preflight_reports_a_path_that_is_not_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("file");
        fs::write(&file, "").unwrap();
        let err = preflight_with(None, &ctx(&file), None, "op", &allow).unwrap_err();
        assert!(err.to_string().contains("is not a directory"), "{err}");
    }

    #[test]
    fn preflight_names_the_service_user_and_the_acl_fix_when_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let msg = preflight_with(
            None,
            &ctx(tmp.path()),
            Some("conductor"),
            "conductor",
            &deny,
        )
        .unwrap_err()
        .to_string();
        assert!(msg.contains("`conductor` cannot enter"), "{msg}");
        assert!(msg.contains(&tmp.path().display().to_string()), "{msg}");
        assert!(msg.contains("workdir = caller"), "{msg}");
        assert!(
            msg.contains(&format!(
                "setfacl -m u:conductor:x {}",
                tmp.path().display()
            )),
            "{msg}"
        );
    }

    #[test]
    fn preflight_without_a_service_user_offers_no_acl_for_another_account() {
        let tmp = tempfile::tempdir().unwrap();
        let fixed = tmp.path().to_str().unwrap();
        let msg = preflight_with(Some(fixed), &ctx(tmp.path()), None, "", &deny)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("this process cannot enter"), "{msg}");
        assert!(
            msg.contains(&format!("workdir is set to `{fixed}`")),
            "{msg}"
        );
        assert!(!msg.contains("setfacl"), "{msg}");
        assert!(msg.contains("grant this account execute"), "{msg}");
    }

    #[test]
    fn audit_probes_the_caller_cwd_and_the_operator_home_for_caller() {
        let c = CallerContext {
            cwd: Some("/home/op/proj".into()),
            home: "/var/lib/conductor".into(),
            operator_home: Some("/home/op".into()),
        };
        for raw in [None, Some(""), Some("caller")] {
            assert_eq!(
                audit_paths(raw, &c),
                vec![PathBuf::from("/home/op/proj"), PathBuf::from("/home/op")],
                "{raw:?}"
            );
        }
        let same = CallerContext {
            cwd: Some("/home/op".into()),
            ..c.clone()
        };
        assert_eq!(audit_paths(None, &same), vec![PathBuf::from("/home/op")]);
    }

    #[test]
    fn audit_probes_only_the_resolved_path_for_a_fixed_workdir() {
        let c = CallerContext {
            cwd: Some("/home/op/proj".into()),
            home: "/var/lib/conductor".into(),
            operator_home: Some("/home/op".into()),
        };
        assert_eq!(
            audit_paths(Some("$HOME/work"), &c),
            vec![PathBuf::from("/var/lib/conductor/work")]
        );
    }

    #[test]
    fn audit_warns_on_an_unset_workdir_the_service_user_cannot_enter() {
        let c = ctx(Path::new("/home/op/proj"));
        let w = audit_with(None, &c, Some("conductor"), &deny).expect("must warn");
        assert!(w.contains("workdir unset"), "{w}");
        assert!(w.contains("conductor cannot enter /home/op/proj"), "{w}");
        assert!(w.contains("setfacl -m u:conductor:x /home/op/proj"), "{w}");
    }

    #[test]
    fn audit_names_every_failed_path_and_fixes_the_first() {
        let c = CallerContext {
            cwd: Some("/home/op/proj".into()),
            home: String::new(),
            operator_home: Some("/home/op".into()),
        };
        let w = audit_with(Some("caller"), &c, Some("conductor"), &|p: &Path| {
            p == Path::new("/home/op/proj")
        })
        .expect("home is blocked");
        assert!(w.contains("workdir=caller"), "{w}");
        assert!(w.contains("cannot enter /home/op "), "{w}");
        assert!(w.contains("setfacl -m u:conductor:x /home/op "), "{w}");

        let w = audit_with(Some("caller"), &c, Some("conductor"), &deny).unwrap();
        assert!(w.contains("cannot enter /home/op/proj, /home/op"), "{w}");
        assert!(w.contains("setfacl -m u:conductor:x /home/op/proj "), "{w}");
    }

    #[test]
    fn audit_warns_on_a_fixed_workdir_the_service_user_cannot_enter() {
        let c = ctx(Path::new("/home/op/proj"));
        let w = audit_with(Some("/srv/x"), &c, Some("conductor"), &deny).unwrap();
        assert!(w.contains("workdir=/srv/x"), "{w}");
        assert!(w.contains("setfacl -m u:conductor:x /srv/x"), "{w}");
    }

    #[test]
    fn audit_is_silent_when_every_path_is_enterable() {
        let c = ctx(Path::new("/home/op/proj"));
        assert_eq!(audit_with(None, &c, Some("conductor"), &allow), None);
        assert_eq!(
            audit_with(Some("/srv/x"), &c, Some("conductor"), &allow),
            None
        );
    }

    #[test]
    fn audit_runs_only_under_a_service_user() {
        let c = ctx(Path::new("/home/op/proj"));
        assert_eq!(audit_with(None, &c, None, &deny), None);
        assert_eq!(audit_with(None, &c, Some(""), &deny), None);
    }

    #[test]
    fn launch_doctor_and_setup_share_one_remedy() {
        let tmp = tempfile::tempdir().unwrap();
        let fix = remedy("conductor", tmp.path());
        let launch = preflight_with(None, &ctx(tmp.path()), Some("conductor"), "c", &deny)
            .unwrap_err()
            .to_string();
        let doctor = audit_with(None, &ctx(tmp.path()), Some("conductor"), &deny).unwrap();
        assert!(launch.contains(&fix), "{launch}");
        assert!(doctor.contains(&fix), "{doctor}");

        let c = CallerContext {
            operator_home: Some(tmp.path().to_path_buf()),
            ..ctx(Path::new("/elsewhere"))
        };
        assert!(setup_note("conductor", &c).contains(&fix));
    }
}
