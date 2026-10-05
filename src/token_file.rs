//! The Manager-token file (`bws.env` / `op.env`): read, judged and written in
//! one place.
//!
//! The launch's file route, Token capture and `doctor` all ask the same
//! question of the file `auth_mode = file` reads, and each used to answer it
//! for itself. On an empty value or a line that does not parse they disagreed,
//! and two of them told the operator the wrong thing (issue #160). Now each
//! asks [`probe`], which reads the file once and returns one verdict, with the
//! token when there is one.
//!
//! The pure planners compare a copyable [`State`], projected from the probe
//! here so the projection is decided once. The invariant-6 explanation for an
//! unreadable file and the message for a malformed one are rendered here too;
//! callers add only their own last line. Token capture is the only writer,
//! through [`write`].

use std::fmt::Display;
use std::fs;
use std::io::{self, Read as _};
use std::path::Path;

use crate::auth::TokenKind;
use crate::config::Paths;
use crate::defaults::Defaults;
use crate::error::{Error, Result};
use crate::file_replace::{self, Perms};
use crate::manifest_entry::{self, Fault};
use crate::privilege;
use crate::secret::ManagerToken;

/// What one read of a Manager-token file found, for one key.
#[derive(Debug)]
pub(crate) enum Probe {
    /// The file carries a non-empty value for the key.
    Token(ManagerToken),
    /// The file parses but has no value for the key, or an empty one. An empty
    /// token never authenticates, so it is no token.
    NoValue,
    /// Absent, or not a regular file.
    Missing,
    /// The file is there but a line does not parse. The fault names the line.
    Malformed(Fault),
    /// The file is there but this process cannot read it (invariant 6).
    Unreadable(io::Error),
}

/// The probe as the pure planners compare it: no IO error, no token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    /// Readable and carries a value for this key.
    Present,
    /// Absent, or readable but carrying no value for this key.
    Missing,
    /// There, but a line does not parse.
    Malformed,
    /// There, but cannot be read (invariant 6).
    Unreadable,
}

impl Probe {
    /// The comparable state. "Holds no value" is missing to everyone but
    /// `doctor`, which reads the probe itself.
    pub(crate) fn state(&self) -> State {
        match self {
            Self::Token(_) => State::Present,
            Self::NoValue | Self::Missing => State::Missing,
            Self::Malformed(_) => State::Malformed,
            Self::Unreadable(_) => State::Unreadable,
        }
    }
}

/// Read the token file at `path` once and judge it for `key`.
///
/// Permission errors are never collapsed into absence: `Path::is_file()` used
/// to make an EACCES file look missing (issue #51).
pub(crate) fn probe(path: &Path, key: &str) -> Probe {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Probe::Missing,
        Err(e) => return Probe::Unreadable(e),
    };
    match file.metadata() {
        Ok(m) if !m.is_file() => return Probe::Missing,
        Ok(_) => {}
        Err(e) => return Probe::Unreadable(e),
    }
    let mut text = String::new();
    if let Err(e) = file.read_to_string(&mut text) {
        return Probe::Unreadable(e);
    }
    // The shared dotenv rules (quotes stripped), as manifests are read.
    let parsed = manifest_entry::parse(&text);
    if let Some(fault) = parsed.faults.into_iter().next() {
        return Probe::Malformed(fault);
    }
    match parsed.entries.into_iter().find(|e| e.var == key) {
        Some(entry) if !entry.value.is_empty() => Probe::Token(ManagerToken::new(entry.value)),
        _ => Probe::NoValue,
    }
}

/// Who is reading a token file, for the invariant-6 explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reader {
    /// The effective user; empty when it cannot be named.
    pub user: String,
    /// The configured Service user, or why `defaults.conf` did not load.
    pub service_user: std::result::Result<Option<String>, String>,
}

impl Reader {
    pub(crate) fn from_runtime(paths: &Paths) -> Self {
        Self {
            user: privilege::current_user(),
            service_user: Defaults::load(paths)
                .map(|d| d.service_user)
                .map_err(|e| e.to_string()),
        }
    }
}

/// Why `path` cannot be read and what to do about it: who is reading, and
/// whether a Service user hop should have happened. `source` is the IO error.
/// The one rendering of invariant 6; callers append only their own last line.
pub(crate) fn explain_unreadable(
    path: impl Display,
    source: impl Display,
    reader: &Reader,
) -> String {
    let who = if reader.user.is_empty() {
        "this process".to_string()
    } else {
        format!("`{}`", reader.user)
    };
    let mut msg = format!(
        "{path} exists but cannot be read as {who} ({source})\n  \
         Token files are often root:<service_user> mode 0640 so only that account can read them."
    );
    match &reader.service_user {
        Err(e) => msg.push_str(&format!("\n  defaults.conf did not load: {e}")),
        Ok(None) => msg.push_str(
            "\n  no service_user set in defaults.conf — the launcher never re-execs as the \
             account that can read this file.\n  \
             Fix: set `service_user = <account>` in defaults.conf, or grant this user group read.",
        ),
        Ok(Some(svc)) if *svc == reader.user => msg.push_str(&format!(
            "\n  This is service_user={svc}, so the file's owner or mode is wrong: fix it, then \
             re-run."
        )),
        Ok(Some(svc)) => msg.push_str(&format!(
            "\n  service_user={svc} is configured; if this process is not that account, the \
             privilege hop did not run (check sudoers / VAULTED_AGENT_NO_REEXEC)."
        )),
    }
    msg
}

/// A token file whose line `fault` does not parse, and the one fix: rewrite it
/// through the rotation door, which verifies the new token first.
pub(crate) fn explain_malformed(
    path: impl Display,
    fault: impl Display,
    kind: TokenKind,
) -> String {
    format!(
        "{path} is malformed ({fault}), so it holds no usable {}\n  \
         rewrite it:  printf %s \"$TOKEN\" | sudo vaulted-agent setup {} --set-token",
        kind.env_var(),
        kind.backend_name()
    )
}

/// The group a Manager-token file written now should carry, as a gid. Pure:
/// `gid_of` resolves an account's primary group (`None` for unknown).
///
/// Only root changes a file's group. The Service user wins, so the service
/// account can read the file after the sudo re-exec (stories #11, #40); an
/// unknown Service user means no change, never a fallback to the invoking
/// account. With no Service user the launch account is the invoking account,
/// so `SUDO_USER`'s group is used when it names a real, non-root account
/// (issue #150), the same choice the installer has always made.
pub(crate) fn gid(
    service_user: Option<&str>,
    sudo_user: Option<&str>,
    euid_root: bool,
    gid_of: impl Fn(&str) -> Option<u32>,
) -> Option<u32> {
    if !euid_root {
        return None;
    }
    match service_user.map(str::trim).filter(|u| !u.is_empty()) {
        Some(svc) => gid_of(svc),
        None => sudo_user
            .map(str::trim)
            .filter(|u| !u.is_empty() && *u != "root")
            .and_then(gid_of),
    }
}

/// Write `KEY=token` with mode 0640 through File replace, group chosen by
/// [`gid`] from `service_user`, `SUDO_USER` and the effective uid.
///
/// The token is staged in a 0600 temp file and renamed over the old one, so it
/// is never briefly world-readable nor truncated in place. An unchanged token
/// is not rewritten, but its mode and group are still repaired.
/// A group that cannot be set fails the write before the rename, leaving the
/// old token file in place.
pub(crate) fn write(
    path: &Path,
    key: &str,
    token: &ManagerToken,
    service_user: Option<&str>,
) -> Result<()> {
    let body = format!("{}={}\n", key, token.expose());
    let sudo_user = std::env::var("SUDO_USER").ok();
    let gid = gid(
        service_user,
        sudo_user.as_deref(),
        is_euid_root(),
        gid_for_user,
    );
    file_replace::replace(path, body.as_bytes(), Perms::Exact { mode: 0o640, gid })
        .map_err(|e| Error::config_write(path, e))
}

pub(crate) fn is_euid_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
            } else {
                None
            }
        })
        .unwrap_or(1)
        == 0
}

fn gid_for_user(user: &str) -> Option<u32> {
    // Primary group of the account (`id -g user`); None when it is unknown.
    let out = std::process::Command::new("id")
        .args(["-g", user])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const KEY: &str = "OP_SERVICE_ACCOUNT_TOKEN";

    fn probe_text(text: &str) -> Probe {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.env");
        fs::write(&path, text).unwrap();
        probe(&path, KEY)
    }

    #[test]
    fn a_present_token_is_returned_with_the_verdict() {
        match probe_text("OP_SERVICE_ACCOUNT_TOKEN=\"ops_abc\"\n") {
            Probe::Token(t) => assert_eq!(t.expose(), "ops_abc"),
            other => panic!("expected Token, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_value_holds_no_value() {
        for text in [
            "OP_SERVICE_ACCOUNT_TOKEN=\n",
            "OP_SERVICE_ACCOUNT_TOKEN=\"\"\n",
        ] {
            let probe = probe_text(text);
            assert!(matches!(probe, Probe::NoValue), "{text:?}: {probe:?}");
            assert_eq!(probe.state(), State::Missing);
        }
    }

    #[test]
    fn an_absent_key_holds_no_value() {
        let probe = probe_text("BWS_ACCESS_TOKEN=0.a.b:c\n");
        assert!(matches!(probe, Probe::NoValue), "{probe:?}");
        assert_eq!(probe.state(), State::Missing);
    }

    #[test]
    fn an_unparseable_line_is_malformed_and_names_the_line() {
        for (text, line) in [
            ("not a token line\n", 1),
            ("OP_SERVICE_ACCOUNT_TOKEN=ops_abc\n\nstray\n", 3),
            ("1BAD=x\n", 1),
        ] {
            match probe_text(text) {
                Probe::Malformed(fault) => {
                    assert_eq!(fault.line, line, "{text:?}");
                    assert!(fault.message.contains(&format!("line {line}")), "{fault}");
                }
                other => panic!("{text:?}: expected Malformed, got {other:?}"),
            }
        }
        assert_eq!(probe_text("oops\n").state(), State::Malformed);
    }

    #[test]
    fn an_absent_file_or_a_directory_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            probe(&dir.path().join("op.env"), KEY),
            Probe::Missing
        ));
        assert!(matches!(probe(dir.path(), KEY), Probe::Missing));
        assert_eq!(probe(dir.path(), KEY).state(), State::Missing);
    }

    #[test]
    fn permission_denied_is_unreadable_not_missing() {
        // Skip when the suite runs as root: chmod 000 does not stop root.
        if is_euid_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.env");
        fs::write(&path, "OP_SERVICE_ACCOUNT_TOKEN=x\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        let probe = probe(&path, KEY);
        // Restore so tempfile cleanup can remove the file.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        match &probe {
            Probe::Unreadable(source) => {
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied)
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
        assert_eq!(probe.state(), State::Unreadable);
    }

    fn reader(user: &str, service_user: Option<&str>) -> Reader {
        Reader {
            user: user.into(),
            service_user: Ok(service_user.map(Into::into)),
        }
    }

    #[test]
    fn the_unreadable_explanation_names_the_reader_and_the_missing_hop() {
        let msg = explain_unreadable("/etc/op.env", "Permission denied", &reader("jacob", None));
        assert!(
            msg.contains("/etc/op.env exists but cannot be read as `jacob`"),
            "{msg}"
        );
        assert!(msg.contains("(Permission denied)"), "{msg}");
        assert!(msg.contains("no service_user set"), "{msg}");

        let msg = explain_unreadable("/etc/op.env", "denied", &reader("jacob", Some("svc")));
        assert!(msg.contains("privilege hop did not run"), "{msg}");

        let msg = explain_unreadable("/etc/op.env", "denied", &reader("svc", Some("svc")));
        assert!(msg.contains("owner or mode is wrong"), "{msg}");

        let msg = explain_unreadable("/etc/op.env", "denied", &reader("", None));
        assert!(msg.contains("as this process"), "{msg}");

        let broken = Reader {
            user: "jacob".into(),
            service_user: Err("defaults.conf:2: bad".into()),
        };
        let msg = explain_unreadable("/etc/op.env", "denied", &broken);
        assert!(
            msg.contains("defaults.conf did not load: defaults.conf:2: bad"),
            "{msg}"
        );
    }

    #[test]
    fn the_malformed_explanation_names_the_file_the_line_and_the_rewrite() {
        let msg = explain_malformed("/etc/bws.env", "line 1: expected KEY=value", TokenKind::Bws);
        assert!(
            msg.contains("/etc/bws.env is malformed (line 1: expected KEY=value)"),
            "{msg}"
        );
        assert!(msg.contains("BWS_ACCESS_TOKEN"), "{msg}");
        assert!(msg.contains("setup bitwarden --set-token"), "{msg}");
    }

    /// Accounts the group tests know: everyone else is unknown.
    fn known_gid(user: &str) -> Option<u32> {
        match user {
            "root" => Some(0),
            "svc" => Some(900),
            "jacob" => Some(1000),
            _ => None,
        }
    }

    #[test]
    fn token_file_group_is_the_service_users_over_sudo_user() {
        assert_eq!(gid(Some("svc"), Some("jacob"), true, known_gid), Some(900));
        // An unknown Service user still wins: no fallback to the invoker.
        assert_eq!(gid(Some("ghost"), Some("jacob"), true, known_gid), None);
    }

    #[test]
    fn token_file_group_is_sudo_users_under_root_with_no_service_user() {
        assert_eq!(gid(None, Some("jacob"), true, known_gid), Some(1000));
        assert_eq!(
            gid(Some("  "), Some("jacob"), true, known_gid),
            Some(1000),
            "a blank Service user is no Service user"
        );
    }

    #[test]
    fn token_file_group_unchanged_for_sudo_user_root_or_unknown() {
        assert_eq!(gid(None, Some("root"), true, known_gid), None);
        assert_eq!(gid(None, Some("ghost"), true, known_gid), None);
        assert_eq!(gid(None, Some(""), true, known_gid), None);
        assert_eq!(gid(None, None, true, known_gid), None);
    }

    #[test]
    fn token_file_group_unchanged_when_not_root() {
        assert_eq!(gid(None, Some("jacob"), false, known_gid), None);
        assert_eq!(gid(Some("svc"), Some("jacob"), false, known_gid), None);
    }
}
