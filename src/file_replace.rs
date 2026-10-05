//! **File replace**: how the Launcher rewrites a file it owns the whole
//! content of — a Conf file, a Refs file, a Manager-token file, a new Harness
//! conf or starter Manifest.
//!
//! One rule for every such write. The file is replaced whole or not at all,
//! through a uniquely named temp file in the same directory and a rename. A
//! symlink is followed: the file it points at is replaced and the link stays.
//! Owner and mode are kept from the file being replaced, or set exactly by the
//! caller. Identical bytes are never rewritten.
//!
//! Errors are plain `io::Error`; each caller maps them the way it always has,
//! so a Refs file failure never picks up a Conf file's sudo hint.

use std::fs;
use std::io::{self, ErrorKind, Write as _};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

/// Who may read the replaced file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Perms {
    /// The replaced file's mode (`& 0o7777`) and, best effort, its owner and
    /// group. A new file gets `0644`.
    Keep,
    /// This mode and, when given, this group, applied even when the bytes are
    /// unchanged.
    Exact { mode: u32, gid: Option<u32> },
}

/// Replace `path` with `bytes` under `perms`. Creates the parent directory.
pub fn replace(path: &Path, bytes: &[u8], perms: Perms) -> io::Result<()> {
    let target = resolve(path);
    let existing = fs::metadata(&target).ok();
    if existing.is_some() && fs::read(&target).is_ok_and(|cur| cur == bytes) {
        if let Perms::Exact { mode, gid } = perms {
            if gid.is_some() {
                std::os::unix::fs::chown(&target, None, gid)?;
            }
            fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
        }
        return Ok(());
    }
    // Dropped (and so deleted) on every early return below.
    let tmp = stage(&target, bytes)?;
    // A chown may clear setuid/setgid bits, so it goes before the mode.
    let mode = match perms {
        Perms::Keep => match &existing {
            Some(m) => {
                // The rename gives the file the writer's ownership; put back
                // who owned it. Only root can, which is the case that matters.
                let _ = std::os::unix::fs::chown(tmp.path(), Some(m.uid()), Some(m.gid()));
                m.permissions().mode() & 0o7777
            }
            None => 0o644,
        },
        Perms::Exact { mode, gid } => {
            if gid.is_some() {
                std::os::unix::fs::chown(tmp.path(), None, gid)?;
            }
            mode
        }
    };
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    tmp.persist(&target).map_err(|e| e.error)?;
    sync_dir(&target);
    Ok(())
}

/// Create `path` with `bytes` and `mode` unless something is already there.
/// Returns whether this call created it. Creates the parent directory.
pub fn create_new(path: &Path, bytes: &[u8], mode: u32) -> io::Result<bool> {
    let tmp = stage(path, bytes)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    match tmp.persist_noclobber(path) {
        Ok(_) => {
            sync_dir(path);
            Ok(true)
        }
        Err(e) if e.error.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e.error),
    }
}

/// The file a write lands on: a symlink's target, or `path` itself.
fn resolve(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// `bytes` in a fresh `0600` temp file beside `path`, flushed to disk.
fn stage(path: &Path, bytes: &[u8]) -> io::Result<NamedTempFile> {
    let dir = parent(path);
    fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let mut tmp = tempfile::Builder::new()
        .prefix(&format!(".{name}."))
        .suffix(".va-tmp")
        .tempfile_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    Ok(tmp)
}

/// Make the rename itself durable. Best effort: the file is already whole.
fn sync_dir(path: &Path) {
    if let Ok(d) = fs::File::open(parent(path)) {
        let _ = d.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        v.sort();
        v
    }

    fn mode_of(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn keep_keeps_the_mode_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("defaults.conf");
        fs::write(&p, "old\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        replace(&p, b"new\n", Perms::Keep).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "new\n");
        assert_eq!(mode_of(&p), 0o640);
        assert_eq!(entries(dir.path()), vec!["defaults.conf"]);
    }

    #[test]
    fn a_new_file_is_0644_and_its_directory_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/defaults.conf");
        replace(&p, b"k = v\n", Perms::Keep).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "k = v\n");
        assert_eq!(mode_of(&p), 0o644);
    }

    #[test]
    fn a_symlink_keeps_its_link_and_its_target_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.conf");
        let link = dir.path().join("defaults.conf");
        fs::write(&real, "old\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        replace(&link, b"new\n", Perms::Keep).unwrap();
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(&real).unwrap(), "new\n");
        assert_eq!(entries(dir.path()), vec!["defaults.conf", "real.conf"]);
    }

    #[test]
    fn a_failed_rename_leaves_no_temp_file() {
        // Renaming over a directory fails after the temp file exists.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("defaults.conf");
        fs::create_dir(&p).unwrap();
        fs::write(p.join("inside"), "x").unwrap();
        assert!(replace(&p, b"k = v\n", Perms::Keep).is_err());
        assert_eq!(entries(dir.path()), vec!["defaults.conf"]);
    }

    #[test]
    fn identical_bytes_keep_the_inode_and_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.conf");
        fs::write(&p, "same\n").unwrap();
        let before = fs::metadata(&p).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        replace(&p, b"same\n", Perms::Keep).unwrap();
        let after = fs::metadata(&p).unwrap();
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        assert_eq!(entries(dir.path()), vec!["h.conf"]);
    }

    #[test]
    fn exact_repairs_the_mode_on_unchanged_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.env");
        fs::write(&p, "T=x\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let ino = fs::metadata(&p).unwrap().ino();
        let exact = Perms::Exact {
            mode: 0o640,
            gid: None,
        };
        replace(&p, b"T=x\n", exact).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().ino(), ino);
        assert_eq!(mode_of(&p), 0o640);
        // And on new bytes, whatever the old mode was.
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        replace(&p, b"T=y\n", exact).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "T=y\n");
        assert_eq!(mode_of(&p), 0o640);
    }

    #[test]
    fn create_new_does_not_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/claude.conf");
        assert!(create_new(&p, b"first\n", 0o644).unwrap());
        assert_eq!(mode_of(&p), 0o644);
        assert!(!create_new(&p, b"second\n", 0o644).unwrap());
        assert_eq!(fs::read_to_string(&p).unwrap(), "first\n");
        assert_eq!(entries(&dir.path().join("sub")), vec!["claude.conf"]);
    }

    /// A group the test user belongs to other than its primary one, so a
    /// chown to it is both allowed and observable.
    fn supplementary_gid() -> Option<u32> {
        let out = std::process::Command::new("id").arg("-G").output().ok()?;
        let primary = std::process::Command::new("id").arg("-g").output().ok()?;
        let primary: u32 = String::from_utf8_lossy(&primary.stdout)
            .trim()
            .parse()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .filter_map(|g| g.parse().ok())
            .find(|&g| g != primary)
    }

    #[test]
    fn keep_keeps_the_group_of_an_existing_file() {
        let Some(gid) = supplementary_gid() else {
            eprintln!("skipped: the test user has no supplementary group");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        fs::write(&p, "A=name:A\n").unwrap();
        std::os::unix::fs::chown(&p, None, Some(gid)).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        replace(&p, b"A=name:A\nB=name:B\n", Perms::Keep).unwrap();
        let m = fs::metadata(&p).unwrap();
        assert_eq!(m.gid(), gid);
        assert_eq!(m.permissions().mode() & 0o7777, 0o640);
    }

    #[test]
    fn exact_sets_the_group_given() {
        let Some(gid) = supplementary_gid() else {
            eprintln!("skipped: the test user has no supplementary group");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.env");
        let exact = Perms::Exact {
            mode: 0o640,
            gid: Some(gid),
        };
        replace(&p, b"T=x\n", exact).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().gid(), gid);
        // Unchanged bytes still get the group back.
        let primary = fs::metadata(dir.path()).unwrap().gid();
        std::os::unix::fs::chown(&p, None, Some(primary)).unwrap();
        replace(&p, b"T=x\n", exact).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().gid(), gid);
    }
}
