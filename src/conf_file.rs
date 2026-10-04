//! **Conf file**: the `key = value` text format of `defaults.conf` and every
//! Harness conf.
//!
//! One line rule for reading it: blank and `#` lines are not entries; any other
//! line is an entry whose key is the text before the first `=` (trimmed) and
//! whose value is the rest (trimmed), or a malformed line when it has no `=`.
//! What a key *means* stays with the reader (defaults getters, `Harness::parse`).
//!
//! One edit for changing it: set or remove a key in memory, touching only the
//! lines that carry it, then write the whole file atomically. A truncated
//! `defaults.conf` silently loses `service_user`, and with it the account
//! agents run as.

use std::fs;
use std::path::Path;

use crate::error::{Error, Result};

/// One physical line, as the line rule reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line<'a> {
    /// Blank, or a `#` comment.
    Comment,
    Entry {
        /// 1-based.
        lineno: usize,
        key: &'a str,
        value: &'a str,
    },
    /// Not blank, not a comment, and no `=`.
    Malformed { lineno: usize },
}

/// A conf text, read or edited. Remembers what it was read as, so a write that
/// changes nothing does not touch the file.
#[derive(Debug, Clone)]
pub struct ConfFile {
    original: String,
    text: String,
}

impl ConfFile {
    pub fn parse(text: &str) -> Self {
        Self {
            original: text.to_string(),
            text: text.to_string(),
        }
    }

    /// Read `path`. A missing file reads as empty; any other I/O error is returned.
    pub fn read(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => Ok(Self::parse(&text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::parse("")),
            Err(e) => Err(Error::Io {
                path: path.to_path_buf(),
                source: e,
            }),
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    /// True when the text read had no line other than blank ones.
    pub fn was_blank(&self) -> bool {
        self.original.trim().is_empty()
    }

    pub fn is_changed(&self) -> bool {
        self.text != self.original
    }

    pub fn lines(&self) -> impl Iterator<Item = Line<'_>> {
        split_lines(&self.text)
            .enumerate()
            .map(|(i, (content, _))| classify(i + 1, content))
    }

    /// The first non-empty value recorded for `key`.
    pub fn first(&self, key: &str) -> Option<&str> {
        self.values(key).next()
    }

    /// Every non-empty value recorded for `key`, in file order.
    pub fn all(&self, key: &str) -> Vec<&str> {
        self.values(key).collect()
    }

    fn values<'s, 'k>(&'s self, key: &'k str) -> impl Iterator<Item = &'s str> + use<'s, 'k> {
        self.lines().filter_map(move |l| match l {
            Line::Entry { key: k, value, .. } if k == key && !value.is_empty() => Some(value),
            _ => None,
        })
    }

    /// Make `key` single-valued with `value`.
    ///
    /// The first entry for `key` keeps its own text up to and including `=` and
    /// the whitespace after it (so `workdir  = caller` stays aligned); later
    /// entries for `key` are dropped. Appends `key = value` when absent. A value
    /// with a line break would inject a second config line, so it is refused.
    pub fn set(&mut self, key: &str, value: &str) -> Result<()> {
        if value.contains(['\n', '\r']) {
            return Err(Error::Message(format!(
                "{key}: value contains a line break (one config line per key)"
            )));
        }
        let mut out = String::with_capacity(self.text.len() + key.len() + value.len() + 4);
        let mut done = false;
        let mut last_ending = "\n";
        let mut ends_open = false;
        for (content, ending) in split_lines(&self.text) {
            if !ending.is_empty() {
                last_ending = ending;
            }
            ends_open = ending.is_empty();
            if is_entry_for(content, key) {
                if done {
                    continue;
                }
                done = true;
                let eq = content.find('=').expect("an entry has '='");
                let after = &content[eq + 1..];
                let ws = after.len() - after.trim_start().len();
                out.push_str(&content[..eq + 1 + ws]);
                out.push_str(value);
                out.push_str(ending);
            } else {
                out.push_str(content);
                out.push_str(ending);
            }
        }
        if !done {
            if ends_open && !out.is_empty() {
                out.push_str(last_ending);
            }
            out.push_str(&format!("{key} = {value}"));
            out.push_str(last_ending);
        }
        self.text = out;
        Ok(())
    }

    /// Drop every entry for `key`.
    pub fn remove(&mut self, key: &str) {
        self.text = split_lines(&self.text)
            .filter(|(content, _)| !is_entry_for(content, key))
            .map(|(content, ending)| format!("{content}{ending}"))
            .collect();
    }

    /// Put a comment line above everything else.
    pub fn prepend_comment(&mut self, comment: &str) {
        let ending = split_lines(&self.text)
            .map(|(_, e)| e)
            .find(|e| !e.is_empty())
            .unwrap_or("\n");
        self.text = format!("# {comment}{ending}{}", self.text);
    }

    /// Replace `path` with this text: through a temp file in the same
    /// directory and a rename, keeping the existing mode (`0644` for a new
    /// file) and, best effort, its owner. Does nothing when nothing changed.
    pub fn write(&self, path: &Path) -> Result<()> {
        if !self.is_changed() {
            return Ok(());
        }
        let dir = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        fs::create_dir_all(dir).map_err(|e| Error::config_write(dir, e))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "conf".to_string());
        // Dropped (and so deleted) on every early return below.
        let mut tmp = tempfile::Builder::new()
            .prefix(&format!(".{name}."))
            .suffix(".va-tmp")
            .tempfile_in(dir)
            .map_err(|e| Error::config_write(path, e))?;
        {
            use std::io::Write as _;
            tmp.write_all(self.text.as_bytes())
                .map_err(|e| Error::config_write(path, e))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let existing = fs::metadata(path).ok();
            let mode = existing
                .as_ref()
                .map(|m| m.permissions().mode() & 0o7777)
                .unwrap_or(0o644);
            fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode))
                .map_err(|e| Error::config_write(path, e))?;
            // The rename gives the file the writer's ownership; put back who
            // owned it. Only root can, which is the case that matters.
            if let Some(m) = existing {
                let _ = std::os::unix::fs::chown(tmp.path(), Some(m.uid()), Some(m.gid()));
            }
        }
        tmp.persist(path)
            .map_err(|e| Error::config_write(path, e.error))?;
        Ok(())
    }
}

fn classify(lineno: usize, content: &str) -> Line<'_> {
    let line = content.trim();
    if line.is_empty() || line.starts_with('#') {
        return Line::Comment;
    }
    match line.split_once('=') {
        Some((k, v)) => Line::Entry {
            lineno,
            key: k.trim(),
            value: v.trim(),
        },
        None => Line::Malformed { lineno },
    }
}

fn is_entry_for(content: &str, key: &str) -> bool {
    matches!(classify(0, content), Line::Entry { key: k, .. } if k == key)
}

/// Physical lines as `(content, ending)`; `\r\n`, `\n` and `\r` each end a
/// line. The last line's ending is empty when the text does not end in one.
fn split_lines(text: &str) -> impl Iterator<Item = (&str, &str)> {
    let mut rest = text;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let (content, ending, next) = match rest.find(['\n', '\r']) {
            Some(i) if rest[i..].starts_with("\r\n") => (&rest[..i], &rest[i..i + 2], i + 2),
            Some(i) => (&rest[..i], &rest[i..i + 1], i + 1),
            None => (rest, "", rest.len()),
        };
        rest = &rest[next..];
        Some((content, ending))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_blanks_entries_and_malformed_lines() {
        let c = ConfFile::parse("# head\n\n  key = some value  \nnope\nk2=\n");
        assert_eq!(
            c.lines().collect::<Vec<_>>(),
            vec![
                Line::Comment,
                Line::Comment,
                Line::Entry {
                    lineno: 3,
                    key: "key",
                    value: "some value"
                },
                Line::Malformed { lineno: 4 },
                Line::Entry {
                    lineno: 5,
                    key: "k2",
                    value: ""
                },
            ]
        );
    }

    #[test]
    fn the_key_is_the_text_before_the_first_equals() {
        let c = ConfFile::parse("alias = A = B\n");
        assert_eq!(c.first("alias"), Some("A = B"));
    }

    #[test]
    fn carriage_returns_read_the_same_as_newlines() {
        let lf = ConfFile::parse("a = 1\nb = 2\nnope\n");
        let crlf = ConfFile::parse("a = 1\r\nb = 2\r\nnope\r\n");
        let cr = ConfFile::parse("a = 1\rb = 2\rnope\r");
        let want: Vec<_> = lf.lines().collect();
        assert_eq!(crlf.lines().collect::<Vec<_>>(), want);
        assert_eq!(cr.lines().collect::<Vec<_>>(), want);
    }

    #[test]
    fn first_and_all_skip_empty_values() {
        let c = ConfFile::parse("x =\nx = one\ny = 9\nx = two\nx =   \n");
        assert_eq!(c.first("x"), Some("one"));
        assert_eq!(c.all("x"), vec!["one", "two"]);
        assert_eq!(c.first("missing"), None);
        assert!(c.all("missing").is_empty());
    }

    #[test]
    fn set_keeps_an_aligned_lines_spacing() {
        let mut c = ConfFile::parse("# shipped\nworkdir  = /old  \ncommand  = claude\n");
        c.set("workdir", "caller").unwrap();
        assert_eq!(
            c.text(),
            "# shipped\nworkdir  = caller\ncommand  = claude\n"
        );
    }

    #[test]
    fn set_drops_later_duplicates() {
        let mut c = ConfFile::parse("a = 1\nb = 2\na = 3\n# a = 4\na=5\n");
        c.set("a", "x").unwrap();
        assert_eq!(c.text(), "a = x\nb = 2\n# a = 4\n");
    }

    #[test]
    fn set_appends_when_absent() {
        let mut c = ConfFile::parse("# only a comment");
        c.set("k", "v").unwrap();
        assert_eq!(c.text(), "# only a comment\nk = v\n");

        let mut empty = ConfFile::parse("");
        empty.set("k", "v").unwrap();
        assert_eq!(empty.text(), "k = v\n");

        let mut crlf = ConfFile::parse("a = 1\r\n");
        crlf.set("k", "v").unwrap();
        assert_eq!(crlf.text(), "a = 1\r\nk = v\r\n");
    }

    #[test]
    fn remove_drops_every_entry_for_the_key() {
        let mut c = ConfFile::parse("# c\nsu = a\nb = 2\nsu=b\n");
        c.remove("su");
        assert_eq!(c.text(), "# c\nb = 2\n");
        assert!(c.is_changed());
    }

    #[test]
    fn a_line_break_in_a_value_is_refused() {
        let mut c = ConfFile::parse("a = 1\n");
        assert!(c.set("a", "x\nservice_user = root").is_err());
        assert!(c.set("a", "x\ry").is_err());
        assert_eq!(c.text(), "a = 1\n");
    }

    #[test]
    fn read_of_a_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let c = ConfFile::read(&dir.path().join("nope.conf")).unwrap();
        assert_eq!(c.text(), "");
        assert!(c.was_blank());
    }

    #[test]
    fn read_of_a_directory_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ConfFile::read(dir.path()).is_err());
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        v.sort();
        v
    }

    #[cfg(unix)]
    #[test]
    fn write_keeps_the_mode_and_leaves_no_temp_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("defaults.conf");
        fs::write(&p, "# keep\nauth_mode = file\n").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        let mut c = ConfFile::read(&p).unwrap();
        c.set("auth_mode", "prompt").unwrap();
        c.write(&p).unwrap();
        assert_eq!(
            fs::read_to_string(&p).unwrap(),
            "# keep\nauth_mode = prompt\n"
        );
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(entries(dir.path()), vec!["defaults.conf"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_new_file_is_0644_and_its_directory_is_created() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/defaults.conf");
        let mut c = ConfFile::read(&p).unwrap();
        c.set("k", "v").unwrap();
        c.write(&p).unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "k = v\n");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn an_unchanged_file_is_not_touched() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("h.conf");
        fs::write(&p, "workdir  = caller\n").unwrap();
        let before = fs::metadata(&p).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut c = ConfFile::read(&p).unwrap();
        c.set("workdir", "caller").unwrap();
        assert!(!c.is_changed());
        // A write would rename a new file over it: a new inode.
        #[cfg(unix)]
        let ino = {
            use std::os::unix::fs::MetadataExt;
            fs::metadata(&p).unwrap().ino()
        };
        c.write(&p).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().modified().unwrap(), before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(fs::metadata(&p).unwrap().ino(), ino);
        }
        assert_eq!(entries(dir.path()), vec!["h.conf"]);
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_write_leaves_no_temp_file() {
        // Renaming over a directory fails after the temp file exists.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("defaults.conf");
        fs::create_dir(&p).unwrap();
        fs::write(p.join("inside"), "x").unwrap();
        let mut c = ConfFile::parse("");
        c.set("k", "v").unwrap();
        assert!(c.write(&p).is_err());
        assert_eq!(entries(dir.path()), vec!["defaults.conf"]);
    }

    #[test]
    fn prepend_comment_goes_above_everything() {
        let mut c = ConfFile::parse("");
        c.set("auth_mode", "file").unwrap();
        c.prepend_comment("Machine-wide launcher defaults.");
        assert_eq!(
            c.text(),
            "# Machine-wide launcher defaults.\nauth_mode = file\n"
        );
    }
}
