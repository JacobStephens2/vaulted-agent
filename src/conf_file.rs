//! **Conf file**: the `key = value` text format of `defaults.conf` and every
//! Harness conf.
//!
//! One line rule for reading it: blank and `#` lines are not entries; any other
//! line is an entry whose key is the text before the first `=` (trimmed) and
//! whose value is the rest (trimmed), or a malformed line when it has no `=`.
//! What a key *means* stays with the reader (Machine defaults, `Harness::parse`).
//!
//! One edit for changing it: set or remove a key in memory, touching only the
//! lines that carry it, then write the whole file through File replace. A truncated
//! `defaults.conf` silently loses `service_user`, and with it the account
//! agents run as.

use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::file_replace::{self, Perms};

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

    /// Replace `path` with this text through File replace, keeping the
    /// existing mode and owner (`0644` for a new file). Does nothing when
    /// nothing changed. A symlinked conf keeps its link.
    pub fn write(&self, path: &Path) -> Result<()> {
        if !self.is_changed() {
            return Ok(());
        }
        file_replace::replace(path, self.text.as_bytes(), Perms::Keep)
            .map_err(|e| Error::config_write(path, e))
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

    #[test]
    fn setting_the_value_already_there_is_no_change() {
        let mut c = ConfFile::parse("workdir  = caller\n");
        c.set("workdir", "caller").unwrap();
        assert!(!c.is_changed());
        assert_eq!(c.text(), "workdir  = caller\n");
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
