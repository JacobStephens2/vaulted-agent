//! Manifest entries: the one reading of `KEY=value` text every reader shares.
//!
//! The launch, validate, `refresh` (merge presence checks and the prune scan),
//! `edit-manifest` and launch-failure blame all need to know where a mapping
//! starts and ends, what its value is once the quotes are gone, and which
//! physical lines it occupies. Each used to decide for itself, and each
//! disagreed with the launch on multi-line or quoted values. The rules live
//! here now, so they can only be wrong in one place.
//!
//! The rules, in brief:
//!
//! - A blank line or a `#` comment is not an entry, and ends any value above it.
//! - A line starts a new entry when the text before its first `=` is a legal
//!   variable name.
//! - A double-quoted value that does not close on its own line takes following
//!   lines until it does. The closing quote ends it.
//! - Any other line continues the bare value above it, so a PEM or a
//!   pretty-printed JSON key from `op inject` stays one value. With nothing open
//!   to continue, the line is a fault.
//! - One layer of surrounding single or double quotes is removed from a value.
//!
//! Parsing keeps going after a fault so an editor can list every problem in one
//! pass; the launch takes the first fault and fails closed on it.

use crate::validate::validate_var_name;

/// One `KEY=value` mapping as the shared parser reads it. It may span several
/// physical lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub var: String,
    /// The value with one layer of surrounding quotes removed: what the launch
    /// puts in the child environment (or resolves, for refs).
    pub value: String,
    /// The value text as written, quotes and any trailing annotation included,
    /// continuation lines joined with `\n`.
    pub raw: String,
    /// 1-based physical line the entry starts on.
    pub first_line: usize,
    /// 1-based physical line the entry ends on. Equal to `first_line` for a
    /// single-line entry.
    pub last_line: usize,
    /// Whether surrounding quotes were removed from the value.
    pub quoted: bool,
}

impl Entry {
    /// True when the entry occupies more than one physical line.
    pub fn is_multiline(&self) -> bool {
        self.last_line > self.first_line
    }
}

/// A line the parser could not read as part of any entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    /// 1-based physical line the fault is reported on.
    pub line: usize,
    /// The full message, `line N: …` prefix included — the exact text the
    /// launch has always failed with.
    pub message: String,
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Everything a Manifest says, in file order, and everything wrong with it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    pub entries: Vec<Entry>,
    pub faults: Vec<Fault>,
}

/// Parse Manifest text into entries and faults.
pub fn parse(text: &str) -> Parsed {
    let mut out = Parsed::default();
    let mut lines = text.lines();
    let mut lineno = 0usize;
    // Whether the entry pushed most recently may still take continuation lines.
    // A blank line, a comment or a fault closes it, so a stray line further
    // down the file cannot silently graft itself onto an earlier secret.
    let mut open = false;
    while let Some(raw) = lines.next() {
        lineno += 1;
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            open = false;
            continue;
        }
        // A line only starts a new entry when the text before its first '=' is
        // a legal variable name. That keeps a continuation line that happens to
        // contain '=' -- a JSON field, base64 padding -- attached to the value
        // it belongs to instead of being misread as an assignment.
        let assignment = trimmed
            .split_once('=')
            .filter(|(k, _)| validate_var_name(k.trim()));
        let Some((k, v)) = assignment else {
            if open {
                // `open` is only set just after a push, so there is always a
                // previous entry here.
                if let Some(last) = out.entries.last_mut() {
                    last.value.push('\n');
                    last.value.push_str(line);
                    last.raw.push('\n');
                    last.raw.push_str(line);
                    last.last_line = lineno;
                    continue;
                }
            }
            // Nothing to continue, so report how this line actually fails.
            let message = match trimmed.split_once('=') {
                Some((k, _)) => format!("line {lineno}: bad variable name {}", k.trim()),
                None => format!("line {lineno}: expected KEY=value"),
            };
            out.faults.push(Fault {
                line: lineno,
                message,
            });
            open = false;
            continue;
        };
        let key = k.trim();
        let first_line = lineno;
        let mut val = v.trim().to_string();
        // Multi-line double-quoted value
        if val.starts_with('"') && !double_quoted_closed(&val) {
            let mut closed = false;
            for cont in lines.by_ref() {
                lineno += 1;
                val.push('\n');
                val.push_str(cont.trim_end_matches('\r'));
                if double_quoted_closed(&val) {
                    closed = true;
                    break;
                }
            }
            if !closed {
                // The rest of the file was swallowed looking for the close, so
                // there is nothing left to parse.
                out.faults.push(Fault {
                    line: lineno,
                    message: format!("line {lineno}: unclosed double-quoted value for {key}"),
                });
                break;
            }
            // The closing quote ended the value; later lines are not part of it.
            out.entries.push(entry(key, val, first_line, lineno));
            open = false;
            continue;
        }
        out.entries.push(entry(key, val, first_line, lineno));
        open = true;
    }
    out
}

fn entry(var: &str, raw: String, first_line: usize, last_line: usize) -> Entry {
    let (value, quoted) = unquote(&raw);
    Entry {
        var: var.to_string(),
        value,
        raw,
        first_line,
        last_line,
        quoted,
    }
}

/// Strip a single layer of surrounding single or double quotes (bash `source`
/// parity), reporting whether there was one.
fn unquote(v: &str) -> (String, bool) {
    let v = v.trim();
    let b = v.as_bytes();
    if b.len() >= 2 {
        let (first, last) = (b[0], b[b.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return (v[1..v.len() - 1].to_string(), true);
        }
    }
    (v.to_string(), false)
}

fn double_quoted_closed(s: &str) -> bool {
    if !s.starts_with('"') || s.len() < 2 {
        return false;
    }
    // Ends with an unescaped "
    let b = s.as_bytes();
    if b[b.len() - 1] != b'"' {
        return false;
    }
    // Count trailing backslashes before the final quote
    let mut i = b.len() - 1;
    let mut bs = 0usize;
    while i > 0 && b[i - 1] == b'\\' {
        bs += 1;
        i -= 1;
    }
    bs.is_multiple_of(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line_entries_carry_their_line() {
        let p = parse("# header\nA=1\n\nB=2\n");
        assert!(p.faults.is_empty(), "{:?}", p.faults);
        assert_eq!(
            p.entries,
            vec![
                Entry {
                    var: "A".into(),
                    value: "1".into(),
                    raw: "1".into(),
                    first_line: 2,
                    last_line: 2,
                    quoted: false,
                },
                Entry {
                    var: "B".into(),
                    value: "2".into(),
                    raw: "2".into(),
                    first_line: 4,
                    last_line: 4,
                    quoted: false,
                },
            ]
        );
    }

    #[test]
    fn a_bare_multiline_value_spans_its_continuation_lines() {
        let text = "A=1\nSA={\n  \"type\": \"service_account\",\n  \"tok\": \"ab==\"\n}\n\nB=2\n";
        let p = parse(text);
        assert!(p.faults.is_empty(), "{:?}", p.faults);
        assert_eq!(p.entries.len(), 3);
        let sa = &p.entries[1];
        assert_eq!(sa.var, "SA");
        assert_eq!((sa.first_line, sa.last_line), (2, 5));
        assert!(sa.is_multiline());
        assert!(!sa.quoted);
        assert_eq!(
            sa.value,
            "{\n  \"type\": \"service_account\",\n  \"tok\": \"ab==\"\n}"
        );
        assert_eq!(sa.raw, sa.value);
        assert_eq!(p.entries[2].first_line, 7);
    }

    #[test]
    fn a_double_quoted_multiline_value_owns_lines_that_look_like_mappings() {
        let p = parse("A=\"x\nB=op://V/gone/f\n\"\nC=3\n");
        assert!(p.faults.is_empty(), "{:?}", p.faults);
        let vars: Vec<&str> = p.entries.iter().map(|e| e.var.as_str()).collect();
        assert_eq!(vars, ["A", "C"]);
        let a = &p.entries[0];
        assert_eq!((a.first_line, a.last_line), (1, 3));
        assert!(a.quoted);
        assert_eq!(a.value, "x\nB=op://V/gone/f\n");
        assert_eq!(a.raw, "\"x\nB=op://V/gone/f\n\"");
        assert_eq!(p.entries[1].first_line, 4);
    }

    #[test]
    fn single_and_double_quotes_are_removed_and_recorded() {
        let p = parse("D=\"name:KEY\"\nS='op://V/i/f'\nB=bare\n");
        assert!(p.faults.is_empty(), "{:?}", p.faults);
        let got: Vec<(&str, &str, bool)> = p
            .entries
            .iter()
            .map(|e| (e.value.as_str(), e.raw.as_str(), e.quoted))
            .collect();
        assert_eq!(
            got,
            [
                ("name:KEY", "\"name:KEY\"", true),
                ("op://V/i/f", "'op://V/i/f'", true),
                ("bare", "bare", false),
            ]
        );
    }

    #[test]
    fn an_unclosed_quote_consumes_the_rest_and_ends_parsing() {
        let p = parse("A=1\nB=\"never closed\nC=3\nD=4\n");
        assert_eq!(p.entries.len(), 1);
        assert_eq!(p.entries[0].var, "A");
        assert_eq!(
            p.faults,
            vec![Fault {
                line: 4,
                message: "line 4: unclosed double-quoted value for B".into(),
            }]
        );
    }

    #[test]
    fn a_bad_name_mid_file_is_a_fault_and_parsing_continues() {
        let p = parse("A=1\n\nMY-VAR=x\nnoise\nB=2\nC=3\n");
        let vars: Vec<&str> = p.entries.iter().map(|e| e.var.as_str()).collect();
        assert_eq!(vars, ["A", "B", "C"]);
        // The fault closes continuation, so `noise` is a fault of its own
        // rather than part of anything.
        assert_eq!(
            p.faults,
            vec![
                Fault {
                    line: 3,
                    message: "line 3: bad variable name MY-VAR".into(),
                },
                Fault {
                    line: 4,
                    message: "line 4: expected KEY=value".into(),
                },
            ]
        );
    }

    #[test]
    fn a_trailing_source_recording_stays_in_the_raw_value() {
        // Stripping `# uuid:` is the Bitwarden callers' job (ADR-0004); a
        // plainfile value may hold `#` as material.
        let u = "11111111-1111-1111-1111-111111111111";
        let p = parse(&format!("A=name:A_KEY # uuid:{u}\n"));
        assert_eq!(p.entries[0].raw, format!("name:A_KEY # uuid:{u}"));
        assert_eq!(p.entries[0].value, p.entries[0].raw);
    }

    #[test]
    fn crlf_line_endings_do_not_reach_the_value() {
        let p = parse("A=1\r\nB=\"x\r\ny\"\r\n");
        assert!(p.faults.is_empty(), "{:?}", p.faults);
        assert_eq!(p.entries[0].value, "1");
        assert_eq!(p.entries[1].value, "x\ny");
    }
}
