//! Refs files: generating, judging and editing the lines `refresh` and `setup`
//! manage, for Bitwarden and 1Password.

use std::fs;
use std::path::Path;

use crate::bitwarden::{BwListing, BwSecret, Lookup};
use crate::error::{Error, Result};
use crate::onepassword::{Lookup as OpLookup, OpListing};

mod writer;
pub use writer::{write_refs, Mapping, RefsStyle, RefsWrite, WriteMode};

fn key_to_var(key: &str) -> String {
    let mut s: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    let needs_prefix = !matches!(s.chars().next(), Some(c) if c.is_ascii_alphabetic() || c == '_');
    if needs_prefix {
        s = format!("SECRET_{s}");
    }
    s
}

/// Split a Bitwarden refs value into its reference and trailing annotation.
///
/// Generated lines record which secret they came from, so a vault-side rename
/// stays detectable after the key it was named for is gone (ADR-0004):
///
/// ```text
/// ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:ea6db86f-…
/// ```
///
/// The split needs whitespace before the `#`. No Bitwarden reference form
/// contains whitespace, so ` #` unambiguously ends one — while a bare `#` may
/// sit inside a secret key, and treating that as a comment would send a
/// truncated reference to the vault.
///
/// Bitwarden refs only. A dotenv manifest holds secret *values*, where a `#`
/// is ordinary material.
pub fn split_annotation(value: &str) -> (&str, Option<&str>) {
    let mut prev_ws = false;
    for (i, c) in value.char_indices() {
        if c == '#' && prev_ws {
            return (value[..i].trim_end(), Some(value[i + 1..].trim()));
        }
        prev_ws = c.is_whitespace();
    }
    (value, None)
}

/// The reference a Bitwarden refs value carries, annotation removed.
pub fn reference_of(value: &str) -> &str {
    split_annotation(value).0
}

/// The source UUID a Bitwarden refs value records, if it records one.
///
/// A placeholder records nothing: invariant 4 keeps placeholders loud, and a
/// zero UUID must never be the evidence that turns a line into a rename.
pub fn recorded_uuid(value: &str) -> Option<&str> {
    split_annotation(value)
        .1?
        .split_whitespace()
        .find_map(|t| t.strip_prefix("uuid:"))
        .filter(|u| is_recordable(u))
}

/// Is this id worth recording on a line?
///
/// A placeholder is not: invariant 4 keeps placeholders loud, and a zero UUID
/// must never be the evidence that turns a line into a rename.
fn is_recordable(id: &str) -> bool {
    crate::validate::is_uuid(id) && !crate::validate::is_placeholder_ref(id)
}

/// A `name:` mapping line, carrying its source recording when there is one.
///
/// The single place the annotated form is spelled out — generation and repair
/// must not be able to disagree about it.
fn name_line(var: &str, key: &str, id: &str) -> String {
    if is_recordable(id) {
        format!("{var}=name:{key} # uuid:{id}")
    } else {
        format!("{var}=name:{key}")
    }
}

/// Recover the one-mapping-per-line form of a 0.3.0 glued Bitwarden refs line.
///
/// `va refresh` on the bash launcher captured each `VAR=name:KEY\n` with
/// `$(…)`, which strips the trailing newline, then concatenated. When the SM
/// secret key was already env-shaped, VAR equals KEY and the file held:
///
/// ```text
/// META_AI_API_KEY=name:META_AI_API_KEYFIREWORKS_API_KEY=name:FIREWORKS_API_KEY
/// ```
///
/// KEY and the next VAR share the `[A-Z0-9_]` charset, so there is no
/// delimiter between them. The writer always emitted `VAR=name:VAR` in this
/// case, and that identity is what makes the split unambiguous.
///
/// Returns `None` when the line is a single mapping (or not this shape).
pub fn split_glued_bitwarden_line(line: &str) -> Option<Vec<String>> {
    let mut rest = line.trim();
    if rest.is_empty() || rest.starts_with('#') {
        return None;
    }
    let mut parts = Vec::new();
    while !rest.is_empty() {
        let (var, after_eq) = rest.split_once('=')?;
        if !crate::validate::validate_var_name(var) {
            return None;
        }
        let after_form = after_eq.strip_prefix("name:")?;
        if !after_form.starts_with(var) {
            return None;
        }
        let after_key = &after_form[var.len()..];
        if !after_key.is_empty() && !starts_with_name_assignment(after_key) {
            return None;
        }
        parts.push(format!("{var}=name:{var}"));
        rest = after_key;
    }
    (parts.len() >= 2).then_some(parts)
}

fn starts_with_name_assignment(s: &str) -> bool {
    let Some((var, after_eq)) = s.split_once('=') else {
        return false;
    };
    crate::validate::validate_var_name(var) && after_eq.starts_with("name:")
}

/// How one refs-file line stands against the secret listing `refresh` fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefFate {
    /// The reference names a secret the manager token can see.
    Resolvable,
    /// A well-formed Bitwarden reference matching nothing in the listing: a
    /// **dangling ref**, fatal to every launch through this manifest.
    Dangling,
    /// The reference matches nothing, but the UUID the line records names a
    /// secret still there under a different key: a **rename**. Repairable
    /// rather than prunable (ADR-0004).
    Renamed,
    /// An **ambiguous ref** (`CONTEXT.md`): the reference matches more than
    /// one listed secret, so the launch fails closed rather than pick one.
    /// Bitwarden only. Not dangling — the secrets exist, and pruning would
    /// delete a mapping to them (ADR-0003) — and not repairable, because which
    /// secret was meant is the operator's choice (ADR-0004). Reported, never
    /// edited.
    Ambiguous,
    /// Not a reference this can judge — an unknown shape, a placeholder, or a
    /// value carried across several lines. Reported, never pruned: shape is
    /// `secrets validate`'s concern (ADR-0003).
    Unjudged,
    /// An **unchecked ref** (`CONTEXT.md`): the reference names a live item
    /// whose fields this run never read, so nothing was learned about it either
    /// way. 1Password only — fields cost one `op item get` apiece, and
    /// `refresh` judges only what it already fetched (ADR-0005). Reported so
    /// the gap is visible, never pruned.
    Unchecked,
}

/// One mapping line, with its verdict against the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannedRef {
    pub var: String,
    /// The value with surrounding quotes removed, as the launch reads it.
    pub reference: String,
    /// The entry's first physical line exactly as it stands in the file,
    /// newline excluded. Prune matches on this, and it is what gets printed
    /// when a line is removed — scrollback is the recovery path.
    pub line: String,
    pub fate: RefFate,
    /// For `Renamed`: the key the recorded secret carries now.
    pub renamed_to: Option<String>,
    /// For `Ambiguous`: every listed secret the reference matches.
    pub candidates: Vec<BwSecret>,
}

impl ScannedRef {
    /// The line this mapping should become once the rename is applied.
    ///
    /// The **variable name does not change**. It is the contract with the agent
    /// and with any harness `alias =` reading it; the vault-side key is only
    /// how the secret is addressed. Rewriting the VAR would break the consumer
    /// silently, which is the failure ADR-0004 set out to remove.
    pub fn repaired_line(&self) -> Option<String> {
        let key = self.renamed_to.as_deref()?;
        let uuid = recorded_uuid(&self.reference)?;
        Some(name_line(&self.var, key, uuid))
    }
}

/// Classify every mapping line in a Bitwarden refs file against the listing
/// `refresh` already holds. No vault calls: the listing is the whole world.
///
/// Each line goes through the same lookup the launch resolves with, so a line
/// called resolvable here is a line the launch accepts. Absent is a rename when
/// the line's source recording names a listed secret, dangling otherwise;
/// ambiguous is its own fate, never pruned or repaired.
///
/// Values are read as the launch reads them, so a quoted `A="name:KEY"` is
/// judged by `name:KEY`. Prune still works on physical lines — it has to put the
/// file back byte for byte, and only a physical line can be dropped from it. A
/// value carried across lines is never a Bitwarden reference, so it is marked
/// `Unjudged` rather than risking a partial removal.
pub fn scan_bitwarden_refs(text: &str, listing: &BwListing) -> Vec<ScannedRef> {
    scan_refs(text, |value| match listing.lookup(reference_of(value)) {
        Lookup::Found(_) => Verdict::of(RefFate::Resolvable),
        // Only consulted for a reference that already failed to match, so a
        // working mapping is never reclassified on a stale recording.
        Lookup::Absent => match recorded_uuid(value).and_then(|u| listing.by_id(u)) {
            Some(now) => Verdict {
                renamed_to: Some(now.key.clone()),
                ..Verdict::of(RefFate::Renamed)
            },
            None => Verdict::of(RefFate::Dangling),
        },
        Lookup::Ambiguous(candidates) => Verdict {
            candidates: candidates.into_iter().cloned().collect(),
            ..Verdict::of(RefFate::Ambiguous)
        },
        Lookup::NotARef => Verdict::of(RefFate::Unjudged),
    })
}

/// What a backend says about one value.
struct Verdict {
    fate: RefFate,
    renamed_to: Option<String>,
    candidates: Vec<BwSecret>,
}

impl Verdict {
    fn of(fate: RefFate) -> Verdict {
        Verdict {
            fate,
            renamed_to: None,
            candidates: Vec::new(),
        }
    }
}

/// Walk a refs file's entries, letting the backend say what each value means.
/// The walk is the part both backends must agree on: prune puts the file back
/// byte for byte, so what counts as one mapping line cannot differ by backend
/// even where "does not resolve" does. Entries come from the parser the launch
/// uses, so a line inside another entry's multi-line value is never mistaken
/// for a mapping of its own.
fn scan_refs(text: &str, classify: impl Fn(&str) -> Verdict) -> Vec<ScannedRef> {
    let lines: Vec<&str> = text.lines().collect();
    crate::manifest_entry::parse(text)
        .entries
        .into_iter()
        .map(|e| {
            // Any entry spanning several physical lines must not be pruned:
            // removing its first line would leave the rest behind.
            let verdict = if e.is_multiline() {
                Verdict::of(RefFate::Unjudged)
            } else {
                classify(&e.value)
            };
            let line = lines
                .get(e.first_line - 1)
                .map_or("", |l| l.trim_end_matches('\r'));
            ScannedRef {
                var: e.var,
                reference: e.value,
                line: line.to_string(),
                fate: verdict.fate,
                renamed_to: verdict.renamed_to,
                candidates: verdict.candidates,
            }
        })
        .collect()
}

/// What `refresh` wants to do to one physical line of a refs file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefEdit {
    /// Drop the line: a dangling ref, already fatal to every launch through
    /// this manifest (ADR-0003).
    Remove,
    /// Replace the line with this text: a rename, repaired in place (ADR-0004).
    Rewrite(String),
}

/// Apply exactly these edits to a refs file, keeping every other byte:
/// comments, blank lines, ordering, UUID-form refs, operator headers.
///
/// One pass and one write, so a run that both removes a deleted secret and
/// repairs a renamed one cannot leave the file half-corrected.
///
/// Written through a temp file in the same directory and a rename, as every
/// Refs file write is: a truncated manifest is an install that launches nothing.
pub fn edit_refs_lines(path: &Path, edits: &[(String, RefEdit)]) -> Result<Vec<(String, RefEdit)>> {
    if edits.is_empty() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let planned: std::collections::HashMap<&str, &RefEdit> =
        edits.iter().map(|(l, e)| (l.as_str(), e)).collect();
    // Only a line that is a whole entry by itself may be edited. A line inside
    // another entry's multi-line value can read exactly like a mapping, and
    // dropping it would cut that value apart.
    let editable: std::collections::HashSet<usize> = crate::manifest_entry::parse(&text)
        .entries
        .iter()
        .filter(|e| !e.is_multiline())
        .map(|e| e.first_line)
        .collect();
    let mut body = String::with_capacity(text.len());
    // What actually changed, in file order — a line the operator wrote twice is
    // edited twice, and the report has to say so.
    let mut applied: Vec<(String, RefEdit)> = Vec::new();
    for (n, chunk) in text.split_inclusive('\n').enumerate() {
        let line = chunk.strip_suffix('\n').unwrap_or(chunk);
        let edit = if editable.contains(&(n + 1)) {
            planned.get(line.trim_end_matches('\r'))
        } else {
            None
        };
        match edit {
            Some(RefEdit::Remove) => {
                applied.push((line.to_string(), RefEdit::Remove));
                continue;
            }
            Some(RefEdit::Rewrite(new)) => {
                applied.push((line.to_string(), RefEdit::Rewrite(new.clone())));
                body.push_str(new);
                if chunk.ends_with('\n') {
                    body.push('\n');
                }
                continue;
            }
            None => body.push_str(chunk),
        }
    }
    if applied.is_empty() {
        return Ok(applied);
    }
    write_atomic(path, &body)?;
    Ok(applied)
}

/// Replace a file's contents without ever leaving it half-written.
fn write_atomic(path: &Path, body: &str) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "refs".to_string());
    let tmp = dir.join(format!(".{name}.va-tmp"));
    let io_err = |p: &Path, e: std::io::Error| Error::Io {
        path: p.to_path_buf(),
        source: e,
    };
    fs::write(&tmp, body).map_err(|e| io_err(&tmp, e))?;
    // The rename replaces the file, so the mode has to be the one the manifest
    // is meant to carry rather than whatever the temp file was created with.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path).map(|m| m.permissions().mode() & 0o777);
        let mut p = fs::metadata(&tmp)
            .map_err(|e| io_err(&tmp, e))?
            .permissions();
        p.set_mode(mode.unwrap_or(0o644));
        let _ = fs::set_permissions(&tmp, p);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(io_err(path, e));
    }
    Ok(())
}

/// Classify every mapping line in a 1Password refs file against the
/// **1Password listing** this run fetched. No extra vault calls — same rule as
/// Bitwarden, different listing. The fate is the lookup, read off: a reference
/// into an item this run never expanded is unchecked, never dangling (ADR-0005).
pub fn scan_op_refs(text: &str, listing: &OpListing) -> Vec<ScannedRef> {
    scan_refs(text, |value| {
        Verdict::of(match listing.lookup(value) {
            OpLookup::Found(_) => RefFate::Resolvable,
            OpLookup::Absent => RefFate::Dangling,
            OpLookup::Unexpanded => RefFate::Unchecked,
            OpLookup::NotARef => RefFate::Unjudged,
        })
    })
}

/// Keyword of the comment recording a variable name `refresh` must never map
/// (`# exclude: PATTERN`). The writer spells it out and `read_exclusions` reads
/// it back, so both take it from here.
const EXCLUDE_KEYWORD: &str = "exclude:";

/// Variable-name patterns the manifest records as "do not map these".
///
/// `refresh` maps every referenceable field of every item it is given. That is
/// the right default for a vault of credentials and the wrong one for the
/// fields sitting beside them: the `username` next to a password, or a login
/// item whose password field holds `google` because the account signs in with
/// Google. Without this they become variables in the agent's environment, and
/// the only way to be rid of them is to hand-edit a file `refresh` will
/// repopulate on its next run.
///
/// The patterns live in the manifest rather than only in a flag, because that
/// next run is the whole problem: an exclusion the operator has to remember to
/// retype is one refresh away from being undone.
pub fn read_exclusions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text.lines() {
        // Lenient about the space after '#': this is a file people hand-edit,
        // and a directive that silently does nothing because of one missing
        // character is worse than accepting both spellings.
        let line = raw.trim();
        let Some(body) = line.strip_prefix('#') else {
            continue;
        };
        let Some(rest) = body
            .trim_start()
            .strip_prefix(EXCLUDE_KEYWORD)
            .or_else(|| body.trim_start().strip_prefix("exclude "))
        else {
            continue;
        };
        let pat = rest.trim();
        if !pat.is_empty() && !out.iter().any(|p: &String| p == pat) {
            out.push(pat.to_string());
        }
    }
    out
}

/// True when `name` matches any pattern. `*` matches any run of characters and
/// `?` a single one; everything else is literal. Matching ignores case, so
/// `*_username` and `*_USERNAME` both catch the variables refresh generates.
pub fn is_excluded(patterns: &[String], name: &str) -> bool {
    patterns.iter().any(|p| matches_pattern(p, name))
}

/// Anchored glob over the whole name, `*` and `?` only. Backtracks on the last
/// `*` rather than recursing, so a pattern of all stars cannot blow the stack.
pub fn matches_pattern(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star, mut after_star) = (None, 0usize);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi].eq_ignore_ascii_case(&n[ni])) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            after_star = ni;
        } else if let Some(s) = star {
            pi = s + 1;
            after_star += 1;
            ni = after_star;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// A menu reply: `all`, or comma-separated numbers and `a-b` ranges.
///
/// Ranges matter at the size these menus reach. A 65-item vault makes
/// "everything but the last few" a line of sixty numbers, so the affordance
/// people reach for anyway — `1-40, 45, 50-60` — should be the one that works.
/// A descending range (`20-5`) is read as the same span rather than rejected;
/// it is unambiguous, and refusing it teaches nothing.
///
/// Duplicates are collapsed and the result is ordered, so overlapping ranges
/// select each item once.
pub fn parse_index_list(s: &str, n: usize) -> Result<Vec<usize>> {
    if s.trim() == "all" {
        return Ok((0..n).collect());
    }
    let one = |tok: &str| -> Result<usize> {
        let num: usize = tok
            .trim()
            .parse()
            .map_err(|_| Error::Message(format!("bad index {}", tok.trim())))?;
        if num == 0 || num > n {
            return Err(Error::Message(format!("index out of range: {num}")));
        }
        Ok(num)
    };

    let mut out: Vec<usize> = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Split on the first '-' only: indices are positive, so a second one is
        // a typo rather than a nested range, and `one()` reports it as such.
        match part.split_once('-') {
            Some((lo, hi)) => {
                let (lo, hi) = (one(lo)?, one(hi)?);
                let (lo, hi) = if lo <= hi { (lo, hi) } else { (hi, lo) };
                out.extend((lo..=hi).map(|i| i - 1));
            }
            None => out.push(one(part)? - 1),
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_list_accepts_ranges_as_well_as_numbers() {
        // A 65-item vault makes "most of them" a line of sixty numbers.
        assert_eq!(parse_index_list("1-5", 65).unwrap(), vec![0, 1, 2, 3, 4]);
        assert_eq!(
            parse_index_list("1-3, 7, 10-11", 65).unwrap(),
            vec![0, 1, 2, 6, 9, 10]
        );
        assert_eq!(parse_index_list("all", 3).unwrap(), vec![0, 1, 2]);
        // Overlapping spans select each item once.
        assert_eq!(parse_index_list("1-3,2-4", 10).unwrap(), vec![0, 1, 2, 3]);
        // Descending is unambiguous; refusing it would teach nothing.
        assert_eq!(parse_index_list("5-3", 10).unwrap(), vec![2, 3, 4]);
        // A single number still behaves.
        assert_eq!(parse_index_list("4", 10).unwrap(), vec![3]);
        assert!(parse_index_list("", 10).unwrap().is_empty());
    }

    #[test]
    fn index_list_still_refuses_what_it_cannot_mean() {
        assert!(parse_index_list("0-3", 10).is_err()); // menus are 1-based
        assert!(parse_index_list("1-99", 10).is_err()); // past the end
        assert!(parse_index_list("1-2-3", 10).is_err()); // not a range
        assert!(parse_index_list("x", 10).is_err());
        assert!(parse_index_list("1-x", 10).is_err());
    }

    #[test]
    fn exclusion_patterns_round_trip_through_the_manifest() {
        assert!(matches_pattern("*_USERNAME", "TWILIO_USERNAME"));
        assert!(matches_pattern("*_username", "TWILIO_USERNAME"));
        assert!(matches_pattern("ZOOM_*", "ZOOM_ACCOUNT_ID"));
        assert!(matches_pattern("EXACT", "EXACT"));
        assert!(matches_pattern("*", "ANYTHING"));
        assert!(matches_pattern("A?C", "ABC"));
        // Anchored at both ends: a bare substring is not a match.
        assert!(!matches_pattern("USERNAME", "TWILIO_USERNAME"));
        assert!(!matches_pattern("ZOOM_*", "TWILIO_ZOOM_ID"));
        assert!(!matches_pattern("A?C", "ABBC"));

        assert!(is_excluded(&["*_USERNAME".to_string()], "APOLLO_USERNAME"));
        assert!(!is_excluded(&["*_USERNAME".to_string()], "APOLLO_API_KEY"));
        assert!(!is_excluded(&[], "ANYTHING"));

        let text = "# a comment\n# exclude: *_USERNAME\nA=op://V/i/f\n#exclude:ZOOM_*\n";
        assert_eq!(read_exclusions(text), vec!["*_USERNAME", "ZOOM_*"]);
    }

    fn listing() -> BwListing {
        BwListing::new(vec![
            BwSecret::new(
                "ea6db86f-0000-0000-0000-000000000001",
                "ASSEMBLY_AI_API_KEY",
                "tools",
            ),
            BwSecret::new(
                "ea6db86f-0000-0000-0000-000000000002",
                "OPENAI_API_KEY",
                "tools",
            ),
        ])
    }

    #[test]
    fn a_renamed_secret_leaves_exactly_one_dangling_line() {
        // The case that started issue #80: the secret kept its UUID and changed
        // its key, so the old `name:` line matches nothing and every launch
        // through this manifest fails closed.
        let text = "# header\n\
                    ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY\n\
                    ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY\n";
        let scan = scan_bitwarden_refs(text, &listing());
        let dangling: Vec<&ScannedRef> = scan
            .iter()
            .filter(|r| r.fate == RefFate::Dangling)
            .collect();
        assert_eq!(dangling.len(), 1);
        assert_eq!(dangling[0].line, "ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY");
        assert_eq!(dangling[0].var, "ASSEMBLY_API_KEY");
    }

    #[test]
    fn every_bitwarden_form_is_judged_against_the_listing() {
        let secrets = listing();
        let text = "BY_UUID=ea6db86f-0000-0000-0000-000000000001\n\
                    BY_UUID_PREFIX=uuid:ea6db86f-0000-0000-0000-000000000002\n\
                    BY_PROJECT=project:tools/OPENAI_API_KEY\n\
                    GONE_UUID=ea6db86f-0000-0000-0000-00000000dead\n\
                    GONE_PROJECT=project:other/OPENAI_API_KEY\n";
        let scan = scan_bitwarden_refs(text, &secrets);
        let fates: Vec<(&str, RefFate)> = scan.iter().map(|r| (r.var.as_str(), r.fate)).collect();
        assert_eq!(
            fates,
            vec![
                ("BY_UUID", RefFate::Resolvable),
                ("BY_UUID_PREFIX", RefFate::Resolvable),
                ("BY_PROJECT", RefFate::Resolvable),
                ("GONE_UUID", RefFate::Dangling),
                ("GONE_PROJECT", RefFate::Dangling),
            ]
        );
    }

    /// A duplicated key, a key containing `/`, and the same key in two
    /// projects.
    fn tricky_listing() -> BwListing {
        BwListing::new(vec![
            BwSecret::new("11111111-1111-1111-1111-111111111111", "DUP", "tools"),
            BwSecret::new("22222222-2222-2222-2222-222222222222", "DUP", "tools"),
            BwSecret::new("33333333-3333-3333-3333-333333333333", "a/b", "P"),
            BwSecret::new("44444444-4444-4444-4444-444444444444", "SHARED", "P"),
            BwSecret::new("55555555-5555-5555-5555-555555555555", "SHARED", "Q"),
        ])
    }

    #[test]
    fn an_ambiguous_ref_has_a_fate_of_its_own_and_is_never_edited() {
        let text = "BY_NAME=name:DUP # uuid:11111111-1111-1111-1111-111111111111\n\
                    BY_PROJECT=project:tools/DUP\n\
                    ACROSS_PROJECTS=name:SHARED\n";
        let scan = scan_bitwarden_refs(text, &tricky_listing());
        assert!(
            scan.iter().all(|r| r.fate == RefFate::Ambiguous),
            "{scan:?}"
        );
        let ids: Vec<&str> = scan[2].candidates.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "44444444-4444-4444-4444-444444444444",
                "55555555-5555-5555-5555-555555555555"
            ]
        );
    }

    #[test]
    fn refresh_calls_a_line_resolvable_exactly_when_the_launch_finds_one_secret() {
        let listing = tricky_listing();
        for reference in [
            "11111111-1111-1111-1111-111111111111",
            "uuid:33333333-3333-3333-3333-333333333333",
            "99999999-9999-9999-9999-999999999999",
            "uuid:99999999-9999-9999-9999-999999999999",
            "name:DUP",
            "name:a/b",
            "name:SHARED",
            "name:GONE",
            "project:tools/DUP",
            "project:P/a/b",
            "project:P/b",
            "project:P/SHARED",
            "project:Q/SHARED",
            "project:R/SHARED",
            "REPLACE_WITH_BITWARDEN_SECRET_UUID",
            "00000000-0000-0000-0000-000000000000",
            "name:",
            "project:P",
            "junk",
        ] {
            let scan = scan_bitwarden_refs(&format!("VAR={reference}\n"), &listing);
            let refresh_ok = scan[0].fate == RefFate::Resolvable;
            let launch_ok = matches!(
                crate::backend::id_from_listing(&listing, reference),
                Ok(Some(_))
            );
            assert_eq!(refresh_ok, launch_ok, "{reference}: {:?}", scan[0].fate);
        }
    }

    #[test]
    fn a_shape_refresh_cannot_judge_is_never_dangling() {
        // Shape is `secrets validate`'s concern. Prune removes what does not
        // resolve, and a line it cannot parse has not been shown not to.
        let secrets = listing();
        let text = "JUNK=not-a-reference\n\
                    PLACEHOLDER=REPLACE_WITH_UUID\n\
                    ZEROS=00000000-0000-0000-0000-000000000000\n\
                    EMPTY_NAME=name:\n\
                    HALF_PROJECT=project:tools\n";
        let scan = scan_bitwarden_refs(text, &secrets);
        assert!(scan.iter().all(|r| r.fate == RefFate::Unjudged), "{scan:?}");
    }

    #[test]
    fn a_value_spanning_lines_is_left_alone() {
        // Never a Bitwarden reference, and prune can only drop whole lines —
        // so judging it dangling would risk a partial removal.
        let text = "SA={\n  \"type\": \"service_account\"\n}\n";
        let scan = scan_bitwarden_refs(text, &listing());
        assert_eq!(scan.len(), 1);
        assert_eq!(scan[0].fate, RefFate::Unjudged);
    }

    #[test]
    fn prune_removes_the_dangling_line_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        let before = "# Bitwarden Secrets Manager refs\n\
                      # operator header, hand written\n\
                      \n\
                      PINNED=uuid:ea6db86f-0000-0000-0000-000000000002\n\
                      ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY\n\
                      \n\
                      # --- appended by vaulted-agent refresh ---\n\
                      ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY\n";
        fs::write(&p, before).unwrap();

        let scan = scan_bitwarden_refs(before, &listing());
        let doomed: Vec<(String, RefEdit)> = scan
            .iter()
            .filter(|r| r.fate == RefFate::Dangling)
            .map(|r| (r.line.clone(), RefEdit::Remove))
            .collect();
        assert_eq!(
            edit_refs_lines(&p, &doomed).unwrap(),
            vec![(
                "ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY".to_string(),
                RefEdit::Remove
            )]
        );

        let after = fs::read_to_string(&p).unwrap();
        assert_eq!(
            after,
            before.replace("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY\n", "")
        );
        // Everything that was not the dangling line survived byte for byte:
        // comments, the blank lines, ordering, and the UUID-form ref.
        assert!(after.contains("# operator header, hand written"));
        assert!(after.contains("PINNED=uuid:ea6db86f-0000-0000-0000-000000000002"));
    }

    #[test]
    fn prune_leaves_the_file_alone_when_nothing_is_dangling() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        let before = "OPENAI_API_KEY=name:OPENAI_API_KEY\n";
        fs::write(&p, before).unwrap();
        assert!(edit_refs_lines(&p, &[]).unwrap().is_empty());
        assert_eq!(fs::read_to_string(&p).unwrap(), before);
        // No temp file left behind in the manifest directory.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn prune_keeps_the_manifest_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        fs::write(&p, "GONE=name:GONE\nOPENAI_API_KEY=name:OPENAI_API_KEY\n").unwrap();
        let mut perms = fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&p, perms).unwrap();

        assert_eq!(
            edit_refs_lines(&p, &[("GONE=name:GONE".to_string(), RefEdit::Remove)])
                .unwrap()
                .len(),
            1
        );
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "prune widened the manifest to {mode:o}");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    // ---- source UUIDs on generated lines (issue #82, ADR-0004) ----

    #[test]
    fn an_annotation_needs_whitespace_and_a_hash_to_start() {
        // No Bitwarden reference form contains whitespace, so ` #` is an
        // unambiguous end-of-reference marker.
        assert_eq!(
            split_annotation("name:FOO # uuid:11111111-1111-1111-1111-111111111111"),
            (
                "name:FOO",
                Some("uuid:11111111-1111-1111-1111-111111111111")
            )
        );
        assert_eq!(
            split_annotation("name:FOO\t# note"),
            ("name:FOO", Some("note"))
        );
        // A `#` welded to the reference is part of it: a Bitwarden key may hold
        // one, and guessing otherwise would resolve the wrong secret.
        assert_eq!(split_annotation("name:FOO#BAR"), ("name:FOO#BAR", None));
        assert_eq!(split_annotation("name:FOO"), ("name:FOO", None));
    }

    #[test]
    fn a_recorded_uuid_is_read_out_of_the_annotation() {
        let u = "11111111-1111-1111-1111-111111111111";
        assert_eq!(recorded_uuid(&format!("name:FOO # uuid:{u}")), Some(u));
        // Prose in the comment is not a recording.
        assert_eq!(recorded_uuid("name:FOO # hand pinned, do not touch"), None);
        // Not a UUID, so not a recording.
        assert_eq!(recorded_uuid("name:FOO # uuid:nope"), None);
        // Invariant 4: a placeholder records nothing, so it can never be the
        // evidence that makes a line a rename.
        assert_eq!(
            recorded_uuid("name:FOO # uuid:00000000-0000-0000-0000-000000000000"),
            None
        );
    }

    #[test]
    fn split_glued_line_recovers_the_0_3_0_refresh_blob() {
        // The exact shape that landed on disk: one physical line, 13 mappings.
        let line = "META_AI_API_KEY=name:META_AI_API_KEYFIREWORKS_API_KEY=name:FIREWORKS_API_KEYELEVENLABS_API_KEY=name:ELEVENLABS_API_KEYMUREKA_API_KEY=name:MUREKA_API_KEYGEMINI_API_KEY=name:GEMINI_API_KEYASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEYANTHROPIC_API_KEY=name:ANTHROPIC_API_KEYBASETEN_API_KEY=name:BASETEN_API_KEYTOGETHER_AI_API_KEY=name:TOGETHER_AI_API_KEYDEEPINFRA_API_KEY=name:DEEPINFRA_API_KEYGROQ_API_KEY=name:GROQ_API_KEYHUME_API_KEY=name:HUME_API_KEYHUME_SECRET_KEY=name:HUME_SECRET_KEY";
        let parts = split_glued_bitwarden_line(line).expect("glued");
        assert_eq!(
            parts,
            vec![
                "META_AI_API_KEY=name:META_AI_API_KEY",
                "FIREWORKS_API_KEY=name:FIREWORKS_API_KEY",
                "ELEVENLABS_API_KEY=name:ELEVENLABS_API_KEY",
                "MUREKA_API_KEY=name:MUREKA_API_KEY",
                "GEMINI_API_KEY=name:GEMINI_API_KEY",
                "ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY",
                "ANTHROPIC_API_KEY=name:ANTHROPIC_API_KEY",
                "BASETEN_API_KEY=name:BASETEN_API_KEY",
                "TOGETHER_AI_API_KEY=name:TOGETHER_AI_API_KEY",
                "DEEPINFRA_API_KEY=name:DEEPINFRA_API_KEY",
                "GROQ_API_KEY=name:GROQ_API_KEY",
                "HUME_API_KEY=name:HUME_API_KEY",
                "HUME_SECRET_KEY=name:HUME_SECRET_KEY",
            ]
        );
        assert!(split_glued_bitwarden_line("OPENAI_API_KEY=name:OPENAI_API_KEY").is_none());
    }

    #[test]
    fn a_renamed_secret_is_a_rename_and_not_a_dangling_ref() {
        let u = "00000000-0000-0000-0000-000000000001";
        let secrets = BwListing::new(vec![BwSecret::new(u, "ASSEMBLY_AI_API_KEY", "tools")]);
        let text = format!("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY # uuid:{u}\n");
        let scan = scan_bitwarden_refs(&text, &secrets);
        assert_eq!(scan.len(), 1);
        assert_eq!(scan[0].fate, RefFate::Renamed);
        assert_eq!(scan[0].renamed_to.as_deref(), Some("ASSEMBLY_AI_API_KEY"));
        // The repair keeps the VAR, so a harness `alias =` reading it survives.
        assert_eq!(
            scan[0].repaired_line().unwrap(),
            format!("ASSEMBLY_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{u}")
        );
    }

    #[test]
    fn without_a_recorded_uuid_a_rename_is_still_only_dangling() {
        // No backfill (ADR-0004): lines already on disk carry no UUID, so they
        // keep exactly the behaviour ADR-0003 gave them.
        let secrets = BwListing::new(vec![BwSecret::new(
            "00000000-0000-0000-0000-000000000001",
            "ASSEMBLY_AI_API_KEY",
            "tools",
        )]);
        let scan = scan_bitwarden_refs("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY\n", &secrets);
        assert_eq!(scan[0].fate, RefFate::Dangling);
    }

    #[test]
    fn a_recorded_uuid_the_token_cannot_see_leaves_the_line_dangling() {
        // The secret is gone, not renamed. Deletion is still prune's case.
        let secrets = BwListing::new(vec![BwSecret::new(
            "00000000-0000-0000-0000-000000000009",
            "OPENAI_API_KEY",
            "tools",
        )]);
        let text = "GONE=name:GONE # uuid:00000000-0000-0000-0000-000000000001\n";
        let scan = scan_bitwarden_refs(text, &secrets);
        assert_eq!(scan[0].fate, RefFate::Dangling);
    }

    #[test]
    fn a_resolvable_line_is_never_a_rename_even_with_a_stale_recording() {
        // Two secrets, and the line resolves. Nothing is broken, so refresh has
        // no business editing it — `validate` stays silent about the mismatch
        // too, because the launch works (ADR-0004).
        let secrets = BwListing::new(vec![
            BwSecret::new("00000000-0000-0000-0000-000000000001", "A_KEY", "tools"),
            BwSecret::new("00000000-0000-0000-0000-000000000002", "B_KEY", "tools"),
        ]);
        let text = "A=name:A_KEY # uuid:00000000-0000-0000-0000-000000000002\n";
        let scan = scan_bitwarden_refs(text, &secrets);
        assert_eq!(scan[0].fate, RefFate::Resolvable);
        assert!(scan[0].repaired_line().is_none());
    }

    #[test]
    fn one_write_applies_a_removal_and_a_repair_together() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        let u = "00000000-0000-0000-0000-000000000001";
        let before = format!(
            "# operator header\n\
             \n\
             PINNED=00000000-0000-0000-0000-000000000099\n\
             ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY # uuid:{u}\n\
             GONE=name:GONE\n"
        );
        fs::write(&p, &before).unwrap();
        let repaired = format!("ASSEMBLY_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{u}");
        let edits = vec![
            (
                format!("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY # uuid:{u}"),
                RefEdit::Rewrite(repaired.clone()),
            ),
            ("GONE=name:GONE".to_string(), RefEdit::Remove),
        ];
        let applied = edit_refs_lines(&p, &edits).unwrap();
        assert_eq!(applied.len(), 2);
        assert_eq!(
            fs::read_to_string(&p).unwrap(),
            format!(
                "# operator header\n\
                 \n\
                 PINNED=00000000-0000-0000-0000-000000000099\n\
                 {repaired}\n"
            ),
            "every byte it did not have to change must survive"
        );
    }

    /// `db.example.com` expanded with one `password` field; `github token`
    /// listed but never expanded.
    fn op_listing() -> OpListing {
        let mut l = OpListing::from_json(
            r#"[
              {"id":"id-host","title":"db.example.com","vault":{"id":"v","name":"Orchestrator"}},
              {"id":"id-other","title":"github token","vault":{"id":"v","name":"Orchestrator"}}
            ]"#,
        )
        .unwrap();
        l.expand(
            "id-host",
            r#"{"fields":[{"id":"f1","label":"password","type":"CONCEALED","value":"a"}]}"#,
        )
        .unwrap();
        l
    }

    fn fate(reference: &str) -> RefFate {
        let scan = scan_op_refs(&format!("VAR={reference}\n"), &op_listing());
        assert_eq!(scan.len(), 1);
        scan[0].fate
    }

    #[test]
    fn an_op_fate_is_the_listing_lookup_read_off() {
        assert_eq!(
            fate("op://Orchestrator/db.example.com/password"),
            RefFate::Resolvable
        );
        assert_eq!(
            fate("op://Orchestrator/vanished/password"),
            RefFate::Dangling
        );
        assert_eq!(
            fate("op://Orchestrator/db.example.com/api-key"),
            RefFate::Dangling
        );
        assert_eq!(
            fate("op://Orchestrator/github token/api-key"),
            RefFate::Unchecked
        );
        assert_eq!(fate("us-east-1"), RefFate::Unjudged);
        assert_eq!(
            fate("op://Orchestrator/db-admin (rw)/password"),
            RefFate::Unjudged
        );
        assert_eq!(
            fate("op://Orchestrator/YOUR_ITEM/password"),
            RefFate::Unjudged
        );
        // Read as the launch reads it: quotes gone.
        assert_eq!(
            fate("'op://Orchestrator/db.example.com/password'"),
            RefFate::Resolvable
        );
    }

    // ---- quoted and multi-line entries (issue #112) ----

    #[test]
    fn a_quoted_bitwarden_ref_is_judged_by_its_unquoted_value() {
        // Validate and resolve read `A="name:KEY"` as `name:KEY`; refresh must too.
        let scan = scan_bitwarden_refs("A=\"name:ASSEMBLY_AI_API_KEY\"\n", &listing());
        assert_eq!(scan.len(), 1);
        assert_eq!(scan[0].fate, RefFate::Resolvable);
        assert_eq!(scan[0].reference, "name:ASSEMBLY_AI_API_KEY");

        let scan = scan_bitwarden_refs("A=\"name:GONE\"\n", &listing());
        assert_eq!(scan[0].fate, RefFate::Dangling);
        assert_eq!(scan[0].line, "A=\"name:GONE\"");
    }

    #[test]
    fn a_double_quoted_multiline_value_hides_mapping_lines_inside_it() {
        // The launch reads all three lines as A's value. A `B=` mapping must not
        // appear, or prune could cut a line out of the middle of A.
        let text = "A=\"x\nB=op://V/gone/f\n\"\n";
        let scan = scan_op_refs(text, &op_listing());
        let vars: Vec<&str> = scan.iter().map(|r| r.var.as_str()).collect();
        assert_eq!(vars, ["A"]);
        assert_eq!(scan[0].fate, RefFate::Unjudged);
    }

    #[test]
    fn edits_never_touch_a_line_inside_a_multiline_value() {
        // Even an edit naming that exact text: the line is part of A.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("op.refs");
        let before = "A=\"x\nB=op://V/gone/f\n\"\n";
        fs::write(&p, before).unwrap();
        let applied = edit_refs_lines(&p, &[("B=op://V/gone/f".into(), RefEdit::Remove)]).unwrap();
        assert!(applied.is_empty(), "{applied:?}");
        assert_eq!(fs::read_to_string(&p).unwrap(), before);
    }
}
