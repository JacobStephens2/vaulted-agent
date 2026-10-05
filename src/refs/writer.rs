//! The Refs file writer: the one place a Refs file is merged into or replaced.
//!
//! `refresh` and `setup bitwarden` hand it a target, the mappings they
//! generated, a write mode and a Backend style. What differs between Backends —
//! the header, how "already mapped" is recognised, glued-line recovery and
//! `# exclude:` directives — is decided here, so a fix like #80's lands for
//! both at once. Every write goes through File replace (`replace_refs_file`): a
//! truncated manifest is an install that launches nothing.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use super::{
    key_to_var, name_line, read_exclusions, recorded_uuid, replace_refs_file, split_annotation,
    split_glued_bitwarden_line, EXCLUDE_KEYWORD,
};
use crate::bitwarden::{BwListing, BwRef, BwSecret};
use crate::error::{Error, Result};
use crate::onepassword::OpRef;

/// Merge into what is there, or regenerate the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Append only what the file does not already map.
    Merge,
    /// Rewrite the file from the mappings given.
    Replace,
}

impl WriteMode {
    /// The mode a run writes with: the one asked for, otherwise replace when
    /// the file does not exist yet and merge when it does.
    pub fn settle(asked: Option<WriteMode>, path: &Path) -> WriteMode {
        asked.unwrap_or(if path.is_file() {
            WriteMode::Merge
        } else {
            WriteMode::Replace
        })
    }
}

/// Which Backend's Refs file is being written.
#[derive(Debug, Clone, Copy)]
pub enum RefsStyle<'a> {
    /// Glued 0.3.0 lines are split on merge.
    Bitwarden,
    /// Exclusion patterns are carried on replace and recorded on merge.
    OnePassword { exclusions: &'a [String] },
}

/// What a secret a mapping points at is, for the "already mapped?" check.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Identity {
    Bitwarden(BwSecret),
    OnePassword { reference: String },
}

/// One generated mapping: the variable it claims, the exact line to write and
/// the secret it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    var: String,
    line: String,
    identity: Identity,
}

impl Mapping {
    /// A Bitwarden secret's mapping, carrying its source recording (ADR-0004).
    pub fn bitwarden(secret: &BwSecret) -> Mapping {
        let (id, key) = (secret.id.as_str(), secret.key.as_str());
        let shaped = !key.is_empty()
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-'));
        let (var, line) = if shaped {
            // The recording is what makes a later rename reportable rather than
            // a dangling ref plus an unrelated-looking new line (ADR-0004). The
            // UUID-form fallback below already carries the identity in the value.
            let var = key_to_var(key);
            let line = name_line(&var, key, id);
            (var, line)
        } else {
            ("SECRET".to_string(), format!("SECRET={id}"))
        };
        Mapping {
            var,
            line,
            identity: Identity::Bitwarden(secret.clone()),
        }
    }

    /// Mappings for the selected secrets of a `bws` listing, in listing order.
    /// `None` selects every secret.
    pub fn bitwarden_selection(listing: &BwListing, indices: Option<&[usize]>) -> Vec<Mapping> {
        listing
            .secrets()
            .iter()
            .enumerate()
            .filter(|(i, _)| indices.is_none_or(|sel| sel.contains(i)))
            .map(|(_, secret)| Mapping::bitwarden(secret))
            .collect()
    }

    /// A 1Password field's mapping under the variable refresh derived for it.
    pub fn onepassword(var: &str, reference: &str) -> Mapping {
        Mapping {
            var: var.to_string(),
            line: format!("{var}={reference}"),
            identity: Identity::OnePassword {
                reference: reference.to_string(),
            },
        }
    }

    /// True when the Refs file text already maps this mapping's secret, under
    /// any variable.
    fn already_mapped(&self, text: &str) -> bool {
        match &self.identity {
            Identity::Bitwarden(secret) => text_has_secret(text, secret),
            Identity::OnePassword { reference } => text_has_reference(text, reference),
        }
    }
}

/// What one write did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RefsWrite {
    /// Mapping lines written: every line on replace, only new ones on merge.
    pub added: usize,
    /// Mappings split out of a 0.3.0 glued line (Bitwarden merge only).
    pub recovered: usize,
    /// Exclusion patterns the file did not record before this write.
    pub recorded: usize,
}

/// Write `mappings` into the Refs file at `path`.
///
/// Replace keeps the first mapping per variable. Merge appends only mappings
/// whose secret the file does not already map, under a variable neither the
/// file nor an earlier mapping in this run claims (story #14), and reuses a
/// trailing separator from the same `source` (#80). A merge that changes
/// nothing leaves the file untouched; into a missing or empty file it writes
/// what replace would.
///
/// An existing file keeps its mode; a new one is 0644.
pub fn write_refs(
    path: &Path,
    mappings: &[Mapping],
    mode: WriteMode,
    style: RefsStyle,
    source: &str,
) -> Result<RefsWrite> {
    let existing = if path.is_file() {
        fs::read_to_string(path).map_err(|e| Error::Io {
            path: path.to_path_buf(),
            source: e,
        })?
    } else {
        String::new()
    };
    let exclusions = match style {
        RefsStyle::Bitwarden => &[][..],
        RefsStyle::OnePassword { exclusions } => exclusions,
    };
    let already = read_exclusions(&existing);
    let fresh: Vec<String> = exclusions
        .iter()
        .filter(|p| !already.contains(*p))
        .cloned()
        .collect();

    if mode == WriteMode::Replace || existing.trim().is_empty() {
        let (body, added) = replace_body(mappings, style, source);
        // A merge that maps nothing leaves even an empty file alone.
        if mode == WriteMode::Merge && added == 0 && fresh.is_empty() {
            return Ok(RefsWrite::default());
        }
        replace_refs_file(path, &body)?;
        return Ok(RefsWrite {
            added,
            recovered: 0,
            recorded: fresh.len(),
        });
    }

    let (existing, recovered) = match style {
        RefsStyle::Bitwarden => split_glued_bitwarden_text(&existing),
        RefsStyle::OnePassword { .. } => (existing, 0),
    };
    let mut new_lines = String::new();
    let mut added = 0usize;
    // Variables claimed earlier in this run; the file's own are checked by
    // `text_has_var`.
    let mut claimed = HashSet::new();
    for m in mappings {
        if m.already_mapped(&existing) {
            continue;
        }
        // Story #14: never append a second mapping under a VAR the operator
        // already pinned.
        if text_has_var(&existing, &m.var) || !claimed.insert(m.var.as_str()) {
            continue;
        }
        new_lines.push_str(&m.line);
        new_lines.push('\n');
        added += 1;
    }
    if added == 0 && recovered == 0 && fresh.is_empty() {
        return Ok(RefsWrite::default());
    }
    // Patterns given on this run and not yet written down are recorded even
    // when nothing was added, so `--exclude` takes effect on the next refresh
    // rather than only on one that happened to find new fields.
    let block = format!("{}{new_lines}", exclusion_lines(&fresh));
    let body = if block.is_empty() {
        existing
    } else if text_ends_in_banner(&existing, source) {
        // The file already ends in this source's banner, so the new lines
        // belong under it. A fresh banner every run left real installs with a
        // ladder of empty separators (issue #80).
        let mut b = existing;
        if !b.ends_with('\n') {
            b.push('\n');
        }
        b.push_str(&block);
        b
    } else {
        format!("{existing}\n\n{}\n{block}", banner_line(source))
    };
    replace_refs_file(path, &body)?;
    Ok(RefsWrite {
        added,
        recovered,
        recorded: fresh.len(),
    })
}

/// The whole file replace writes, and how many mappings it holds.
fn replace_body(mappings: &[Mapping], style: RefsStyle, source: &str) -> (String, usize) {
    let mut body = match style {
        RefsStyle::Bitwarden => format!(
            "# Bitwarden Secrets Manager refs (no secret values). Generated by {source}.\n\
             # Forms: UUID | uuid:UUID | name:KEY | project:PROJECT/KEY\n\
             # A trailing `# uuid:UUID` records the secret a line was generated from.\n\
             # Update: vaulted-agent refresh\n\
             # Values fetched live at launch.\n"
        ),
        // The form line deliberately does not spell out a literal reference.
        // `op inject` substitutes every reference it finds in the file,
        // comments included, so an illustrative op://VAULT/ITEM/FIELD in this
        // header is read as a real reference and the whole injection dies on
        // "VAULT isn't a vault in this account" - taking every genuine entry
        // below it down too.
        RefsStyle::OnePassword { exclusions } => {
            let mut h = format!(
                "# 1Password refs (no secret values). Generated by {source}.\n\
                 # Form: VAR= a secret reference (vault, item and field, slash separated).\n\
                 # Update: vaulted-agent refresh\n\
                 # Values fetched live at launch.\n"
            );
            // Rewriting the file must not silently re-admit what the operator
            // excluded, so the directives are carried into the new header
            // rather than dropped with the rest of the old content.
            if !exclusions.is_empty() {
                h.push_str("# Names refresh will not map (vaulted-agent refresh --exclude):\n");
                h.push_str(&exclusion_lines(exclusions));
            }
            h
        }
    };
    body.push('\n');
    let mut seen = HashSet::new();
    let mut added = 0usize;
    for m in mappings {
        if !seen.insert(m.var.as_str()) {
            continue;
        }
        body.push_str(&m.line);
        body.push('\n');
        added += 1;
    }
    (body, added)
}

/// True if the refs file already maps this secret: a line whose reference
/// selects it (same id, same key for `name:`, same project and key for
/// `project:`), or whose source recording names its id.
///
/// The reference is parsed as the launch parses it, so `project:P/a/b` maps
/// key `a/b` in project `P`. Listing-free: the secret record is all it needs.
///
/// Reads values as the launch does, so `A="name:KEY"` counts as mapping `KEY`.
fn text_has_secret(text: &str, secret: &BwSecret) -> bool {
    crate::manifest_entry::parse(text).entries.iter().any(|e| {
        let v = e.value.as_str();
        // A recorded UUID is the secret's identity, so a line still mapping it
        // under its old key counts as mapped. Without this the rename would
        // come back as "1 dangling, 1 new" — the outcome ADR-0004 exists to
        // replace.
        (!secret.id.is_empty() && recorded_uuid(v) == Some(secret.id.as_str()))
            || BwRef::parse(split_annotation(v).0).is_some_and(|r| r.selects(secret))
    })
}

/// True if a VAR= line already exists (protects hand-edited custom mappings; story #14).
fn text_has_var(text: &str, var: &str) -> bool {
    crate::manifest_entry::parse(text)
        .entries
        .iter()
        .any(|e| e.var == var)
}

/// A reference reduced to the field it identifies (`OpRef::canonical`), so a
/// generated mapping can be recognised in a manifest an operator wrote by hand.
///
/// Comparing the strings byte for byte instead reports "not present" for a
/// field the manifest already maps under the other form, and merge appends a
/// second mapping under the generated name. On a 60-item vault that was 81
/// duplicate variables, every one of them a live credential in the agent's
/// environment twice.
fn canonical_reference(reference: &str) -> String {
    match OpRef::parse(reference) {
        Some(r) => r.canonical().to_string(),
        None => reference.to_string(),
    }
}

/// True if the refs file already points at this field, under any name and
/// through either the section-qualified or the unqualified form.
fn text_has_reference(text: &str, reference: &str) -> bool {
    let want = canonical_reference(reference);
    crate::manifest_entry::parse(text)
        .entries
        .iter()
        .any(|e| canonical_reference(&e.value) == want)
}

/// Split every glued mapping in a refs file. Unchanged bytes when there is
/// nothing to split, so a healthy merge stays byte-identical.
fn split_glued_bitwarden_text(text: &str) -> (String, usize) {
    let mut recovered = 0usize;
    let mut out = String::new();
    let mut changed = false;
    for (i, line) in text.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if let Some(parts) = split_glued_bitwarden_line(line) {
            recovered += parts.len();
            changed = true;
            out.push_str(&parts.join("\n"));
        } else {
            out.push_str(line);
        }
    }
    if text.ends_with('\n') && !out.ends_with('\n') {
        out.push('\n');
    }
    if changed {
        (out, recovered)
    } else {
        (text.to_string(), 0)
    }
}

/// The separator merge puts above the lines it appends.
///
/// A separator, never an ownership mark: real installs carry operator-written
/// lines above every banner in the file (ADR-0003).
fn banner_line(source: &str) -> String {
    format!("# --- appended by {source} ---")
}

/// True when the file's last section is already this source's banner, so new
/// lines can extend it instead of opening another one.
///
/// Scans upward past mappings, blank lines and the exclusion directives merge
/// records under a banner. Any other comment ends the section: a header an
/// operator wrote below the last banner means the tail of the file is no
/// longer refresh's to append into silently.
fn text_ends_in_banner(text: &str, source: &str) -> bool {
    let banner = banner_line(source);
    for raw in text.lines().rev() {
        let line = raw.trim();
        if line.is_empty() || !read_exclusions(line).is_empty() {
            continue;
        }
        if line == banner {
            return true;
        }
        if line.starts_with('#') || !line.contains('=') {
            return false;
        }
    }
    false
}

/// Directive lines for every pattern.
fn exclusion_lines(patterns: &[String]) -> String {
    patterns
        .iter()
        .map(|p| format!("# {EXCLUDE_KEYWORD} {p}\n"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "test";

    fn op(pairs: &[(&str, &str)]) -> Vec<Mapping> {
        pairs
            .iter()
            .map(|(v, r)| Mapping::onepassword(v, r))
            .collect()
    }

    /// Mappings for secrets in project `tools`.
    fn bw(secrets: &[(&str, &str)]) -> Vec<Mapping> {
        secrets
            .iter()
            .map(|(id, key)| Mapping::bitwarden(&BwSecret::new(id, key, "tools")))
            .collect()
    }

    fn op_style(exclusions: &[String]) -> RefsStyle<'_> {
        RefsStyle::OnePassword { exclusions }
    }

    fn merge(p: &Path, m: &[Mapping], style: RefsStyle) -> RefsWrite {
        write_refs(p, m, WriteMode::Merge, style, SRC).unwrap()
    }

    fn replace(p: &Path, m: &[Mapping], style: RefsStyle) -> RefsWrite {
        write_refs(p, m, WriteMode::Replace, style, SRC).unwrap()
    }

    fn mapping_lines(body: &str) -> Vec<&str> {
        body.lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#') && t.contains('=')
            })
            .collect()
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn mode_defaults_to_replace_when_missing_and_merge_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.refs");
        assert_eq!(WriteMode::settle(None, &p), WriteMode::Replace);
        fs::write(&p, "").unwrap();
        assert_eq!(WriteMode::settle(None, &p), WriteMode::Merge);
        assert_eq!(
            WriteMode::settle(Some(WriteMode::Replace), &p),
            WriteMode::Replace
        );
    }

    #[test]
    fn substring_uuid_in_comment_is_not_a_hit() {
        let text = "# note about 00000000-0000-0000-0000-000000000001\nOPENAI=name:other\n";
        assert!(!text_has_secret(
            text,
            &BwSecret::new(
                "00000000-0000-0000-0000-000000000001",
                "openai-api-key",
                "tools"
            )
        ));
    }

    #[test]
    fn name_ref_line_is_a_hit() {
        let text = "OPENAI_API_KEY=name:openai-api-key\n";
        assert!(text_has_secret(
            text,
            &BwSecret::new("id-x", "openai-api-key", "tools")
        ));
    }

    #[test]
    fn bare_uuid_value_is_a_hit() {
        let text = "X=00000000-0000-0000-0000-000000000099\n";
        assert!(text_has_secret(
            text,
            &BwSecret::new("00000000-0000-0000-0000-000000000099", "anything", "")
        ));
    }

    #[test]
    fn bitwarden_replace_writes_the_header_and_keeps_the_first_mapping_per_var() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        fs::write(&p, "OLD=name:OLD\n").unwrap();
        let out = replace(
            &p,
            &bw(&[("id1", "OPENAI_API_KEY"), ("id2", "openai-api-key")]),
            RefsStyle::Bitwarden,
        );
        assert_eq!(out.added, 1);
        let body = fs::read_to_string(&p).unwrap();
        assert!(body.starts_with(
            "# Bitwarden Secrets Manager refs (no secret values). Generated by test.\n"
        ));
        assert_eq!(
            mapping_lines(&body),
            vec!["OPENAI_API_KEY=name:OPENAI_API_KEY"]
        );
    }

    #[test]
    fn bitwarden_merge_into_a_missing_file_writes_the_replace_header() {
        let dir = tempfile::tempdir().unwrap();
        let merged = dir.path().join("merged.refs");
        let replaced = dir.path().join("replaced.refs");
        let m = bw(&[("id1", "OPENAI_API_KEY")]);
        assert_eq!(merge(&merged, &m, RefsStyle::Bitwarden).added, 1);
        replace(&replaced, &m, RefsStyle::Bitwarden);
        assert_eq!(
            fs::read_to_string(&merged).unwrap(),
            fs::read_to_string(&replaced).unwrap()
        );
    }

    #[test]
    fn op_merge_into_an_empty_file_writes_the_replace_header() {
        let dir = tempfile::tempdir().unwrap();
        let merged = dir.path().join("merged.refs");
        let replaced = dir.path().join("replaced.refs");
        fs::write(&merged, "").unwrap();
        let m = op(&[("A_KEY", "op://V/a/key")]);
        let ex = vec!["*_USERNAME".to_string()];
        merge(&merged, &m, op_style(&ex));
        replace(&replaced, &m, op_style(&ex));
        assert_eq!(
            fs::read_to_string(&merged).unwrap(),
            fs::read_to_string(&replaced).unwrap()
        );
    }

    #[test]
    fn generated_header_carries_no_resolvable_reference() {
        // `op inject` resolves every reference in the file, comments included.
        // An illustrative op://VAULT/ITEM/FIELD in the header is therefore a
        // real lookup that fails, and one failed lookup aborts the injection of
        // the entire manifest. Only lines written by refresh may contain a
        // reference, and every one of those is a genuine entry.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("op.refs");
        replace(
            &p,
            &op(&[("A_KEY", "op://V/anthropic/conductor-api-key")]),
            op_style(&[]),
        );

        for line in fs::read_to_string(&p).unwrap().lines() {
            if line.trim_start().starts_with('#') {
                assert!(
                    !line.contains("op://"),
                    "header comment carries a reference op inject would try to resolve: {line}"
                );
            }
        }
    }

    #[test]
    fn op_merge_skips_references_and_vars_already_present() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("op.refs");

        let entries = op(&[
            ("A_KEY", "op://V/anthropic/conductor-api-key"),
            ("B_KEY", "op://V/github token/tok"),
        ]);
        replace(&p, &entries, op_style(&[]));
        let first = fs::read_to_string(&p).unwrap();
        assert!(first.contains("A_KEY=op://V/anthropic/conductor-api-key"));

        // Same entries again: nothing new.
        assert_eq!(merge(&p, &entries, op_style(&[])).added, 0);
        assert_eq!(fs::read_to_string(&p).unwrap(), first);

        // A new reference under a VAR the operator already pinned is skipped
        // rather than appended as a second mapping.
        let clash = op(&[("A_KEY", "op://V/other/field")]);
        assert_eq!(merge(&p, &clash, op_style(&[])).added, 0);

        // A genuinely new one is appended.
        let fresh = op(&[("C_KEY", "op://V/third/field")]);
        assert_eq!(merge(&p, &fresh, op_style(&[])).added, 1);
        assert!(fs::read_to_string(&p)
            .unwrap()
            .contains("C_KEY=op://V/third/field"));
    }

    #[test]
    fn merge_never_claims_a_var_twice_in_one_run() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("op.refs");
        fs::write(&p, "PINNED=op://V/p/f\n").unwrap();
        let out = merge(
            &p,
            &op(&[("A_KEY", "op://V/a/one"), ("A_KEY", "op://V/a/two")]),
            op_style(&[]),
        );
        assert_eq!(out.added, 1);
        let body = fs::read_to_string(&p).unwrap();
        assert_eq!(
            mapping_lines(&body),
            vec!["PINNED=op://V/p/f", "A_KEY=op://V/a/one"]
        );
    }

    #[test]
    fn merge_skips_when_var_already_mapped_to_different_ref() {
        // Would produce OPENAI_API_KEY=name:openai.api.key — must not append.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        let before = "OPENAI_API_KEY=uuid:00000000-0000-0000-0000-000000000009\n";
        fs::write(&p, before).unwrap();
        let m = bw(&[("other-id", "openai.api.key")]);
        assert_eq!(m[0].var, "OPENAI_API_KEY");
        assert!(!m[0].already_mapped(before));
        assert_eq!(merge(&p, &m, RefsStyle::Bitwarden).added, 0);
        assert_eq!(fs::read_to_string(&p).unwrap(), before);
    }

    #[test]
    fn merge_recognises_a_field_the_operator_mapped_without_the_section() {
        // The duplicate that started this: a curated GH_ETA_FACTORY_APP_ID and
        // a generated ETA_FACTORY_GITHUB_APP_ADD_MORE_APP_ID are one field, and
        // comparing reference strings byte for byte saw two. Every such pair
        // reached the agent as the same credential under two names.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("op.refs");
        fs::write(
            &p,
            "GH_ETA_FACTORY_APP_ID=op://Orchestrator/eta-factory-github-app/app-id\n",
        )
        .unwrap();

        let generated = op(&[(
            "ETA_FACTORY_GITHUB_APP_APP_ID",
            "op://Orchestrator/eta-factory-github-app/add more/app-id",
        )]);
        assert_eq!(merge(&p, &generated, op_style(&[])).added, 0);
        assert!(!fs::read_to_string(&p).unwrap().contains("add more"));

        // The reverse direction too: a curated section-qualified line already
        // covers the unqualified form of the same field.
        let q = dir.path().join("q.refs");
        fs::write(&q, "PINNED=op://V/item/add more/app-id\n").unwrap();
        let plain = op(&[("ITEM_APP_ID", "op://V/item/app-id")]);
        assert_eq!(merge(&q, &plain, op_style(&[])).added, 0);

        // A genuinely different field on the same item is still added.
        let other = op(&[("ITEM_TOKEN", "op://V/item/add more/token")]);
        assert_eq!(merge(&q, &other, op_style(&[])).added, 1);
        // An operator-named section is not a default one, so it is not folded
        // away and two such fields stay distinct.
        assert_eq!(
            canonical_reference("op://V/host/mysql/password"),
            "op://V/host/mysql/password"
        );
    }

    #[test]
    fn exclusions_survive_both_modes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("op.refs");
        let entries = op(&[("A_KEY", "op://V/anthropic/key")]);
        let ex = vec!["*_USERNAME".to_string()];

        // Replace rewrites the file, and must not drop the operator's patterns
        // along with the content: the next refresh would re-admit everything.
        replace(&p, &entries, op_style(&ex));
        assert_eq!(read_exclusions(&fs::read_to_string(&p).unwrap()), ex);

        // Merge records a pattern first seen on this run even when it found no
        // new mappings, so --exclude takes effect on a run that happens to add
        // nothing.
        let more = vec!["*_USERNAME".to_string(), "ZOOM_*".to_string()];
        let out = merge(&p, &entries, op_style(&more));
        assert_eq!((out.added, out.recorded), (0, 1));
        assert_eq!(read_exclusions(&fs::read_to_string(&p).unwrap()), more);

        // Recorded once, not appended again on every subsequent run.
        let before = fs::read_to_string(&p).unwrap();
        assert_eq!(merge(&p, &entries, op_style(&more)), RefsWrite::default());
        assert_eq!(fs::read_to_string(&p).unwrap(), before);
    }

    #[test]
    fn op_merge_twice_reuses_one_separator() {
        // The #80 rule, which 1Password never received: a merge whose file
        // already ends in this source's separator appends under it.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("op.refs");
        fs::write(&p, "PINNED=op://V/p/f\n").unwrap();
        merge(&p, &op(&[("A_KEY", "op://V/a/key")]), op_style(&[]));
        // An exclusion recorded under the separator does not end its section.
        let ex = vec!["ZOOM_*".to_string()];
        merge(&p, &op(&[]), op_style(&ex));
        merge(&p, &op(&[("B_KEY", "op://V/b/key")]), op_style(&ex));

        let body = fs::read_to_string(&p).unwrap();
        assert_eq!(
            body.matches("# --- appended by test ---").count(),
            1,
            "{body}"
        );
        assert_eq!(
            mapping_lines(&body),
            vec![
                "PINNED=op://V/p/f",
                "A_KEY=op://V/a/key",
                "B_KEY=op://V/b/key"
            ],
            "{body}"
        );
        assert_eq!(read_exclusions(&body), ex);
    }

    #[test]
    fn merge_does_not_stack_a_banner_on_every_run() {
        // A real install grew one banner and two blank lines per refresh
        // (issue #80). The banner is a separator, so one is enough.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        fs::write(&p, "OPERATOR_PINNED=name:PINNED\n").unwrap();

        let first = bw(&[("id1", "OPENAI_API_KEY")]);
        assert_eq!(merge(&p, &first, RefsStyle::Bitwarden).added, 1);
        let second = bw(&[("id2", "META_AI_API_KEY")]);
        assert_eq!(merge(&p, &second, RefsStyle::Bitwarden).added, 1);

        let body = fs::read_to_string(&p).unwrap();
        assert_eq!(
            body.matches("# --- appended by test ---").count(),
            1,
            "{body}"
        );
        // `contains` would pass if both mappings were glued onto one line, which
        // is the 0.3.0 bash refresh bug. Each mapping has to be its own line.
        assert_eq!(
            mapping_lines(&body),
            vec![
                "OPERATOR_PINNED=name:PINNED",
                "OPENAI_API_KEY=name:OPENAI_API_KEY",
                "META_AI_API_KEY=name:META_AI_API_KEY",
            ],
            "{body}"
        );
        // The operator's line is still above the separator, untouched.
        assert!(body.starts_with("OPERATOR_PINNED=name:PINNED\n"), "{body}");
    }

    #[test]
    fn merge_opens_a_new_banner_below_an_operator_header() {
        // A comment the operator wrote after the last banner ends refresh's
        // section: appending into it would put mappings under someone else's
        // heading. Existing banners are never collapsed retroactively.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        fs::write(
            &p,
            "# --- appended by test ---\nA=name:A\n\n# operator: staging keys below\nB=name:B\n",
        )
        .unwrap();
        assert_eq!(
            merge(&p, &bw(&[("id", "NEW_KEY")]), RefsStyle::Bitwarden).added,
            1
        );
        let body = fs::read_to_string(&p).unwrap();
        assert_eq!(
            body.matches("# --- appended by test ---").count(),
            2,
            "{body}"
        );
    }

    #[test]
    fn generated_lines_record_the_source_uuid() {
        let u = "11111111-1111-1111-1111-111111111111";
        assert_eq!(
            Mapping::bitwarden(&BwSecret::new(u, "ASSEMBLY_AI_API_KEY", "")).line,
            format!("ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{u}")
        );
        // The UUID-form fallback already carries the identity.
        assert_eq!(
            Mapping::bitwarden(&BwSecret::new(u, "has spaces", "")).line,
            format!("SECRET={u}")
        );

        // And the recording reaches the file on both modes.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        fs::write(&p, "PINNED=name:P\n").unwrap();
        let m = bw(&[(u, "ASSEMBLY_AI_API_KEY")]);
        merge(&p, &m, RefsStyle::Bitwarden);
        let recorded = format!("ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{u}\n");
        assert!(fs::read_to_string(&p).unwrap().contains(&recorded));
        replace(&p, &m, RefsStyle::Bitwarden);
        assert!(fs::read_to_string(&p).unwrap().contains(&recorded));
    }

    #[test]
    fn a_merge_that_maps_nothing_leaves_an_empty_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        fs::write(&p, "").unwrap();
        assert_eq!(merge(&p, &[], RefsStyle::Bitwarden), RefsWrite::default());
        assert_eq!(fs::read_to_string(&p).unwrap(), "");
        let missing = dir.path().join("missing.refs");
        assert_eq!(merge(&missing, &[], op_style(&[])), RefsWrite::default());
        assert!(!missing.exists());
    }

    #[test]
    fn selection_keeps_listing_order_and_honours_indices() {
        let secrets = BwListing::new(vec![
            BwSecret::new("id0", "A", ""),
            BwSecret::new("id1", "B", ""),
            BwSecret::new("id2", "C", ""),
        ]);
        let vars = |m: Vec<Mapping>| m.into_iter().map(|m| m.var).collect::<Vec<_>>();
        assert_eq!(
            vars(Mapping::bitwarden_selection(&secrets, None)),
            ["A", "B", "C"]
        );
        assert_eq!(
            vars(Mapping::bitwarden_selection(&secrets, Some(&[2, 0]))),
            ["A", "C"]
        );
    }

    #[test]
    fn merge_sees_a_secret_still_mapped_under_its_old_key() {
        // The whole point of the recording: after a vault-side rename the old
        // line is the same secret, so merge must not append a second mapping
        // for it. "1 dangling, 1 new" becomes "1 renamed".
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        let u = "00000000-0000-0000-0000-000000000001";
        fs::write(
            &p,
            format!("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY # uuid:{u}\n"),
        )
        .unwrap();
        let out = merge(&p, &bw(&[(u, "ASSEMBLY_AI_API_KEY")]), RefsStyle::Bitwarden);
        assert_eq!(out.added, 0, "{}", fs::read_to_string(&p).unwrap());
    }

    #[test]
    fn merge_recognises_every_bitwarden_form() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        let before = "\
            A=00000000-0000-0000-0000-00000000000a\n\
            B=uuid:00000000-0000-0000-0000-00000000000b\n\
            C=name:KEY_C\n\
            D=project:tools/KEY_D\n";
        fs::write(&p, before).unwrap();
        let m = bw(&[
            ("00000000-0000-0000-0000-00000000000a", "KEY_A"),
            ("00000000-0000-0000-0000-00000000000b", "KEY_B"),
            ("id-c", "KEY_C"),
            ("id-d", "KEY_D"),
        ]);
        assert_eq!(merge(&p, &m, RefsStyle::Bitwarden), RefsWrite::default());
        assert_eq!(fs::read_to_string(&p).unwrap(), before);
    }

    #[test]
    fn a_key_containing_a_slash_is_already_mapped_by_its_project_ref() {
        // `refresh` generates this shape. Splitting on the last `/` read the
        // key as `b`, missed the mapping and appended a duplicate.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        let before = "AB=project:P/a/b\n";
        fs::write(&p, before).unwrap();
        let m = [Mapping::bitwarden(&BwSecret::new("id-ab", "a/b", "P"))];
        assert_eq!(merge(&p, &m, RefsStyle::Bitwarden), RefsWrite::default());
        assert_eq!(fs::read_to_string(&p).unwrap(), before);
    }

    #[test]
    fn a_mapping_into_another_project_does_not_block_this_one() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        fs::write(&p, "Q_SHARED=project:Q/SHARED\n").unwrap();
        let m = [Mapping::bitwarden(&BwSecret::new("id-p", "SHARED", "P"))];
        assert_eq!(merge(&p, &m, RefsStyle::Bitwarden).added, 1);
        assert!(fs::read_to_string(&p)
            .unwrap()
            .contains("SHARED=name:SHARED"));
    }

    #[test]
    fn merge_splits_a_glued_line_even_when_every_secret_looks_already_mapped() {
        // Substring search on the glued line matches `name:META_AI_API_KEY`
        // inside the blob, so merge used to report "nothing to add" and leave
        // the file broken. Repair has to run first, and has to write even
        // when added == 0.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        fs::write(
            &p,
            "OPENAI_API_KEY=name:OPENAI_API_KEY\n\
             META_AI_API_KEY=name:META_AI_API_KEYFIREWORKS_API_KEY=name:FIREWORKS_API_KEY\n",
        )
        .unwrap();
        let secrets = bw(&[
            ("id-o", "OPENAI_API_KEY"),
            ("id-m", "META_AI_API_KEY"),
            ("id-f", "FIREWORKS_API_KEY"),
        ]);
        let out = merge(&p, &secrets, RefsStyle::Bitwarden);
        assert_eq!(out.added, 0, "already mapped once split");
        assert_eq!(out.recovered, 2, "{out:?}");
        let body = fs::read_to_string(&p).unwrap();
        assert_eq!(
            mapping_lines(&body),
            vec![
                "OPENAI_API_KEY=name:OPENAI_API_KEY",
                "META_AI_API_KEY=name:META_AI_API_KEY",
                "FIREWORKS_API_KEY=name:FIREWORKS_API_KEY",
            ],
            "{body}"
        );
    }

    #[test]
    fn bitwarden_merge_does_not_duplicate_a_quoted_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        let before = "MINE=\"name:ASSEMBLY_AI_API_KEY\"\n";
        fs::write(&p, before).unwrap();
        let m = bw(&[(
            "ea6db86f-0000-0000-0000-000000000001",
            "ASSEMBLY_AI_API_KEY",
        )]);
        assert_eq!(merge(&p, &m, RefsStyle::Bitwarden).added, 0);
        assert_eq!(fs::read_to_string(&p).unwrap(), before);
    }

    #[test]
    fn op_merge_does_not_duplicate_a_quoted_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("op.refs");
        let before = "MINE='op://Orchestrator/db.example.com/password'\n";
        fs::write(&p, before).unwrap();
        let m = op(&[(
            "DB_EXAMPLE_COM_PASSWORD",
            "op://Orchestrator/db.example.com/password",
        )]);
        assert_eq!(merge(&p, &m, op_style(&[])).added, 0);
        assert_eq!(fs::read_to_string(&p).unwrap(), before);
    }

    #[test]
    fn a_quoted_variable_is_already_claimed() {
        assert!(text_has_var("A=\"name:X\"\n", "A"));
        // A line inside a multi-line value is not a variable of its own.
        assert!(!text_has_var("A=\"x\nB=1\n\"\n", "B"));
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_mode_survives_merge_and_replace_on_both_backends() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cases: [(&str, Vec<Mapping>, RefsStyle); 2] = [
            ("bws.refs", bw(&[("id1", "NEW_KEY")]), RefsStyle::Bitwarden),
            ("op.refs", op(&[("NEW_KEY", "op://V/n/k")]), op_style(&[])),
        ];
        for (name, m, style) in cases {
            let p = dir.path().join(name);
            fs::write(&p, "PINNED=name:P\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
            assert_eq!(merge(&p, &m, style).added, 1);
            assert_eq!(mode_of(&p), 0o640, "{name} after merge");
            replace(&p, &m, style);
            assert_eq!(mode_of(&p), 0o640, "{name} after replace");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_new_file_is_0644_on_both_backends_and_modes() {
        let dir = tempfile::tempdir().unwrap();
        let cases: [(&str, WriteMode, Vec<Mapping>, RefsStyle); 4] = [
            (
                "bm",
                WriteMode::Merge,
                bw(&[("id", "K")]),
                RefsStyle::Bitwarden,
            ),
            (
                "br",
                WriteMode::Replace,
                bw(&[("id", "K")]),
                RefsStyle::Bitwarden,
            ),
            (
                "om",
                WriteMode::Merge,
                op(&[("K", "op://V/i/f")]),
                op_style(&[]),
            ),
            (
                "or",
                WriteMode::Replace,
                op(&[("K", "op://V/i/f")]),
                op_style(&[]),
            ),
        ];
        for (name, mode, m, style) in cases {
            let p = dir.path().join(name);
            write_refs(&p, &m, mode, style, SRC).unwrap();
            assert_eq!(mode_of(&p), 0o644, "{name}");
        }
    }

    #[test]
    fn no_temp_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.refs");
        replace(&p, &bw(&[("id1", "A")]), RefsStyle::Bitwarden);
        merge(&p, &bw(&[("id2", "B")]), RefsStyle::Bitwarden);
        let ex = vec!["Z_*".to_string()];
        let q = dir.path().join("y.refs");
        replace(&q, &op(&[("A", "op://V/a/f")]), op_style(&[]));
        merge(&q, &op(&[]), op_style(&ex));
        let mut names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["x.refs", "y.refs"]);
    }
}
