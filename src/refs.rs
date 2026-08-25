//! Bitwarden refs file write / merge (setup + refresh).

use std::fs;
use std::path::Path;

use crate::error::{Error, Result};

pub fn key_to_var(key: &str) -> String {
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

pub fn line_for_secret(id: &str, key: &str) -> String {
    if !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '/' || c == '-')
    {
        // The recording is what makes a later rename reportable rather than a
        // dangling ref plus an unrelated-looking new line (ADR-0004). The
        // UUID-form fallback below already carries the identity in the value.
        format!("{}\n", name_line(&key_to_var(key), key, id))
    } else {
        format!("SECRET={id}\n")
    }
}

fn var_from_line(line: &str) -> Option<&str> {
    line.split_once('=').map(|(k, _)| k.trim())
}

/// True if the refs file already maps this secret by reference (id / name:KEY / project:…/KEY).
fn text_has_secret(text: &str, id: &str, key: &str) -> bool {
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let Some((_, v)) = line.split_once('=') else {
            continue;
        };
        let (r, _) = split_annotation(v.trim());
        // A recorded UUID is the secret's identity, so a line still mapping it
        // under its old key counts as mapped. Without this the rename would
        // come back as "1 dangling, 1 new" — the outcome ADR-0004 exists to
        // replace.
        if !id.is_empty() && recorded_uuid(v) == Some(id) {
            return true;
        }
        if !id.is_empty() && (r == id || r == format!("uuid:{id}")) {
            return true;
        }
        if !key.is_empty() {
            if r == format!("name:{key}") {
                return true;
            }
            // project:PROJECT/KEY also counts as mapped for this key
            if let Some(rest) = r.strip_prefix("project:") {
                if rest.rsplit_once('/').map(|(_, s)| s) == Some(key) {
                    return true;
                }
            }
        }
    }
    false
}

/// True if a VAR= line already exists (protects hand-edited custom mappings; story #14).
fn text_has_var(text: &str, var: &str) -> bool {
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || !line.contains('=') {
            continue;
        }
        if var_from_line(line) == Some(var) {
            return true;
        }
    }
    false
}

pub fn write_refs_replace(
    path: &Path,
    secrets: &[(String, String, String)],
    indices: Option<&[usize]>,
    source: &str,
) -> Result<()> {
    let mut body = format!(
        "# Bitwarden Secrets Manager refs (no secret values). Generated by {source}.\n\
         # Forms: UUID | uuid:UUID | name:KEY | project:PROJECT/KEY\n\
         # A trailing `# uuid:UUID` records the secret a line was generated from.\n\
         # Update: vaulted-agent refresh\n\
         # Values fetched live at launch.\n\n"
    );
    let mut seen_vars = std::collections::HashSet::new();
    for (i, (id, key, _)) in secrets.iter().enumerate() {
        if let Some(sel) = indices {
            if !sel.contains(&i) {
                continue;
            }
        }
        let line = line_for_secret(id, key);
        let var = var_from_line(line.trim()).unwrap_or("SECRET");
        if !seen_vars.insert(var.to_string()) {
            continue;
        }
        body.push_str(&line);
    }
    fs::write(path, body).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut p = fs::metadata(path)
            .map_err(|e| Error::Io {
                path: path.to_path_buf(),
                source: e,
            })?
            .permissions();
        p.set_mode(0o644);
        let _ = fs::set_permissions(path, p);
    }
    Ok(())
}

pub fn write_refs_merge(
    path: &Path,
    secrets: &[(String, String, String)],
    indices: Option<&[usize]>,
    source: &str,
) -> Result<usize> {
    let existing = if path.is_file() {
        fs::read_to_string(path).map_err(|e| Error::Io {
            path: path.to_path_buf(),
            source: e,
        })?
    } else {
        String::new()
    };
    let mut new_lines = String::new();
    let mut added = 0usize;
    // Track VARs newly claimed this pass (existing checked via text_has_var).
    let mut claimed = std::collections::HashSet::new();

    for (i, (id, key, _)) in secrets.iter().enumerate() {
        if let Some(sel) = indices {
            if !sel.contains(&i) {
                continue;
            }
        }
        if text_has_secret(&existing, id, key) {
            continue;
        }
        let line = line_for_secret(id, key);
        let var = var_from_line(line.trim()).unwrap_or("SECRET").to_string();
        // Story #14: never append a second mapping under a VAR the operator already pinned.
        if text_has_var(&existing, &var) || !claimed.insert(var) {
            continue;
        }
        new_lines.push_str(&line);
        added += 1;
    }
    if added == 0 {
        return Ok(0);
    }
    let body = if existing.is_empty() {
        format!(
            "# Bitwarden Secrets Manager refs (no secret values). Generated by {source}.\n\n{new_lines}"
        )
    } else if text_ends_in_banner(&existing, source) {
        // The file already ends in this source's banner, so the new mappings
        // belong under it. A fresh banner every run left real installs with a
        // ladder of empty separators (issue #80).
        let mut b = existing.clone();
        if !b.ends_with('\n') {
            b.push('\n');
        }
        b.push_str(&new_lines);
        b
    } else {
        format!("{existing}\n\n{}\n{new_lines}", banner_line(source))
    };
    fs::write(path, body).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(added)
}

/// The separator `write_refs_merge` puts above the mappings it appends.
///
/// A separator, never an ownership mark: real installs carry operator-written
/// lines above every banner in the file (ADR-0003).
fn banner_line(source: &str) -> String {
    format!("# --- appended by {source} ---")
}

/// True when the file's last section is already this source's banner, so new
/// mappings can extend it instead of opening another one.
///
/// Scans upward past mappings and blank lines. Any other comment ends the
/// section: a header an operator wrote below the last banner means the tail of
/// the file is no longer refresh's to append into silently.
fn text_ends_in_banner(text: &str, source: &str) -> bool {
    let banner = banner_line(source);
    for raw in text.lines().rev() {
        let line = raw.trim();
        if line.is_empty() {
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
    pub reference: String,
    /// The line exactly as it stands in the file, newline excluded. Prune
    /// matches on this, and it is what gets printed when a line is removed —
    /// scrollback is the recovery path.
    pub line: String,
    pub fate: RefFate,
    /// For `Renamed`: the key the recorded secret carries now.
    pub renamed_to: Option<String>,
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

/// Does this reference name a secret in the listing?
///
/// `None` when the reference is not a Bitwarden form this can judge. Mirrors
/// what `parse_bws_ref` matches on, minus the ambiguity errors: a `name:` that
/// hits two secrets resolves to *something*, so it is not dangling.
fn bitwarden_ref_matches(reference: &str, secrets: &[(String, String, String)]) -> Option<bool> {
    let r = reference.trim();
    if crate::validate::is_placeholder_ref(r) {
        return None;
    }
    if let Some(want) = r.strip_prefix("name:") {
        if want.is_empty() {
            return None;
        }
        return Some(secrets.iter().any(|(_, k, _)| k == want));
    }
    if let Some(rest) = r.strip_prefix("project:") {
        let (p, k) = rest.split_once('/')?;
        if p.is_empty() || k.is_empty() {
            return None;
        }
        return Some(secrets.iter().any(|(_, key, proj)| key == k && proj == p));
    }
    let bare = r.strip_prefix("uuid:").unwrap_or(r);
    if crate::validate::is_uuid(bare) {
        return Some(secrets.iter().any(|(id, _, _)| id == bare));
    }
    None
}

/// The key a line's recorded secret carries now, when that differs from what
/// the line's reference asks for.
///
/// Only ever consulted for a reference that already failed to match, so a
/// working mapping is never reclassified on the strength of a stale recording.
fn renamed_key(value: &str, secrets: &[(String, String, String)]) -> Option<String> {
    let uuid = recorded_uuid(value)?;
    let (_, key, _) = secrets.iter().find(|(id, _, _)| id == uuid)?;
    Some(key.clone())
}

/// Classify every mapping line in a Bitwarden refs file against the listing
/// `refresh` already holds. No vault calls: the listing is the whole world.
///
/// Line-based on purpose — prune has to put the file back byte for byte, and
/// only a physical line can be dropped from it. A value carried across lines is
/// never a Bitwarden reference, so it is marked `Unjudged` rather than risking
/// a partial removal.
pub fn scan_bitwarden_refs(text: &str, secrets: &[(String, String, String)]) -> Vec<ScannedRef> {
    scan_refs(text, |value| {
        match bitwarden_ref_matches(reference_of(value), secrets) {
            Some(true) => (RefFate::Resolvable, None),
            Some(false) => match renamed_key(value, secrets) {
                Some(key) => (RefFate::Renamed, Some(key)),
                None => (RefFate::Dangling, None),
            },
            None => (RefFate::Unjudged, None),
        }
    })
}

/// Walk a refs file's mapping lines, letting the backend say what each value
/// means. The walk is the part both backends must agree on: prune puts the file
/// back byte for byte, so what counts as one mapping line cannot differ by
/// backend even where "does not resolve" does.
fn scan_refs(text: &str, classify: impl Fn(&str) -> (RefFate, Option<String>)) -> Vec<ScannedRef> {
    let mut out: Vec<ScannedRef> = Vec::new();
    // Whether the previous mapping's value may still take continuation lines,
    // matching `parse_dotenv_pairs`: a blank line or a comment closes it.
    let mut open = false;
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            open = false;
            continue;
        }
        let assignment = trimmed
            .split_once('=')
            .filter(|(k, _)| crate::validate::validate_var_name(k.trim()));
        let Some((var, value)) = assignment else {
            // A continuation of the value above, or a line nothing can parse.
            // Either way the mapping it belongs to is not a single line, so it
            // must not be pruned.
            if let Some(last) = out.last_mut() {
                if open {
                    last.fate = RefFate::Unjudged;
                }
            }
            continue;
        };
        let value = value.trim();
        let (fate, renamed_to) = classify(value);
        out.push(ScannedRef {
            var: var.trim().to_string(),
            reference: value.to_string(),
            line: line.to_string(),
            fate,
            renamed_to,
        });
        open = true;
    }
    out
}

/// The dangling lines from a scan, in file order.
pub fn dangling_refs(scan: &[ScannedRef]) -> Vec<&ScannedRef> {
    scan.iter()
        .filter(|r| r.fate == RefFate::Dangling)
        .collect()
}

/// The renamed lines from a scan, in file order.
pub fn renamed_refs(scan: &[ScannedRef]) -> Vec<&ScannedRef> {
    scan.iter().filter(|r| r.fate == RefFate::Renamed).collect()
}

/// The lines a scan could not judge on shape, in file order.
pub fn unjudged_refs(scan: &[ScannedRef]) -> Vec<&ScannedRef> {
    scan.iter()
        .filter(|r| r.fate == RefFate::Unjudged)
        .collect()
}

/// The unchecked lines from a scan, in file order.
pub fn unchecked_refs(scan: &[ScannedRef]) -> Vec<&ScannedRef> {
    scan.iter()
        .filter(|r| r.fate == RefFate::Unchecked)
        .collect()
}

/// Mappings whose variable name matches a recorded exclusion but which resolve
/// anyway, in file order.
///
/// Reported, never pruned (ADR-0005). An exclusion says what `refresh` may
/// **add**; the mapping is still a working line, and removing a working line is
/// the one thing prune promises not to do.
///
/// Only lines shown to resolve. Every other fate already has a heading of its
/// own, and each says something this one would contradict — a dangling line is
/// about to go, and an unchecked or unjudged line was never shown to resolve at
/// all. One line, one heading, one fate.
pub fn excluded_refs<'a>(scan: &'a [ScannedRef], patterns: &[String]) -> Vec<&'a ScannedRef> {
    scan.iter()
        .filter(|r| r.fate == RefFate::Resolvable && is_excluded(patterns, &r.var))
        .collect()
}

/// Everything a scan says this manifest needs, as one ordered edit list.
///
/// Repairs come first so a rename is fixed before anything is dropped, and both
/// kinds travel together: one list means one write, so a run cannot leave the
/// file half-corrected.
pub fn plan_ref_edits(scan: &[ScannedRef]) -> Vec<(String, RefEdit)> {
    let mut edits: Vec<(String, RefEdit)> = Vec::new();
    for r in renamed_refs(scan) {
        if let Some(new) = r.repaired_line() {
            edits.push((r.line.clone(), RefEdit::Rewrite(new)));
        }
    }
    for r in dangling_refs(scan) {
        edits.push((r.line.clone(), RefEdit::Remove));
    }
    edits
}

/// A planned or applied edit list in the operator's terms — a removal and a
/// repair are not the same act, and a prompt that blurs them is asking for a
/// wrong `y`.
pub fn describe_ref_edits(edits: &[(String, RefEdit)]) -> String {
    let repairs = edits
        .iter()
        .filter(|(_, e)| matches!(e, RefEdit::Rewrite(_)))
        .count();
    let removals = edits.len() - repairs;
    match (removals, repairs) {
        (0, n) => format!("Repair {n} renamed mapping(s)"),
        (n, 0) => format!("Remove {n} dangling mapping(s)"),
        (n, m) => format!("Remove {n} dangling and repair {m} renamed mapping(s)"),
    }
}

/// What `refresh` should do about the changes its scan wants to make.
///
/// Named for the change in general, not for pruning: the `--prune` flag now
/// gates repairs as well as removals (ADR-0004), and `CONTEXT.md` keeps
/// **prune** meaning removal alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefFixChoice {
    /// Nothing to change, so nothing to decide.
    NothingPending,
    /// `--replace` is about to regenerate the file, which prunes by
    /// construction. `--replace --prune` lands here: a harmless no-op rather
    /// than an error.
    ReplaceRegenerates,
    /// `--prune`: make the changes.
    Apply,
    /// A TTY is present: ask, defaulting to no.
    Ask,
    /// Non-interactive without `--prune`: report and change nothing.
    Report,
}

/// The decision, kept out of the I/O so it can be stated as a table.
///
/// `setup` never calls this — fixing a manifest is maintenance, and `refresh`
/// is the maintenance verb (ADR-0003).
pub fn ref_fix_choice(
    pending: usize,
    prune_flag: bool,
    mode_is_replace: bool,
    interactive: bool,
) -> RefFixChoice {
    if pending == 0 {
        return RefFixChoice::NothingPending;
    }
    if mode_is_replace {
        return RefFixChoice::ReplaceRegenerates;
    }
    if prune_flag {
        return RefFixChoice::Apply;
    }
    if interactive {
        RefFixChoice::Ask
    } else {
        RefFixChoice::Report
    }
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
/// Written through a temp file in the same directory and a rename, unlike the
/// append paths. Merge and replace can only lose regenerable lines; this
/// removes lines nothing can regenerate, and a truncated manifest is an install
/// that launches nothing.
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
    let mut body = String::with_capacity(text.len());
    // What actually changed, in file order — a line the operator wrote twice is
    // edited twice, and the report has to say so.
    let mut applied: Vec<(String, RefEdit)> = Vec::new();
    for chunk in text.split_inclusive('\n') {
        let line = chunk.strip_suffix('\n').unwrap_or(chunk);
        match planned.get(line.trim_end_matches('\r')) {
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

/// True for a section label 1Password supplied rather than the operator.
///
/// `add more` is the label the app gives the section holding custom fields
/// added to an item without choosing a section, so it turns up across a vault
/// without anyone having typed it. Folding it into a variable name gives
/// ANTHROPIC_ADD_MORE_CONDUCTOR_API_KEY where ANTHROPIC_CONDUCTOR_API_KEY was
/// meant, and it carries nothing a reader wants: a section disambiguates
/// fields *within* an item, and this one collects everything never grouped.
///
/// This governs naming and dedupe only. A written reference always keeps the
/// section it was built with, so what `op` is asked to resolve never changes.
pub fn op_section_is_default(section: &str) -> bool {
    section.trim().eq_ignore_ascii_case("add more")
}

/// True when a variable name still carries a default section label folded into
/// it, the shape `refresh` generated before it learned to drop one. Derived
/// from the label rather than spelled out, so the two cannot drift apart.
pub fn name_folds_default_section(name: &str) -> bool {
    let fragment = var_from_parts("", Some("add more"), "");
    name.to_ascii_uppercase().contains(&format!("_{fragment}_"))
}

/// The section as it should count toward a variable name: absent when there is
/// no section, or when 1Password named it rather than the operator.
fn section_for_naming(section: Option<&str>) -> Option<&str> {
    section.filter(|s| !s.is_empty() && !op_section_is_default(s))
}

/// VAR name for a 1Password field: "anthropic" + "conductor-api-key" becomes
/// ANTHROPIC_CONDUCTOR_API_KEY. An operator-named section is included, because
/// label alone is not unique within an item; a default section label is not
/// (see `op_section_is_default`).
///
/// Dropping a default label can make two fields in one item want the same
/// name. Only the caller can see that, because it holds the whole item; it
/// resolves the clash with `op_ref_var_qualified`.
pub fn op_ref_var(item: &str, section: Option<&str>, field: &str) -> String {
    var_from_parts(item, section_for_naming(section), field)
}

/// `op_ref_var`, keeping a section label it would otherwise drop. For the one
/// case that needs it: two fields in an item whose names would collide.
pub fn op_ref_var_qualified(item: &str, section: Option<&str>, field: &str) -> String {
    var_from_parts(item, section.filter(|s| !s.is_empty()), field)
}

fn var_from_parts(item: &str, section: Option<&str>, field: &str) -> String {
    let joined = match section {
        Some(s) => format!("{item}_{s}_{field}"),
        None => format!("{item}_{field}"),
    };
    let mut s: String = joined
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    while s.contains("__") {
        s = s.replace("__", "_");
    }
    let s = s.trim_matches('_').to_string();
    let needs_prefix = !matches!(s.chars().next(), Some(c) if c.is_ascii_alphabetic());
    if needs_prefix {
        format!("SECRET_{s}")
    } else {
        s
    }
}

/// `op://VAULT/ITEM/FIELD`, or `op://VAULT/ITEM/SECTION/FIELD` for a field in a
/// section.
///
/// The section is not decoration. An item can carry several fields with the same
/// label in different sections, holding different secrets; the unqualified form
/// then resolves to whichever one `op` picks. Both forms were checked against a
/// real vault, including that two section-qualified references return different
/// values.
///
/// Spaces are fine: `op inject` reads a dotenv value to end of line.
pub fn op_reference(vault: &str, item: &str, section: Option<&str>, field: &str) -> String {
    match section {
        Some(s) if !s.is_empty() => format!("op://{vault}/{item}/{s}/{field}"),
        _ => format!("op://{vault}/{item}/{field}"),
    }
}

/// True when a reference component survives `op inject`'s reference scanner.
///
/// The scanner ends a reference at a character it does not accept, so an item
/// titled `db-admin jstephens MySQL (read-write)` is read as the truncated
/// `op://Orchestrator/db-admin jstephens MySQL` and rejected with "too few
/// '/'": one such item aborts the injection of the entire manifest. Spaces are
/// accepted; parentheses and non-ASCII characters (an em dash in a title, say)
/// are not. Quoting the value is not a workaround, because the scanner runs
/// over the reference text itself rather than the shell-quoted line.
pub fn op_component_is_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' '))
}

/// True when `op` can read a whole reference: the scheme, then at least a
/// vault, an item and a field, each built only from characters its scanner
/// accepts. One reference that fails this aborts the injection of the entire
/// manifest, so it is worth checking before a launch rather than during one.
pub fn op_reference_is_parseable(reference: &str) -> bool {
    let Some(rest) = reference.strip_prefix("op://") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('/').collect();
    parts.len() >= 3 && parts.iter().all(|p| op_component_is_safe(p))
}

/// The item component of a reference: the readable title when `op` can parse
/// it, otherwise the item's opaque ID, which always parses. Variable names are
/// still derived from the title, so a fallback here costs readability only in
/// the reference itself.
pub fn op_item_component<'a>(title: &'a str, id: &'a str) -> &'a str {
    if op_component_is_safe(title) {
        title
    } else {
        id
    }
}

/// A reference reduced to the field it identifies, so a generated mapping can
/// be recognised in a manifest an operator wrote by hand.
///
/// `op://V/eta-factory-github-app/add more/app-id` and
/// `op://V/eta-factory-github-app/app-id` are the same secret: a default
/// section groups fields that were never grouped, and `op` resolves the
/// unqualified form to the field inside it — checked against a real vault, by
/// launching with both forms mapped and observing one value under both names.
///
/// Comparing the strings byte for byte instead reports "not present" for a
/// field the manifest already maps, and merge appends a second mapping under
/// the generated name. On a 60-item vault that was 81 duplicate variables,
/// every one of them a live credential in the agent's environment twice.
fn canonical_reference(reference: &str) -> String {
    let Some(rest) = reference.strip_prefix("op://") else {
        return reference.to_string();
    };
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        [vault, item, section, field] if op_section_is_default(section) => {
            format!("op://{vault}/{item}/{field}")
        }
        _ => reference.to_string(),
    }
}

/// True if the refs file already points at this field, under any name and
/// through either the section-qualified or the unqualified form.
fn text_has_reference(text: &str, reference: &str) -> bool {
    let want = canonical_reference(reference);
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((_, v)) = line.split_once('=') {
            if canonical_reference(v.trim()) == want {
                return true;
            }
        }
    }
    false
}

/// Everything `refresh` learned about the 1Password side of this run, and the
/// whole world an existing mapping is judged against.
///
/// Deliberately only what the run already paid for. `op item list` is one call
/// and names every item; fields cost one `op item get` per item, which is why
/// selection is at item level in the first place. So a mapping into an item
/// this run expanded is judged down to the field, and a mapping into an item it
/// did not is an **unchecked ref** — reported, never pruned (ADR-0005).
pub struct OpWorld {
    /// `op item list`: every item the token can see.
    pub items: Vec<crate::backend::OpItem>,
    /// Field identities by item id, for the items this run expanded.
    pub fields: std::collections::HashMap<String, Vec<crate::backend::OpFieldRef>>,
}

impl OpWorld {
    /// The listed item a reference's vault and item components name, if any.
    fn item_of(&self, vault: &str, item: &str) -> Option<&crate::backend::OpItem> {
        self.items.iter().find(|it| it.named_by(vault, item))
    }
}

/// How one `op://` reference stands against what this run fetched.
///
/// Lenient by construction: every uncertainty resolves toward "not dangling".
/// A wrong `Dangling` removes a line that launches today, and no report is
/// worth that.
fn op_ref_fate(reference: &str, world: &OpWorld) -> RefFate {
    let r = reference.trim();
    // Invariant 4 keeps placeholders loud, and `secrets validate` owns them.
    if crate::validate::is_placeholder_ref(r) {
        return RefFate::Unjudged;
    }
    // A literal beside the references (a region, a URL) is not refresh's to
    // judge, and neither is a shape `op` itself cannot read.
    if !r.starts_with("op://") || !op_reference_is_parseable(r) {
        return RefFate::Unjudged;
    }
    let parts: Vec<&str> = r["op://".len()..].split('/').collect();
    let (vault, item, section, field) = match parts.as_slice() {
        [v, i, f] => (*v, *i, None, *f),
        [v, i, s, f] => (*v, *i, Some(*s), *f),
        // More components than `op`'s own form has: nothing to judge it by.
        _ => return RefFate::Unjudged,
    };
    // A placeholder anywhere in the reference keeps the whole line unjudged.
    // `is_placeholder_ref` anchors most of its spellings at the start of the
    // string, which behind an `op://` prefix is the scheme, so the components
    // have to be offered to it one at a time. Invariant 4 makes a placeholder
    // fail closed and ADR-0003 keeps prune off it: removing one would take the
    // variable out of the manifest and turn a loud misconfiguration into a
    // secret that quietly stops being injected.
    if [Some(item), section, Some(field)]
        .into_iter()
        .flatten()
        .any(crate::validate::is_placeholder_ref)
    {
        return RefFate::Unjudged;
    }
    let Some(found) = world.item_of(vault, item) else {
        // Neither an id nor a title in the listing: the item was deleted,
        // renamed, or moved out of this token's reach. An `op` reference records
        // no source id (ADR-0005), so a rename here is indistinguishable from a
        // deletion and both are dangling.
        return RefFate::Dangling;
    };
    let Some(fields) = world.fields.get(found.id.as_str()) else {
        return RefFate::Unchecked;
    };
    // A default section label groups fields that were never grouped, and `op`
    // resolves the unqualified form to the field inside it — the same
    // equivalence `canonical_reference` relies on.
    let section = section.filter(|s| !op_section_is_default(s));
    let hit = fields
        .iter()
        .any(|f| f.named(field) && f.in_section(section));
    if hit {
        RefFate::Resolvable
    } else {
        RefFate::Dangling
    }
}

/// Classify every mapping line in a 1Password refs file against what this run
/// fetched. No extra vault calls — same rule as Bitwarden, different world.
pub fn scan_op_refs(text: &str, world: &OpWorld) -> Vec<ScannedRef> {
    scan_refs(text, |value| (op_ref_fate(value, world), None))
}

const OP_REFS_HEADER: &str = "1Password refs (no secret values). Generated by";

/// Comment form recording a variable name `refresh` must never map.
const EXCLUDE_DIRECTIVE: &str = "# exclude:";

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
            .strip_prefix("exclude:")
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

/// Directive lines for every pattern, for a writer building a fresh header.
fn exclusion_lines(patterns: &[String]) -> String {
    patterns
        .iter()
        .map(|p| format!("{EXCLUDE_DIRECTIVE} {p}\n"))
        .collect()
}

/// Write a 1Password refs manifest from (var, reference) pairs, replacing any
/// existing content.
pub fn write_op_refs_replace(
    path: &Path,
    entries: &[(String, String)],
    exclusions: &[String],
    source: &str,
) -> Result<()> {
    // The form line deliberately does not spell out a literal reference.
    // `op inject` substitutes every reference it finds in the file, comments
    // included, so an illustrative op://VAULT/ITEM/FIELD in this header is read
    // as a real reference and the whole injection dies on "VAULT isn't a vault
    // in this account" - taking every genuine entry below it down too.
    let mut body = format!(
        "# {OP_REFS_HEADER} {source}.\n\
         # Form: VAR= a secret reference (vault, item and field, slash separated).\n\
         # Update: vaulted-agent refresh\n\
         # Values fetched live at launch.\n"
    );
    // Rewriting the file must not silently re-admit what the operator excluded,
    // so the directives are carried into the new header rather than dropped
    // with the rest of the old content.
    if !exclusions.is_empty() {
        body.push_str("# Names refresh will not map (vaulted-agent refresh --exclude):\n");
        body.push_str(&exclusion_lines(exclusions));
    }
    body.push('\n');
    let mut seen = std::collections::HashSet::new();
    for (var, reference) in entries {
        if !seen.insert(var.clone()) {
            continue;
        }
        body.push_str(&format!("{var}={reference}\n"));
    }
    fs::write(path, body).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    set_refs_mode(path);
    Ok(())
}

/// Append only the (var, reference) pairs not already mapped. Returns how many
/// were added.
pub fn write_op_refs_merge(
    path: &Path,
    entries: &[(String, String)],
    exclusions: &[String],
    source: &str,
) -> Result<usize> {
    let existing = if path.is_file() {
        fs::read_to_string(path).map_err(|e| Error::Io {
            path: path.to_path_buf(),
            source: e,
        })?
    } else {
        String::new()
    };
    let mut new_lines = String::new();
    let mut added = 0usize;
    let mut claimed = std::collections::HashSet::new();

    for (var, reference) in entries {
        if text_has_reference(&existing, reference) {
            continue;
        }
        // Never append a second mapping under a VAR the operator already pinned.
        if text_has_var(&existing, var) || !claimed.insert(var.clone()) {
            continue;
        }
        new_lines.push_str(&format!("{var}={reference}\n"));
        added += 1;
    }
    // Patterns given on this run and not yet written down. Recorded even when
    // nothing was added, so `--exclude` takes effect on the next refresh rather
    // than only on one that happened to find new fields.
    let already = read_exclusions(&existing);
    let fresh: Vec<String> = exclusions
        .iter()
        .filter(|p| !already.iter().any(|q| q == *p))
        .cloned()
        .collect();
    if added == 0 && fresh.is_empty() {
        return Ok(0);
    }
    let block = format!("{}{new_lines}", exclusion_lines(&fresh));
    let body = if existing.is_empty() {
        format!("# {OP_REFS_HEADER} {source}.\n\n{block}")
    } else {
        format!("{existing}\n\n# --- appended by {source} ---\n{block}")
    };
    fs::write(path, body).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    set_refs_mode(path);
    Ok(added)
}

fn set_refs_mode(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = fs::metadata(path) {
            let mut p = md.permissions();
            p.set_mode(0o644);
            let _ = fs::set_permissions(path, p);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
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
    fn substring_uuid_in_comment_is_not_a_hit() {
        let text = "# note about 00000000-0000-0000-0000-000000000001\nOPENAI=name:other\n";
        assert!(!text_has_secret(
            text,
            "00000000-0000-0000-0000-000000000001",
            "openai-api-key"
        ));
    }

    #[test]
    fn name_ref_line_is_a_hit() {
        let text = "OPENAI_API_KEY=name:openai-api-key\n";
        assert!(text_has_secret(text, "id-x", "openai-api-key"));
    }

    #[test]
    fn bare_uuid_value_is_a_hit() {
        let text = "X=00000000-0000-0000-0000-000000000099\n";
        assert!(text_has_secret(
            text,
            "00000000-0000-0000-0000-000000000099",
            "anything"
        ));
    }

    #[test]
    fn op_var_uppercases_and_collapses_separators() {
        assert_eq!(
            op_ref_var("anthropic", None, "conductor-api-key"),
            "ANTHROPIC_CONDUCTOR_API_KEY"
        );
        assert_eq!(
            op_ref_var("github token", None, "fine-grained-token"),
            "GITHUB_TOKEN_FINE_GRAINED_TOKEN"
        );
        // Leading/trailing junk must not produce __ or a trailing _.
        assert_eq!(op_ref_var("  spaced  ", None, "-field-"), "SPACED_FIELD");
    }

    #[test]
    fn op_var_prefixes_when_it_would_not_start_with_a_letter() {
        // A bare digit start is not a valid shell identifier.
        assert_eq!(op_ref_var("3cx", None, "api-key"), "SECRET_3CX_API_KEY");
    }

    #[test]
    fn section_distinguishes_same_label_fields() {
        // Without the section these collapse to one VAR and one ambiguous
        // reference, silently dropping real secrets.
        let a = op_ref_var("mysql8.etadventures.com", Some("mysql"), "password");
        let b = op_ref_var("mysql8.etadventures.com", None, "password");
        assert_eq!(a, "MYSQL8_ETADVENTURES_COM_MYSQL_PASSWORD");
        assert_eq!(b, "MYSQL8_ETADVENTURES_COM_PASSWORD");
        assert_ne!(a, b);

        assert_eq!(
            op_reference("V", "host", Some("mysql"), "password"),
            "op://V/host/mysql/password"
        );
        assert_eq!(
            op_reference("V", "host", None, "password"),
            "op://V/host/password"
        );
        // An empty section must not produce a double slash.
        assert_eq!(
            op_reference("V", "host", Some(""), "password"),
            "op://V/host/password"
        );
    }

    #[test]
    fn op_component_safety_matches_what_op_can_parse() {
        // Spaces are accepted by op's reference scanner.
        assert!(op_component_is_safe("db-admin jstephens MySQL"));
        assert!(op_component_is_safe("mysql8.etadventures.com"));
        assert!(op_component_is_safe("add more"));
        // These end the reference early, so op reports "too few '/'".
        assert!(!op_component_is_safe(
            "db-admin jstephens MySQL (read-write)"
        ));
        assert!(!op_component_is_safe("Grafana — grafana.etadventures.com"));
        assert!(!op_component_is_safe(""));
    }

    #[test]
    fn unparseable_item_title_falls_back_to_the_id() {
        let id = "7vjm6j5srnx2krtk5nvduzjjoe";
        assert_eq!(op_item_component("plain-title", id), "plain-title");
        assert_eq!(op_item_component("db-admin (read-write)", id), id);
        // The variable name still comes from the title, so the fallback costs
        // readability only inside the reference.
        assert_eq!(
            op_ref_var("db-admin (read-write)", None, "username"),
            "DB_ADMIN_READ_WRITE_USERNAME"
        );
        assert_eq!(
            op_reference(
                "V",
                op_item_component("db-admin (read-write)", id),
                None,
                "username"
            ),
            format!("op://V/{id}/username")
        );
    }

    #[test]
    fn reference_parseability_matches_op() {
        assert!(op_reference_is_parseable("op://V/item/field"));
        assert!(op_reference_is_parseable("op://V/item/add more/field"));
        assert!(op_reference_is_parseable(
            "op://V/db-admin jstephens/username"
        ));
        // Truncated by op's scanner, so op reports "too few '/'".
        assert!(!op_reference_is_parseable(
            "op://V/db-admin (read-write)/username"
        ));
        assert!(!op_reference_is_parseable("op://V/Grafana — host/username"));
        // Genuinely too few components, before any character question.
        assert!(!op_reference_is_parseable("op://V/item"));
        // Not a 1Password reference at all.
        assert!(!op_reference_is_parseable("name:some-secret"));
        // Literals are not parseable references — callers must gate on the
        // op:// prefix so doctor does not treat them as errors (issue #53).
        assert!(!op_reference_is_parseable("us-east-1"));
        assert!(!op_reference_is_parseable("https://example.com/v1"));
    }

    #[test]
    fn doctor_style_filter_flags_only_malformed_op_refs() {
        // Same rule the doctor call site uses: only values that claim to be
        // references, and fail the scanner among those.
        let lines = [
            ("GOOD", "op://V/item/field"),
            ("BAD_PARENS", "op://V/db-admin (rw)/user"),
            ("LITERAL_REGION", "us-east-1"),
            ("LITERAL_URL", "https://example.com/v1"),
        ];
        let flagged: Vec<&str> = lines
            .iter()
            .filter(|(_, v)| v.starts_with("op://") && !op_reference_is_parseable(v))
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(flagged, vec!["BAD_PARENS"]);
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
        let entries = vec![(
            "A_KEY".to_string(),
            "op://V/anthropic/conductor-api-key".to_string(),
        )];
        write_op_refs_replace(&p, &entries, &[], "test").unwrap();

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

        let entries = vec![
            (
                "A_KEY".to_string(),
                "op://V/anthropic/conductor-api-key".to_string(),
            ),
            ("B_KEY".to_string(), "op://V/github token/tok".to_string()),
        ];
        write_op_refs_replace(&p, &entries, &[], "test").unwrap();
        let first = fs::read_to_string(&p).unwrap();
        assert!(first.contains("A_KEY=op://V/anthropic/conductor-api-key"));

        // Same entries again: nothing new.
        assert_eq!(write_op_refs_merge(&p, &entries, &[], "test").unwrap(), 0);
        assert_eq!(fs::read_to_string(&p).unwrap(), first);

        // A new reference under a VAR the operator already pinned is skipped
        // rather than appended as a second mapping.
        let clash = vec![("A_KEY".to_string(), "op://V/other/field".to_string())];
        assert_eq!(write_op_refs_merge(&p, &clash, &[], "test").unwrap(), 0);

        // A genuinely new one is appended.
        let fresh = vec![("C_KEY".to_string(), "op://V/third/field".to_string())];
        assert_eq!(write_op_refs_merge(&p, &fresh, &[], "test").unwrap(), 1);
        assert!(fs::read_to_string(&p)
            .unwrap()
            .contains("C_KEY=op://V/third/field"));
    }

    #[test]
    fn merge_skips_when_var_already_mapped_to_different_ref() {
        let existing = "OPENAI_API_KEY=uuid:00000000-0000-0000-0000-000000000009\n";
        // Would produce OPENAI_API_KEY=name:openai.api.key — must not append.
        let line = line_for_secret("other-id", "openai.api.key");
        let var = var_from_line(line.trim()).unwrap();
        assert!(text_has_var(existing, var));
        assert!(!text_has_secret(existing, "other-id", "openai.api.key"));
    }

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
    fn default_section_label_does_not_reach_the_name() {
        // 1Password labels the section holding ungrouped custom fields
        // "add more". Nobody typed it, and it made every generated name carry
        // it: ANTHROPIC_ADD_MORE_CONDUCTOR_API_KEY for a field whose own item
        // and label already say everything.
        assert_eq!(
            op_ref_var("anthropic", Some("add more"), "conductor-api-key"),
            "ANTHROPIC_CONDUCTOR_API_KEY"
        );
        assert_eq!(
            op_ref_var("anthropic", None, "conductor-api-key"),
            op_ref_var("anthropic", Some("add more"), "conductor-api-key")
        );
        // 1Password's own casing is not guaranteed.
        assert!(op_section_is_default("Add More"));
        assert!(op_section_is_default(" add more "));
        // A section the operator named still distinguishes fields, which is the
        // whole reason the section is in the name at all.
        assert!(!op_section_is_default("mysql"));
        assert_eq!(
            op_ref_var("mysql8.etadventures.com", Some("mysql"), "password"),
            "MYSQL8_ETADVENTURES_COM_MYSQL_PASSWORD"
        );
    }

    #[test]
    fn qualified_form_is_available_when_dropping_the_label_would_collide() {
        // One item carrying `app-id` loose and `app-id` under "add more" holds
        // two secrets. The caller sees the clash and asks for both qualified,
        // rather than letting one name win and the other secret vanish.
        let a = op_ref_var("eta-factory-github-app", None, "app-id");
        let b = op_ref_var("eta-factory-github-app", Some("add more"), "app-id");
        assert_eq!(a, b);
        let b_q = op_ref_var_qualified("eta-factory-github-app", Some("add more"), "app-id");
        assert_eq!(b_q, "ETA_FACTORY_GITHUB_APP_ADD_MORE_APP_ID");
        assert_ne!(a, b_q);
        // With no section there is nothing to add back.
        assert_eq!(op_ref_var_qualified("item", None, "field"), "ITEM_FIELD");
    }

    #[test]
    fn legacy_names_are_recognisable_for_doctor() {
        assert!(name_folds_default_section(
            "ETA_FACTORY_GITHUB_APP_ADD_MORE_APP_ID"
        ));
        assert!(name_folds_default_section(&op_ref_var_qualified(
            "anthropic",
            Some("add more"),
            "conductor-api-key"
        )));
        // What refresh generates now must never look legacy.
        assert!(!name_folds_default_section(&op_ref_var(
            "anthropic",
            Some("add more"),
            "conductor-api-key"
        )));
        assert!(!name_folds_default_section("PLAIN_API_KEY"));
        // A field genuinely named "add-more-seats" produces the same fragment,
        // so this cannot be the whole test. Doctor pairs it with the reference,
        // which only carries a default section when there really is one:
        // op://V/zoom/add-more-seats-url has no section component at all.
        assert!(name_folds_default_section("ZOOM_ADD_MORE_SEATS_URL"));
        assert!(!"op://V/zoom/add-more-seats-url"
            .split('/')
            .any(op_section_is_default));
        assert!("op://V/anthropic/add more/conductor-api-key"
            .split('/')
            .any(op_section_is_default));
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

        let generated = vec![(
            "ETA_FACTORY_GITHUB_APP_APP_ID".to_string(),
            "op://Orchestrator/eta-factory-github-app/add more/app-id".to_string(),
        )];
        assert_eq!(write_op_refs_merge(&p, &generated, &[], "test").unwrap(), 0);
        assert!(!fs::read_to_string(&p).unwrap().contains("add more"));

        // The reverse direction too: a curated section-qualified line already
        // covers the unqualified form of the same field.
        let q = dir.path().join("q.refs");
        fs::write(&q, "PINNED=op://V/item/add more/app-id\n").unwrap();
        let plain = vec![("ITEM_APP_ID".to_string(), "op://V/item/app-id".to_string())];
        assert_eq!(write_op_refs_merge(&q, &plain, &[], "test").unwrap(), 0);

        // A genuinely different field on the same item is still added.
        let other = vec![(
            "ITEM_TOKEN".to_string(),
            "op://V/item/add more/token".to_string(),
        )];
        assert_eq!(write_op_refs_merge(&q, &other, &[], "test").unwrap(), 1);
        // An operator-named section is not a default one, so it is not folded
        // away and two such fields stay distinct.
        assert_eq!(
            canonical_reference("op://V/host/mysql/password"),
            "op://V/host/mysql/password"
        );
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

    #[test]
    fn exclusions_survive_both_writers() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("op.refs");
        let entries = vec![("A_KEY".to_string(), "op://V/anthropic/key".to_string())];
        let ex = vec!["*_USERNAME".to_string()];

        // Replace rewrites the file, and must not drop the operator's patterns
        // along with the content: the next refresh would re-admit everything.
        write_op_refs_replace(&p, &entries, &ex, "test").unwrap();
        assert_eq!(read_exclusions(&fs::read_to_string(&p).unwrap()), ex);

        // Merge records a pattern first seen on this run even when it found no
        // new mappings, so --exclude takes effect on a run that happens to add
        // nothing. The count is mappings added, so recording a pattern is 0.
        let more = vec!["*_USERNAME".to_string(), "ZOOM_*".to_string()];
        assert_eq!(write_op_refs_merge(&p, &entries, &more, "test").unwrap(), 0);
        assert_eq!(read_exclusions(&fs::read_to_string(&p).unwrap()), more);

        // Recorded once, not appended again on every subsequent run.
        assert_eq!(write_op_refs_merge(&p, &entries, &more, "test").unwrap(), 0);
        assert_eq!(read_exclusions(&fs::read_to_string(&p).unwrap()), more);
    }

    fn listing() -> Vec<(String, String, String)> {
        vec![
            (
                "ea6db86f-0000-0000-0000-000000000001".into(),
                "ASSEMBLY_AI_API_KEY".into(),
                "tools".into(),
            ),
            (
                "ea6db86f-0000-0000-0000-000000000002".into(),
                "OPENAI_API_KEY".into(),
                "tools".into(),
            ),
        ]
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
        let dangling = dangling_refs(&scan);
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
        assert!(dangling_refs(&scan).is_empty(), "{scan:?}");
        assert!(scan.iter().all(|r| r.fate == RefFate::Unjudged));
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
        let doomed: Vec<(String, RefEdit)> = dangling_refs(&scan)
            .iter()
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

    #[test]
    fn prune_decision_table() {
        // --prune removes; a TTY asks; neither reports and changes nothing.
        assert_eq!(ref_fix_choice(2, true, false, false), RefFixChoice::Apply);
        assert_eq!(ref_fix_choice(2, false, false, true), RefFixChoice::Ask);
        assert_eq!(ref_fix_choice(2, false, false, false), RefFixChoice::Report);
        // Nothing dangling is nothing to decide.
        assert_eq!(
            ref_fix_choice(0, true, false, true),
            RefFixChoice::NothingPending
        );
        // --replace already prunes by construction, so --replace --prune is a
        // harmless no-op rather than an error.
        assert_eq!(
            ref_fix_choice(3, true, true, true),
            RefFixChoice::ReplaceRegenerates
        );
    }

    #[test]
    fn merge_does_not_stack_a_banner_on_every_run() {
        // A real install grew one banner and two blank lines per refresh
        // (issue #80). The banner is a separator, so one is enough.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        fs::write(&p, "OPERATOR_PINNED=name:PINNED\n").unwrap();

        let first = vec![(
            "id1".to_string(),
            "OPENAI_API_KEY".to_string(),
            String::new(),
        )];
        assert_eq!(write_refs_merge(&p, &first, None, "test").unwrap(), 1);
        let second = vec![(
            "id2".to_string(),
            "META_AI_API_KEY".to_string(),
            String::new(),
        )];
        assert_eq!(write_refs_merge(&p, &second, None, "test").unwrap(), 1);

        let body = fs::read_to_string(&p).unwrap();
        assert_eq!(
            body.matches("# --- appended by test ---").count(),
            1,
            "{body}"
        );
        assert!(
            body.contains("OPENAI_API_KEY=name:OPENAI_API_KEY"),
            "{body}"
        );
        assert!(
            body.contains("META_AI_API_KEY=name:META_AI_API_KEY"),
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
        let secrets = vec![("id".to_string(), "NEW_KEY".to_string(), String::new())];
        assert_eq!(write_refs_merge(&p, &secrets, None, "test").unwrap(), 1);
        let body = fs::read_to_string(&p).unwrap();
        assert_eq!(
            body.matches("# --- appended by test ---").count(),
            2,
            "{body}"
        );
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
    fn generated_lines_record_the_source_uuid() {
        let u = "11111111-1111-1111-1111-111111111111";
        assert_eq!(
            line_for_secret(u, "ASSEMBLY_AI_API_KEY"),
            format!("ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{u}\n")
        );
        // The UUID-form fallback already carries the identity.
        assert_eq!(line_for_secret(u, "has spaces"), format!("SECRET={u}\n"));
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
        let secrets = vec![(
            u.to_string(),
            "ASSEMBLY_AI_API_KEY".to_string(),
            "tools".to_string(),
        )];
        let added = write_refs_merge(&p, &secrets, None, "t").unwrap();
        assert_eq!(added, 0, "{}", fs::read_to_string(&p).unwrap());
    }

    #[test]
    fn a_renamed_secret_is_a_rename_and_not_a_dangling_ref() {
        let u = "00000000-0000-0000-0000-000000000001";
        let secrets = vec![(
            u.to_string(),
            "ASSEMBLY_AI_API_KEY".to_string(),
            "tools".to_string(),
        )];
        let text = format!("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY # uuid:{u}\n");
        let scan = scan_bitwarden_refs(&text, &secrets);
        assert_eq!(scan.len(), 1);
        assert_eq!(scan[0].fate, RefFate::Renamed);
        assert_eq!(scan[0].renamed_to.as_deref(), Some("ASSEMBLY_AI_API_KEY"));
        // A rename is not prunable: it is repairable, which is strictly better.
        assert!(dangling_refs(&scan).is_empty());
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
        let secrets = vec![(
            "00000000-0000-0000-0000-000000000001".to_string(),
            "ASSEMBLY_AI_API_KEY".to_string(),
            "tools".to_string(),
        )];
        let scan = scan_bitwarden_refs("ASSEMBLY_API_KEY=name:ASSEMBLY_API_KEY\n", &secrets);
        assert_eq!(scan[0].fate, RefFate::Dangling);
        assert_eq!(dangling_refs(&scan).len(), 1);
    }

    #[test]
    fn a_recorded_uuid_the_token_cannot_see_leaves_the_line_dangling() {
        // The secret is gone, not renamed. Deletion is still prune's case.
        let secrets = vec![(
            "00000000-0000-0000-0000-000000000009".to_string(),
            "OPENAI_API_KEY".to_string(),
            "tools".to_string(),
        )];
        let text = "GONE=name:GONE # uuid:00000000-0000-0000-0000-000000000001\n";
        let scan = scan_bitwarden_refs(text, &secrets);
        assert_eq!(scan[0].fate, RefFate::Dangling);
    }

    #[test]
    fn a_resolvable_line_is_never_a_rename_even_with_a_stale_recording() {
        // Two secrets, and the line resolves. Nothing is broken, so refresh has
        // no business editing it — `validate` stays silent about the mismatch
        // too, because the launch works (ADR-0004).
        let secrets = vec![
            (
                "00000000-0000-0000-0000-000000000001".to_string(),
                "A_KEY".to_string(),
                "tools".to_string(),
            ),
            (
                "00000000-0000-0000-0000-000000000002".to_string(),
                "B_KEY".to_string(),
                "tools".to_string(),
            ),
        ];
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

    fn op_world() -> OpWorld {
        let mut fields = std::collections::HashMap::new();
        fields.insert(
            "id-host".to_string(),
            vec![
                crate::backend::OpFieldRef {
                    section: None,
                    label: "password".into(),
                    id: "f1".into(),
                },
                crate::backend::OpFieldRef {
                    section: Some("mysql".into()),
                    label: "password".into(),
                    id: "f2".into(),
                },
                crate::backend::OpFieldRef {
                    section: Some("add more".into()),
                    label: "app-id".into(),
                    id: "f3".into(),
                },
            ],
        );
        OpWorld {
            items: vec![
                crate::backend::OpItem {
                    id: "id-host".into(),
                    title: "db.example.com".into(),
                    vault: "Orchestrator".into(),
                    vault_id: "vault-id-1".into(),
                },
                crate::backend::OpItem {
                    id: "id-other".into(),
                    title: "github token".into(),
                    vault: "Orchestrator".into(),
                    vault_id: "vault-id-1".into(),
                },
            ],
            fields,
        }
    }

    fn fate(reference: &str) -> RefFate {
        let scan = scan_op_refs(&format!("VAR={reference}\n"), &op_world());
        assert_eq!(scan.len(), 1);
        scan[0].fate
    }

    #[test]
    fn op_refs_are_judged_against_what_the_run_fetched() {
        assert_eq!(
            fate("op://Orchestrator/db.example.com/password"),
            RefFate::Resolvable
        );
        assert_eq!(
            fate("op://Orchestrator/db.example.com/mysql/password"),
            RefFate::Resolvable
        );
        // The item component may be the opaque id, which is what refresh writes
        // when the title is one `op` cannot parse.
        assert_eq!(
            fate("op://Orchestrator/id-host/password"),
            RefFate::Resolvable
        );
        // A default section label groups fields that were never grouped, so the
        // qualified and unqualified forms are the same reference.
        assert_eq!(
            fate("op://Orchestrator/id-host/add more/app-id"),
            RefFate::Resolvable
        );
        assert_eq!(
            fate("op://Orchestrator/id-host/app-id"),
            RefFate::Resolvable
        );
        // `op` matches names case-insensitively; a manifest written in another
        // case launches fine and must not be called dangling.
        assert_eq!(
            fate("op://orchestrator/DB.Example.com/PASSWORD"),
            RefFate::Resolvable
        );

        // Item gone from the listing, and field gone from an item that was read.
        assert_eq!(
            fate("op://Orchestrator/vanished/password"),
            RefFate::Dangling
        );
        assert_eq!(
            fate("op://Orchestrator/db.example.com/api-key"),
            RefFate::Dangling
        );
        // A vault this token cannot see holds nothing it can resolve.
        assert_eq!(
            fate("op://Other/db.example.com/password"),
            RefFate::Dangling
        );

        // Item in the listing, fields never read: nothing was learned.
        assert_eq!(
            fate("op://Orchestrator/github token/api-key"),
            RefFate::Unchecked
        );

        // `op` accepts a vault id in place of its name, so the listing has to
        // match on either. Judging by name alone would prune a working line.
        assert_eq!(
            fate("op://vault-id-1/db.example.com/password"),
            RefFate::Resolvable
        );

        // Shapes prune must not touch.
        assert_eq!(fate("us-east-1"), RefFate::Unjudged);
        assert_eq!(
            fate("op://Orchestrator/db-admin (rw)/password"),
            RefFate::Unjudged
        );
        // A placeholder in any component, not only the spellings that survive
        // being read behind the `op://` prefix: invariant 4 keeps them loud,
        // and pruning one would take the variable out of the manifest.
        for placeholder in [
            "op://Orchestrator/db.example.com/REPLACE_WITH_FIELD",
            "op://Orchestrator/db.example.com/CHANGE_ME",
            "op://Orchestrator/YOUR_ITEM/password",
            "op://Orchestrator/db.example.com/TODO/password",
        ] {
            assert_eq!(fate(placeholder), RefFate::Unjudged, "{placeholder}");
        }
    }

    #[test]
    fn an_exclusion_does_not_make_a_working_mapping_prunable() {
        let text = "DB_EXAMPLE_COM_PASSWORD=op://Orchestrator/db.example.com/password\n\
                    GONE=op://Orchestrator/vanished/password\n";
        let scan = scan_op_refs(text, &op_world());
        let patterns = vec!["*_PASSWORD".to_string(), "GONE".to_string()];

        // Reported under its own heading, and absent from the edit list.
        let excluded = excluded_refs(&scan, &patterns);
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded[0].var, "DB_EXAMPLE_COM_PASSWORD");
        let edits = plan_ref_edits(&scan);
        assert_eq!(edits.len(), 1);
        assert!(edits[0].0.starts_with("GONE="));
    }
}
