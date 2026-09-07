//! Manifest validation: placeholders and Bitwarden ref forms.

use std::path::Path;

use crate::config::Backend;
use crate::error::{Error, Result};

pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// Placeholder check for operator-supplied *references* (not secret values).
/// Kept narrow so legitimate pass paths like `example.com/token` are accepted.
pub fn is_placeholder_ref(r: &str) -> bool {
    let low = r.to_ascii_lowercase();
    if low.is_empty() {
        return true;
    }
    if low.contains("00000000-0000-0000-0000-000000000000") || low.contains("replace_with") {
        return true;
    }
    low.starts_with("change_me")
        || low.starts_with("changeme")
        || low.starts_with("your_")
        || low.starts_with("placeholder")
        || low == "todo"
        || low.starts_with("todo_")
        || low == "xxx"
        || low.starts_with("xxx_")
        || low == "example"
        || low == "replace"
}

/// Strong signals only — applied to decrypted secret *values* (sops/plainfile).
/// A password containing the substring "REPLACE" must not fail closed.
pub fn is_placeholder_secret_value(val: &str) -> bool {
    let low = val.to_ascii_lowercase();
    if low.is_empty() {
        return false;
    }
    low.contains("replace_with")
        || low.contains("change_me")
        || low.contains("00000000-0000-0000-0000-000000000000")
        || low == "changeme"
        || low == "placeholder"
        || low == "todo"
        || low == "xxx"
}

pub fn validate_var_name(var: &str) -> bool {
    let mut chars = var.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn validate_bitwarden_ref(var: &str, r: &str) -> Result<()> {
    if is_placeholder_ref(r) {
        return Err(Error::Message(format!(
            "{var} still has placeholder ref {r}"
        )));
    }
    if r.is_empty() {
        return Err(Error::Message(format!("empty reference for {var}")));
    }
    // None of the four Bitwarden reference forms contain `=`. A second
    // `VAR=name:KEY` glued onto this one is the bash 0.3.0 refresh merge
    // (command substitution strips the trailing newline). Fail closed with
    // the recovered lines rather than sending the blob to the vault.
    if r.contains('=') {
        let glued = format!("{var}={r}");
        if let Some(parts) = crate::refs::split_glued_bitwarden_line(&glued) {
            let listed = parts
                .iter()
                .map(|p| format!("  {p}"))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(Error::Message(format!(
                "{var} looks like several mappings glued onto one line \
                 (va 0.3.0 refresh merge dropped the newlines). \
                 Split each onto its own line:\n{listed}\n\
                 Or run: vaulted-agent refresh"
            )));
        }
        return Err(Error::Message(format!(
            "{var} bad bitwarden ref {r} (a reference cannot contain '=')"
        )));
    }
    if let Some(rest) = r.strip_prefix("uuid:") {
        if !is_uuid(rest) {
            return Err(Error::Message(format!(
                "{var} uuid: value is not a UUID: {r}"
            )));
        }
        return Ok(());
    }
    if let Some(rest) = r.strip_prefix("name:") {
        if rest.is_empty() {
            return Err(Error::Message(format!("{var} empty name: ref")));
        }
        return Ok(());
    }
    if let Some(rest) = r.strip_prefix("project:") {
        let Some((p, s)) = rest.split_once('/') else {
            return Err(Error::Message(format!(
                "{var} want project:PROJECT/SECRET (got {r})"
            )));
        };
        if p.is_empty() || s.is_empty() {
            return Err(Error::Message(format!(
                "{var} want project:PROJECT/SECRET (got {r})"
            )));
        }
        return Ok(());
    }
    if is_uuid(r) {
        return Ok(());
    }
    Err(Error::Message(format!(
        "{var} bad bitwarden ref {r} (use UUID, uuid:UUID, name:KEY, or project:PROJECT/KEY)"
    )))
}

pub fn validate_manifest_text(text: &str, backend: Backend) -> Result<Vec<(String, String)>> {
    // Shared KEY=value policy with resolve (quotes, multiline, var names).
    let pairs = crate::config::parse_dotenv_pairs(text)?;
    let mut out = Vec::with_capacity(pairs.len());
    for (var, mut r) in pairs {
        // A Bitwarden refs line may record the secret it was generated from as
        // a trailing `# uuid:…` (ADR-0004). Stripping it here — once, at the
        // one seam every reader already goes through — is the whole cost of the
        // format change on the launch path (story #44): `resolve_bitwarden`
        // never learns the recording exists.
        //
        // Bitwarden only. A plainfile or sops manifest holds secret *values*,
        // where a `#` is material and dropping the tail would truncate it.
        if backend == Backend::Bitwarden {
            r = crate::refs::reference_of(&r).to_string();
        }
        if r.is_empty() {
            return Err(Error::Message(format!("empty reference for {var}")));
        }
        match backend {
            Backend::Bitwarden => validate_bitwarden_ref(&var, &r)?,
            Backend::OnePassword | Backend::Pass => {
                if is_placeholder_ref(&r) {
                    return Err(Error::Message(format!(
                        "{var} still has placeholder ref {r}"
                    )));
                }
            }
            Backend::Plainfile | Backend::Sops => {
                if is_placeholder_secret_value(&r) {
                    return Err(Error::Message(format!(
                        "{var} looks like a placeholder value"
                    )));
                }
            }
        }
        out.push((var, r));
    }
    Ok(out)
}

/// 1-based line numbers of `#` comments that contain an `op://` token.
///
/// `op inject` resolves references in comments too; one failed lookup aborts
/// the whole file. Shared by doctor and `edit-manifest` so the two agree.
pub fn comment_lines_with_op_refs(text: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim_start();
        if !line.starts_with('#') {
            continue;
        }
        // Same rough scanner as op: a whitespace-delimited token that claims
        // to be a reference is enough to fail inject if it does not resolve.
        for tok in line.split_whitespace() {
            if tok.starts_with("op://") {
                lines.push(n + 1);
                break;
            }
        }
    }
    lines
}

/// Name the variables whose reference mentions something in a resolver error.
///
/// `op inject` fails the whole file at the first reference it cannot read and
/// reports the item, not the variable. The operator needs the variable: that is
/// what they will grep the manifest for. Matching the item name back to the
/// lines that use it turns "could not find item X" into the two or three
/// entries actually at fault, without a round trip per reference.
pub fn blame_manifest_lines(manifest: &Path, error: &str) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(manifest) else {
        return Vec::new();
    };
    let mut blamed = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || !line.contains('=') {
            continue;
        }
        let Some((var, value)) = line.split_once('=') else {
            continue;
        };
        let (var, value) = (var.trim(), value.trim());
        // Quoted values are still references once the outer quotes are gone.
        let value = value
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(value);
        if !value.starts_with("op://") {
            continue;
        }
        // The item component is what op names when it cannot resolve one.
        let parts: Vec<&str> = value[5..].split('/').collect();
        if parts.len() < 2 || parts[1].is_empty() {
            continue;
        }
        let item = parts[1];
        // Match "item <title>" as op phrases it, not a bare substring of the
        // title: a short name must not hitch a ride on a longer title's error.
        if error_names_op_item(error, item) {
            blamed.push(format!("{var}\n      {value}"));
        }
    }
    blamed
}

/// True when `error` names this 1Password item the way `op` does.
fn error_names_op_item(error: &str, item: &str) -> bool {
    let needle = format!("item {item}");
    let bytes = error.as_bytes();
    let mut start = 0;
    while let Some(rel) = error[start..].find(&needle) {
        let after = start + rel + needle.len();
        let boundary = match bytes.get(after) {
            None => true,
            Some(b) => !b.is_ascii_alphanumeric() && *b != b'-' && *b != b'_',
        };
        if boundary {
            return true;
        }
        start += rel + 1;
    }
    false
}

/// Every problem in a manifest, each with its line number.
///
/// `validate_manifest_text` stops at the first error, which is right for a
/// pre-flight gate: one problem means the launch must not proceed. An editor
/// wants the opposite — show everything wrong so the operator fixes it in one
/// pass rather than rediscovering the next fault on each save.
///
/// The `op://` check earns its place here. A reference `op inject` cannot read
/// does not fail alone: the scanner stops at the offending character, the
/// reference comes out truncated, and the whole injection aborts. One typo
/// therefore costs every other variable in the file, so it is worth catching
/// while the editor is still open. Comments are included: inject reads them.
pub fn manifest_problems(text: &str) -> Vec<String> {
    let mut problems = Vec::new();

    // Structural faults (unbalanced quotes, a value that runs off the end) come
    // from the same parser resolve uses, so the editor agrees with the launch.
    if let Err(e) = crate::config::parse_dotenv_pairs(text) {
        problems.push(format!("{e}"));
    }

    for n in comment_lines_with_op_refs(text) {
        problems.push(format!(
            "line {n}: comment contains a secret reference (op://…). \
             `op inject` resolves references in comments too, and one that fails \
             aborts the whole manifest"
        ));
    }

    let mut seen: Vec<String> = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((var, value)) = line.split_once('=') else {
            continue; // a continuation line of a quoted value, or noise
        };
        let (var, value) = (var.trim(), value.trim());
        if var.is_empty() || !validate_var_name(var) {
            problems.push(format!(
                "line {}: '{var}' is not a valid variable name",
                n + 1
            ));
            continue;
        }
        if seen.iter().any(|s| s == var) {
            problems.push(format!("line {}: {var} is set more than once", n + 1));
        } else {
            seen.push(var.to_string());
        }
        if value.starts_with("op://") && !crate::refs::op_reference_is_parseable(value) {
            problems.push(format!(
                "line {}: {var} has a reference op cannot parse ({value}) \u{2014} \
                 one such reference aborts the whole manifest, not just this line",
                n + 1
            ));
        }
    }
    problems
}

pub fn validate_manifest_file(path: &Path, backend: Backend) -> Result<Vec<(String, String)>> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    validate_manifest_text(&text, backend)
        .map_err(|e| Error::Message(format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comment_lines_with_op_refs_finds_only_references() {
        let text = "\
# prose about 1Password, no reference\n\
# see op://Vault/item/field\n\
GOOD=op://Vault/item/field\n\
# TODO: clean this up\n";
        assert_eq!(comment_lines_with_op_refs(text), vec![2]);
    }

    #[test]
    fn manifest_problems_flags_comment_refs() {
        let text = "# note op://Vault/x/y\nA=op://Vault/item/field\n";
        let p = manifest_problems(text);
        assert!(
            p.iter()
                .any(|s| s.contains("comment") && s.contains("line 1")),
            "{p:?}"
        );
    }

    #[test]
    fn rejects_placeholder() {
        assert!(validate_bitwarden_ref("X", "REPLACE_WITH_BITWARDEN_SECRET_UUID").is_err());
    }

    #[test]
    fn accepts_name_ref() {
        assert!(validate_bitwarden_ref("OPENAI_API_KEY", "name:openai-api-key").is_ok());
    }

    #[test]
    fn accepts_uuid() {
        assert!(validate_bitwarden_ref("X", "6a1c0e94-1111-2222-3333-444444444444").is_ok());
    }

    #[test]
    fn pass_path_example_com_is_not_placeholder() {
        assert!(!is_placeholder_ref("example.com/token"));
        assert!(validate_manifest_text("API=example.com/token\n", Backend::Pass).is_ok());
    }

    #[test]
    fn unknown_backend_is_a_type_error_not_a_match_arm() {
        // Compiles only because Backend is exhaustive — this documents the intent.
        let _ = Backend::Plainfile;
    }

    #[test]
    fn secret_value_with_replace_substring_is_ok() {
        assert!(!is_placeholder_secret_value("please-REPLACE-this-password"));
        assert!(is_placeholder_secret_value("REPLACE_WITH_SECRET"));
    }

    #[test]
    fn validate_shares_quote_stripping_with_resolve() {
        let pairs = validate_manifest_text("QUOTED=\"hello world\"\n", Backend::Plainfile).unwrap();
        assert_eq!(pairs, vec![("QUOTED".into(), "hello world".into())]);
    }

    #[test]
    fn validate_multiline_does_not_split_continuation() {
        let pairs = validate_manifest_text("PEM=\"line1\nline2\"\n", Backend::Plainfile).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].1, "line1\nline2");
    }

    // ---- annotated bitwarden refs (issue #82, ADR-0004) ----

    #[test]
    fn an_annotated_bitwarden_ref_reaches_resolve_as_the_bare_reference() {
        // The launch path is deliberately small (story #44): stripping the
        // recording happens once, here, and `resolve_bitwarden` never learns
        // the format changed.
        let u = "11111111-1111-1111-1111-111111111111";
        let text = format!("ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{u}\n");
        let pairs = validate_manifest_text(&text, Backend::Bitwarden).unwrap();
        assert_eq!(
            pairs,
            vec![(
                "ASSEMBLY_AI_API_KEY".to_string(),
                "name:ASSEMBLY_AI_API_KEY".to_string()
            )]
        );
    }

    #[test]
    fn a_stale_recording_does_not_fail_the_pre_flight_gate() {
        // The line resolves, so validate must not block it (invariant 5). A
        // disagreement between the recording and the key is `refresh`'s signal
        // to report a rename, not a misconfiguration.
        let text = "A=name:A_KEY # uuid:11111111-1111-1111-1111-111111111111\n";
        assert!(validate_manifest_text(text, Backend::Bitwarden).is_ok());
    }

    #[test]
    fn a_hash_inside_a_secret_value_is_still_part_of_the_value() {
        // The recording is a Bitwarden-refs concept. Stripping comments from
        // dotenv secret material would silently truncate passwords.
        let pairs =
            validate_manifest_text("PW=s3cret # not-a-comment\n", Backend::Plainfile).unwrap();
        assert_eq!(pairs[0].1, "s3cret # not-a-comment");
    }

    #[test]
    fn an_annotation_cannot_smuggle_a_placeholder_past_the_gate() {
        // Invariant 4: the reference itself is what must be real.
        let text = "A=name: # uuid:11111111-1111-1111-1111-111111111111\n";
        assert!(validate_manifest_text(text, Backend::Bitwarden).is_err());
    }

    #[test]
    fn a_glued_0_3_0_refresh_line_fails_closed_with_the_recovered_mappings() {
        // The launch used to send the whole blob to the vault and report
        // `no secret matched 'name:META_AI_API_KEYFIREWORKS_API_KEY=name:…'`.
        // Shape is validate's job (CONTEXT.md: malformed ref).
        let text = "META_AI_API_KEY=name:META_AI_API_KEYFIREWORKS_API_KEY=name:FIREWORKS_API_KEYELEVENLABS_API_KEY=name:ELEVENLABS_API_KEY\n";
        let err = validate_manifest_text(text, Backend::Bitwarden)
            .unwrap_err()
            .to_string();
        assert!(err.contains("glued onto one line"), "{err}");
        assert!(
            err.contains("META_AI_API_KEY=name:META_AI_API_KEY"),
            "{err}"
        );
        assert!(
            err.contains("FIREWORKS_API_KEY=name:FIREWORKS_API_KEY"),
            "{err}"
        );
        assert!(
            err.contains("ELEVENLABS_API_KEY=name:ELEVENLABS_API_KEY"),
            "{err}"
        );
        assert!(err.contains("vaulted-agent refresh"), "{err}");
    }
}
