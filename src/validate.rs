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
    let mut pairs = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim().trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(Error::Message(format!(
                "line {}: expected VAR=reference",
                lineno + 1
            )));
        };
        let var = k.trim();
        let r = v.trim();
        if !validate_var_name(var) {
            return Err(Error::Message(format!(
                "line {}: bad variable name {var}",
                lineno + 1
            )));
        }
        if r.is_empty() {
            return Err(Error::Message(format!(
                "line {}: empty reference for {var}",
                lineno + 1
            )));
        }
        match backend {
            Backend::Bitwarden => validate_bitwarden_ref(var, r)?,
            Backend::OnePassword | Backend::Pass => {
                if is_placeholder_ref(r) {
                    return Err(Error::Message(format!(
                        "{var} still has placeholder ref {r}"
                    )));
                }
            }
            Backend::Plainfile | Backend::Sops => {
                if is_placeholder_secret_value(r) {
                    return Err(Error::Message(format!(
                        "{var} looks like a placeholder value"
                    )));
                }
            }
        }
        pairs.push((var.to_string(), r.to_string()));
    }
    Ok(pairs)
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
}
