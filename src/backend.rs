//! Vault backends: resolve a manifest into env var → SecretValue.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::config::{parse_dotenv_keys, Backend, Paths};
use crate::error::{Error, Result};
use crate::secret::{ManagerToken, SecretValue};
use crate::validate::{is_placeholder_secret_value, is_uuid, validate_manifest_file};

fn run_capture(program: &str, args: &[&str], env: &[(&str, &str)]) -> Result<String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .map_err(|e| Error::Message(format!("{program}: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(Error::Message(format!(
            "{program} {} failed: {err}",
            args.join(" ")
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn resolve_plainfile(manifest: &Path) -> Result<HashMap<String, SecretValue>> {
    let _ = validate_manifest_file(manifest, Backend::Plainfile)?;
    let text = fs::read_to_string(manifest).map_err(|e| Error::Io {
        path: manifest.to_path_buf(),
        source: e,
    })?;
    let raw = parse_dotenv_keys(&text)?;
    Ok(raw
        .into_iter()
        .map(|(k, v)| (k, SecretValue::new(v)))
        .collect())
}

fn bws_list_json(token: &ManagerToken) -> Result<String> {
    run_capture(
        "bws",
        &["secret", "list", "--output", "json"],
        &[("BWS_ACCESS_TOKEN", token.expose())],
    )
}

/// Parse bws secret list JSON into (id, key, project_name) rows.
pub fn parse_bws_list_json(list_json: &str) -> Result<Vec<(String, String, String)>> {
    let v: serde_json::Value = serde_json::from_str(list_json)
        .map_err(|e| Error::Message(format!("bws secret list JSON: {e}")))?;
    let arr = match &v {
        serde_json::Value::Array(a) => a.clone(),
        serde_json::Value::Object(o) => o
            .get("data")
            .or_else(|| o.get("secrets"))
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    let mut rows = Vec::new();
    for s in arr {
        let id = s
            .get("id")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if id.is_empty() {
            continue;
        }
        let key = s
            .get("key")
            .or_else(|| s.get("name"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let proj = match s.get("project") {
            Some(serde_json::Value::Object(p)) => p
                .get("name")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            Some(serde_json::Value::String(s)) => s.clone(),
            _ => String::new(),
        };
        rows.push((id, key, proj));
    }
    Ok(rows)
}

fn parse_bws_ref(list_json: &str, r: &str) -> Result<String> {
    let rows = parse_bws_list_json(list_json)?;
    if let Some(want_name) = r.strip_prefix("name:") {
        let matches: Vec<_> = rows.iter().filter(|(_, k, _)| k == want_name).collect();
        if matches.is_empty() {
            return Err(Error::Message(format!("no secret matched {r}")));
        }
        if matches.len() > 1 {
            return Err(Error::Message(format!(
                "multiple secrets named {want_name}; use project:PROJECT/{want_name}"
            )));
        }
        return Ok(matches[0].0.clone());
    }
    if let Some(rest) = r.strip_prefix("project:") {
        let Some((p, s)) = rest.split_once('/') else {
            return Err(Error::Message("project: ref needs PROJECT/SECRET".into()));
        };
        let m = rows
            .iter()
            .find(|(_, k, proj)| k == s && proj == p)
            .ok_or_else(|| Error::Message(format!("no secret matched {r}")))?;
        return Ok(m.0.clone());
    }
    Err(Error::Message(format!("bad bitwarden ref {r}")))
}

fn bws_resolve_ref_to_id(token: &ManagerToken, r: &str) -> Result<String> {
    let bare = r.strip_prefix("uuid:").unwrap_or(r);
    if is_uuid(bare) {
        return Ok(bare.to_string());
    }
    let list = bws_list_json(token)?;
    parse_bws_ref(&list, r)
}

/// Extract secret value from `bws secret get --output json`.
pub fn parse_bws_get_value_json(stdout: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|e| Error::Message(format!("bws secret get JSON: {e}")))?;
    v.get("value")
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Message("bws secret get missing value field".into()))
}

fn bws_get_value(token: &ManagerToken, id: &str) -> Result<String> {
    let stdout = run_capture(
        "bws",
        &["secret", "get", id, "--output", "json"],
        &[("BWS_ACCESS_TOKEN", token.expose())],
    )?;
    parse_bws_get_value_json(&stdout)
}

/// Resolve a bitwarden ref to secret id (for secrets get).
pub fn bws_resolve_ref(token: &ManagerToken, r: &str) -> Result<String> {
    bws_resolve_ref_to_id(token, r)
}

/// Fetch secret value by id (for secrets get).
pub fn bws_secret_value(token: &ManagerToken, id: &str) -> Result<String> {
    bws_get_value(token, id)
}

pub fn resolve_bitwarden(
    manifest: &Path,
    token: &ManagerToken,
) -> Result<HashMap<String, SecretValue>> {
    let pairs: Vec<(String, String)> = validate_manifest_file(manifest, Backend::Bitwarden)?;
    let mut out = HashMap::new();
    for (var, r) in pairs {
        let id = bws_resolve_ref_to_id(token, &r)?;
        let value = bws_get_value(token, &id)?;
        out.insert(var, SecretValue::new(value));
    }
    Ok(out)
}

pub fn resolve_onepassword(
    manifest: &Path,
    token: &ManagerToken,
) -> Result<HashMap<String, SecretValue>> {
    let _ = validate_manifest_file(manifest, Backend::OnePassword)?;
    let stdout = run_capture(
        "op",
        &["inject", "-i", &manifest.to_string_lossy()],
        &[("OP_SERVICE_ACCOUNT_TOKEN", token.expose())],
    )?;
    let raw = parse_dotenv_keys(&stdout)?;
    Ok(raw
        .into_iter()
        .map(|(k, v)| (k, SecretValue::new(v)))
        .collect())
}

pub fn resolve_pass(manifest: &Path) -> Result<HashMap<String, SecretValue>> {
    let pairs: Vec<(String, String)> = validate_manifest_file(manifest, Backend::Pass)?;
    let mut out = HashMap::new();
    for (var, r) in pairs {
        let stdout = run_capture("pass", &["show", &r], &[])?;
        // Full multi-line password store entry (first line is conventionally the secret).
        // Keep the whole body so multi-line notes are not truncated into false env vars.
        let value = stdout.trim_end_matches('\n').to_string();
        out.insert(var, SecretValue::new(value));
    }
    Ok(out)
}

fn validate_decrypted_dotenv(text: &str, backend: Backend) -> Result<()> {
    // Fail closed on clear misconfiguration only — not on legitimate secret values
    // that happen to contain substrings like "REPLACE".
    for (var, val) in parse_dotenv_keys(text)? {
        if is_placeholder_secret_value(&val) {
            return Err(Error::Message(format!(
                "{backend}: {var} looks like a placeholder value"
            )));
        }
    }
    Ok(())
}

pub fn resolve_sops(manifest: &Path, age_key: &Path) -> Result<HashMap<String, SecretValue>> {
    if !age_key.is_file() {
        return Err(Error::Message(format!(
            "backend 'sops' needs {}",
            age_key.display()
        )));
    }
    let stdout = run_capture(
        "sops",
        &["--decrypt", &manifest.to_string_lossy()],
        &[("SOPS_AGE_KEY_FILE", &age_key.to_string_lossy())],
    )?;
    validate_decrypted_dotenv(&stdout, Backend::Sops)?;
    let raw = parse_dotenv_keys(&stdout)?;
    if raw.is_empty() && !stdout.trim().is_empty() {
        // Still allow empty after comments-only; if ciphertext decrypt produced
        // unparseable lines, surface that as fail-closed when no keys.
        let has_kv = stdout.lines().any(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && t.contains('=')
        });
        if has_kv {
            return Err(Error::Message(
                "sops: decrypted content has no valid KEY=value lines".into(),
            ));
        }
    }
    Ok(raw
        .into_iter()
        .map(|(k, v)| (k, SecretValue::new(v)))
        .collect())
}

pub fn resolve(
    backend: Backend,
    manifest: &Path,
    paths: &Paths,
    token: Option<&ManagerToken>,
) -> Result<HashMap<String, SecretValue>> {
    match backend {
        Backend::Plainfile => resolve_plainfile(manifest),
        Backend::Bitwarden => {
            let t = token.ok_or_else(|| Error::Message("bitwarden needs manager token".into()))?;
            resolve_bitwarden(manifest, t)
        }
        Backend::OnePassword => {
            let t =
                token.ok_or_else(|| Error::Message("onepassword needs manager token".into()))?;
            resolve_onepassword(manifest, t)
        }
        Backend::Pass => resolve_pass(manifest),
        Backend::Sops => resolve_sops(manifest, &paths.age_key_file),
    }
}

/// List SM secrets as (id, key, project) for setup/refresh/secrets list.
pub fn bws_list_secrets(token: &ManagerToken) -> Result<Vec<(String, String, String)>> {
    let list = bws_list_json(token)?;
    parse_bws_list_json(&list)
}

/// List 1Password items the token can see, as (id, title, vault name).
///
/// Items only - fields are fetched per item in `op_item_field_labels`, because
/// `op item list` does not include them and expanding every item up front costs
/// one `op` call per item (~50s for a 60-item vault).
pub fn op_list_items(
    token: &ManagerToken,
    vault: Option<&str>,
) -> Result<Vec<(String, String, String)>> {
    let mut args: Vec<&str> = vec!["item", "list", "--format", "json"];
    if let Some(v) = vault {
        args.push("--vault");
        args.push(v);
    }
    let json = run_capture("op", &args, &[("OP_SERVICE_ACCOUNT_TOKEN", token.expose())])?;
    parse_op_item_list_json(&json)
}

/// Parse `op item list --format json` into (id, title, vault name) rows.
pub fn parse_op_item_list_json(list_json: &str) -> Result<Vec<(String, String, String)>> {
    let v: serde_json::Value = serde_json::from_str(list_json)
        .map_err(|e| Error::Message(format!("op item list JSON: {e}")))?;
    let arr = match &v {
        serde_json::Value::Array(a) => a.clone(),
        _ => return Err(Error::Message("op item list: expected a JSON array".into())),
    };
    let mut out = Vec::new();
    for it in arr {
        let id = it.get("id").and_then(|x| x.as_str()).unwrap_or_default();
        let title = it.get("title").and_then(|x| x.as_str()).unwrap_or_default();
        let vault = it
            .get("vault")
            .and_then(|x| x.get("name"))
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        if id.is_empty() || title.is_empty() {
            continue;
        }
        out.push((id.to_string(), title.to_string(), vault.to_string()));
    }
    Ok(out)
}

/// Field labels on one item that are worth a reference.
///
/// `vault` is required in practice: a service-account token cannot run
/// `op item get` without one ("a vault query must be provided when this command
/// is called by a service account"), and service accounts are how this tool
/// authenticates. It stays optional so a user-authenticated `op` still works.
///
/// Metadata only: a field is kept based on whether a value is PRESENT, and the
/// value itself is never returned, stored, or logged. Refs files hold
/// references, never secret material (CONTEXT.md invariant).
pub fn op_item_field_labels(
    token: &ManagerToken,
    item_id: &str,
    vault: Option<&str>,
) -> Result<Vec<OpField>> {
    let mut args: Vec<&str> = vec!["item", "get", item_id, "--format", "json"];
    if let Some(v) = vault.filter(|v| !v.is_empty()) {
        args.push("--vault");
        args.push(v);
    }
    let json = run_capture("op", &args, &[("OP_SERVICE_ACCOUNT_TOKEN", token.expose())])?;
    parse_op_item_fields_json(&json)
}

/// Parse `op item get --format json` into referenceable field labels.
pub fn parse_op_item_fields_json(item_json: &str) -> Result<Vec<OpField>> {
    let v: serde_json::Value = serde_json::from_str(item_json)
        .map_err(|e| Error::Message(format!("op item get JSON: {e}")))?;
    let mut out: Vec<OpField> = Vec::new();
    let Some(fields) = v.get("fields").and_then(|f| f.as_array()) else {
        return Ok(out);
    };
    for f in fields {
        // OTP fields are time-based; a static reference to one is not useful.
        let ty = f.get("type").and_then(|x| x.as_str()).unwrap_or_default();
        if ty.eq_ignore_ascii_case("OTP") {
            continue;
        }
        // Presence check only. Never bind the value to a name.
        let has_value = f
            .get("value")
            .map(|x| match x {
                serde_json::Value::Null => false,
                serde_json::Value::String(s) => !s.is_empty(),
                _ => true,
            })
            .unwrap_or(false);
        if !has_value {
            continue;
        }
        let label = f
            .get("label")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| f.get("id").and_then(|x| x.as_str()))
            .unwrap_or_default();
        if label.is_empty() {
            continue;
        }
        let section = op_section_name(&v, f);
        // One item can hold several fields with the SAME label in different
        // sections - a real vault has three distinct `password` fields on one
        // host item. They are different secrets, so the pair identifies a field,
        // not the label alone.
        if out.iter().any(|e| e.section == section && e.label == label) {
            continue;
        }
        out.push(OpField {
            section,
            label: label.to_string(),
        });
    }
    Ok(out)
}

/// A referenceable field: its section (when it is in one) and its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpField {
    pub section: Option<String>,
    pub label: String,
}

/// Section name for a field: the label when set, else the section id, resolved
/// against the item's top-level `sections` when the field only carries an id.
fn op_section_name(item: &serde_json::Value, field: &serde_json::Value) -> Option<String> {
    let sec = field.get("section")?;
    if let Some(l) = sec.get("label").and_then(|x| x.as_str()) {
        if !l.is_empty() {
            return Some(l.to_string());
        }
    }
    let id = sec
        .get("id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())?;
    let looked_up = item
        .get("sections")
        .and_then(|s| s.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|s| s.get("id").and_then(|x| x.as_str()) == Some(id))
                .and_then(|s| s.get("label").and_then(|x| x.as_str()))
                .filter(|l| !l.is_empty())
        });
    Some(looked_up.unwrap_or(id).to_string())
}

#[cfg(test)]
mod op_tests {
    use super::*;

    #[test]
    fn item_list_yields_id_title_and_vault() {
        let json = r#"[
          {"id":"a1","title":"anthropic","vault":{"id":"v","name":"Orchestrator"}},
          {"id":"a2","title":"github token","vault":{"id":"v","name":"Orchestrator"}}
        ]"#;
        let rows = parse_op_item_list_json(json).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            ("a1".into(), "anthropic".into(), "Orchestrator".into())
        );
        // Titles with spaces survive; op inject reads to end of line.
        assert_eq!(rows[1].1, "github token");
    }

    #[test]
    fn item_list_skips_rows_missing_id_or_title() {
        let json = r#"[{"id":"","title":"x"},{"id":"y","title":""},{"id":"ok","title":"t"}]"#;
        let rows = parse_op_item_list_json(json).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "ok");
    }

    #[test]
    fn item_list_rejects_non_array() {
        assert!(parse_op_item_list_json(r#"{"error":"nope"}"#).is_err());
    }

    fn labels(json: &str) -> Vec<String> {
        parse_op_item_fields_json(json)
            .unwrap()
            .into_iter()
            .map(|f| match f.section {
                Some(s) => format!("{s}/{}", f.label),
                None => f.label,
            })
            .collect()
    }

    #[test]
    fn fields_keep_only_referenceable_labels() {
        let json = r#"{"fields":[
          {"id":"f1","label":"api-key","type":"CONCEALED","value":"SECRET"},
          {"id":"f2","label":"blank","type":"STRING","value":""},
          {"id":"f3","label":"totp","type":"OTP","value":"otpauth://x"},
          {"id":"f4","label":"","type":"STRING","value":"v"},
          {"id":"f5","type":"STRING","value":"v"}
        ]}"#;
        // api-key kept; blank is empty; totp is OTP; f4 and f5 have no usable
        // label so they fall back to their ids.
        assert_eq!(labels(json), vec!["api-key", "f4", "f5"]);
    }

    #[test]
    fn same_label_in_different_sections_is_kept_as_distinct_fields() {
        // Shape taken from a real vault: one host item with a top-level password
        // plus one per section. These are three different secrets.
        let json = r#"{"sections":[{"id":"s1","label":"mysql"},{"id":"s2","label":"replica"}],
          "fields":[
          {"id":"f1","label":"password","type":"CONCEALED","value":"a"},
          {"id":"f2","label":"password","type":"CONCEALED","value":"b","section":{"id":"s1","label":"mysql"}},
          {"id":"f3","label":"password","type":"CONCEALED","value":"c","section":{"id":"s2"}}
        ]}"#;
        // f3 carries only a section id; the label is resolved from `sections`.
        assert_eq!(
            labels(json),
            vec!["password", "mysql/password", "replica/password"]
        );
    }

    #[test]
    fn section_falls_back_to_its_id_when_unresolvable() {
        let json = r#"{"fields":[
          {"id":"f1","label":"password","type":"CONCEALED","value":"a","section":{"id":"orphan"}}
        ]}"#;
        assert_eq!(labels(json), vec!["orphan/password"]);
    }

    #[test]
    fn fields_are_deduplicated_and_missing_fields_is_not_an_error() {
        // Same label AND same section: a genuine duplicate.
        let json = r#"{"fields":[
          {"id":"f1","label":"dup","type":"STRING","value":"a"},
          {"id":"f2","label":"dup","type":"STRING","value":"b"}
        ]}"#;
        assert_eq!(labels(json), vec!["dup"]);
        assert!(parse_op_item_fields_json(r#"{"id":"x"}"#)
            .unwrap()
            .is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_list_array() {
        let j = r#"[{"id":"a","key":"k1","project":{"name":"p"}}]"#;
        let rows = parse_bws_list_json(j).unwrap();
        assert_eq!(rows, vec![("a".into(), "k1".into(), "p".into())]);
    }

    #[test]
    fn parse_name_ref() {
        let j = r#"[{"id":"id1","key":"openai-api-key","project":{"name":"tools"}}]"#;
        assert_eq!(parse_bws_ref(j, "name:openai-api-key").unwrap(), "id1");
    }

    #[test]
    fn parse_get_value() {
        assert_eq!(
            parse_bws_get_value_json(r#"{"value":"sk-x"}"#).unwrap(),
            "sk-x"
        );
    }

    #[test]
    fn sops_placeholder_fails() {
        assert!(validate_decrypted_dotenv("X=REPLACE_WITH_SECRET\n", Backend::Sops).is_err());
    }

    #[test]
    fn sops_value_with_replace_substring_ok() {
        assert!(validate_decrypted_dotenv("X=please-REPLACE-now\n", Backend::Sops).is_ok());
    }
}
