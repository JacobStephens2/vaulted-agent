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
