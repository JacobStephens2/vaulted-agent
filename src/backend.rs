//! Vault backends: resolve a manifest into env var → SecretValue.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::config::parse_dotenv_keys;
use crate::error::{Error, Result};
use crate::secret::{ManagerToken, SecretValue};
use crate::validate::{is_uuid, validate_manifest_file};

fn run_capture(program: &str, args: &[&str], env: &[(&str, &str)]) -> Result<String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().map_err(|e| Error::Message(format!("{program}: {e}")))?;
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
    let _ = validate_manifest_file(manifest, "plainfile")?;
    let text = fs::read_to_string(manifest).map_err(|e| Error::Io {
        path: manifest.to_path_buf(),
        source: e,
    })?;
    let raw = parse_dotenv_keys(&text);
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

fn bws_resolve_ref_to_id(token: &ManagerToken, r: &str) -> Result<String> {
    let bare = r.strip_prefix("uuid:").unwrap_or(r);
    if is_uuid(bare) {
        return Ok(bare.to_string());
    }
    let list = bws_list_json(token)?;
    // Parse with minimal JSON: look for objects — use a tiny approach via python if needed?
    // Prefer pure Rust: simple string scan is fragile; use serde_json with one dep.
    // Keep zero serde for now: shell out to python3 for list parse only when name: used
    // Actually we already have python in fake bws tests. For production, add serde_json.
    parse_bws_ref(&list, r)
}

fn parse_bws_ref(list_json: &str, r: &str) -> Result<String> {
    // Use python3 for robust JSON when name/project refs — available on target hosts for bws users
    let out = Command::new("python3")
        .arg("-c")
        .arg(
            r#"import json,sys
ref=sys.argv[1]
data=json.load(sys.stdin)
if isinstance(data, dict):
    data=data.get("data") or data.get("secrets") or []
want_name=None
want_proj=None
if ref.startswith("name:"):
    want_name=ref[5:]
elif ref.startswith("project:"):
    rest=ref[8:]
    if "/" not in rest:
        sys.stderr.write("project: ref needs PROJECT/SECRET\n"); sys.exit(2)
    want_proj, want_name=rest.split("/",1)
else:
    sys.stderr.write("bad ref\n"); sys.exit(2)
matches=[]
for s in data or []:
    key=s.get("key") or s.get("name") or ""
    if key != want_name: continue
    p=s.get("project") or {}
    pn=p.get("name") if isinstance(p, dict) else str(p or "")
    if want_proj is not None and pn != want_proj: continue
    matches.append(s.get("id") or "")
if not matches:
    sys.stderr.write("no secret matched %r\n"% (ref,)); sys.exit(1)
if len(matches)>1 and want_proj is None:
    sys.stderr.write("multiple secrets named %r; use project:PROJECT/%s\n"% (want_name, want_name)); sys.exit(1)
print(matches[0], end="")
"#,
        )
        .arg(r)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(list_json.as_bytes())?;
            child.wait_with_output()
        })
        .map_err(|e| Error::Message(format!("resolve ref: {e}")))?;
    if !out.status.success() {
        return Err(Error::Message(format!(
            "could not resolve bitwarden ref '{r}': {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn bws_get_value(token: &ManagerToken, id: &str) -> Result<String> {
    let stdout = run_capture(
        "bws",
        &["secret", "get", id, "--output", "json"],
        &[("BWS_ACCESS_TOKEN", token.expose())],
    )?;
    // extract "value":"..."
    let out = Command::new("python3")
        .arg("-c")
        .arg("import json,sys; print(json.load(sys.stdin)['value'], end='')")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(stdout.as_bytes())?;
            child.wait_with_output()
        })
        .map_err(|e| Error::Message(format!("parse bws get: {e}")))?;
    if !out.status.success() {
        return Err(Error::Message(
            "bws secret get returned unparseable JSON".into(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn resolve_bitwarden(
    manifest: &Path,
    token: &ManagerToken,
) -> Result<HashMap<String, SecretValue>> {
    let pairs: Vec<(String, String)> = validate_manifest_file(manifest, "bitwarden")?;
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
    let _ = validate_manifest_file(manifest, "onepassword")?;
    let stdout = run_capture(
        "op",
        &["inject", "-i", &manifest.to_string_lossy()],
        &[("OP_SERVICE_ACCOUNT_TOKEN", token.expose())],
    )?;
    let raw = parse_dotenv_keys(&stdout);
    Ok(raw
        .into_iter()
        .map(|(k, v)| (k, SecretValue::new(v)))
        .collect())
}

pub fn resolve_pass(manifest: &Path) -> Result<HashMap<String, SecretValue>> {
    let pairs: Vec<(String, String)> = validate_manifest_file(manifest, "pass")?;
    let mut out = HashMap::new();
    for (var, r) in pairs {
        let stdout = run_capture("pass", &["show", &r], &[])?;
        let value = stdout.lines().next().unwrap_or("").to_string();
        out.insert(var, SecretValue::new(value));
    }
    Ok(out)
}

pub fn resolve_sops(manifest: &Path, age_key: &Path) -> Result<HashMap<String, SecretValue>> {
    if !age_key.is_file() {
        return Err(Error::Message(format!(
            "backend 'sops' needs {}",
            age_key.display()
        )));
    }
    let _ = validate_manifest_file(manifest, "sops").ok(); // decrypted content validated loosely
    let stdout = run_capture(
        "sops",
        &["--decrypt", &manifest.to_string_lossy()],
        &[("SOPS_AGE_KEY_FILE", &age_key.to_string_lossy())],
    )?;
    let raw = parse_dotenv_keys(&stdout);
    Ok(raw
        .into_iter()
        .map(|(k, v)| (k, SecretValue::new(v)))
        .collect())
}

pub fn resolve(
    backend: &str,
    manifest: &Path,
    paths: &crate::config::Paths,
    token: Option<&ManagerToken>,
) -> Result<HashMap<String, SecretValue>> {
    match backend {
        "plainfile" => resolve_plainfile(manifest),
        "bitwarden" => {
            let t = token.ok_or_else(|| Error::Message("bitwarden needs manager token".into()))?;
            resolve_bitwarden(manifest, t)
        }
        "onepassword" => {
            let t = token.ok_or_else(|| Error::Message("onepassword needs manager token".into()))?;
            resolve_onepassword(manifest, t)
        }
        "pass" => resolve_pass(manifest),
        "sops" => resolve_sops(manifest, &paths.age_key_file),
        other => Err(Error::Message(format!("unknown backend '{other}'"))),
    }
}

/// List SM secrets as (id, key, project) for setup/refresh/secrets list.
pub fn bws_list_secrets(token: &ManagerToken) -> Result<Vec<(String, String, String)>> {
    let list = bws_list_json(token)?;
    let out = Command::new("python3")
        .arg("-c")
        .arg(
            r#"import json,sys
data=json.load(sys.stdin)
if isinstance(data, dict):
    data=data.get("data") or data.get("secrets") or []
for s in data or []:
    i=s.get("id") or ""
    k=s.get("key") or s.get("name") or ""
    p=s.get("project") or {}
    pn=p.get("name") if isinstance(p, dict) else str(p or "")
    print(i+"\t"+k+"\t"+pn)
"#,
        )
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(list.as_bytes())?;
            child.wait_with_output()
        })
        .map_err(|e| Error::Message(format!("list secrets: {e}")))?;
    if !out.status.success() {
        return Err(Error::Message("failed to parse bws secret list".into()));
    }
    let mut rows = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut p = line.splitn(3, '\t');
        let id = p.next().unwrap_or("").to_string();
        let key = p.next().unwrap_or("").to_string();
        let proj = p.next().unwrap_or("").to_string();
        if !id.is_empty() {
            rows.push((id, key, proj));
        }
    }
    Ok(rows)
}
