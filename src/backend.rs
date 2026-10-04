//! Vault backends: resolve a manifest into env var → SecretValue.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::auth::{TokenKind, TokenSource};
use crate::bitwarden::{BwListing, BwRef, Lookup};
use crate::config::{parse_dotenv_keys, Backend, Paths};
use crate::error::{Error, Result};
use crate::onepassword::OpListing;
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

/// The secret id a launch injects for `r`, judged against the listing.
///
/// The one place a lookup becomes the launch's errors. `refresh` judges the
/// same lookup, so a line it calls resolvable is exactly a line this accepts.
pub(crate) fn id_from_listing(listing: &BwListing, r: &str) -> Result<String> {
    match listing.lookup(r) {
        Lookup::Found(s) => Ok(s.id.clone()),
        // `name_the_manifest` recognises this wording; keep them in step.
        Lookup::Absent => Err(Error::Message(format!("no secret matched {r}"))),
        Lookup::Ambiguous(_) => Err(match BwRef::parse(r) {
            Some(BwRef::Name(key)) => Error::Message(format!(
                "multiple secrets named {key}; use project:PROJECT/{key}"
            )),
            // Same key in the same project: only the id tells them apart.
            _ => Error::Message(format!(
                "multiple secrets match {r}; use the secret's UUID (uuid:UUID)"
            )),
        }),
        // The launch validates first, so only `secrets get` reaches these. Each
        // keeps the wording it had before the shared parse (issue #120).
        Lookup::NotARef => Err(Error::Message(match r.strip_prefix("project:") {
            Some(rest) if !rest.contains('/') => "project: ref needs PROJECT/SECRET".into(),
            Some(_) => format!("no secret matched {r}"),
            None if r.starts_with("name:") => format!("no secret matched {r}"),
            None => format!("bad bitwarden ref {r}"),
        })),
    }
}

/// Lookup metadata lives only for one resolution; UUIDs need no listing.
struct BwsRefResolver<'a> {
    token: &'a ManagerToken,
    listing: Option<BwListing>,
}

impl<'a> BwsRefResolver<'a> {
    fn new(token: &'a ManagerToken) -> Self {
        Self {
            token,
            listing: None,
        }
    }

    fn resolve_id(&mut self, r: &str) -> Result<String> {
        // Saves one `bws secret list` per manifest of UUID refs. The answer is
        // the same: `bws secret get` on an id the token cannot see fails just
        // as a listing miss would.
        //
        // Checked on the UUID shape alone, as before the shared parse: a
        // placeholder UUID reaches `bws secret get` here, and the launch's
        // validate pass has already refused it.
        let bare = r.strip_prefix("uuid:").unwrap_or(r);
        if is_uuid(bare) {
            return Ok(bare.to_string());
        }
        let listing = match self.listing {
            Some(ref listing) => listing,
            None => self
                .listing
                .insert(BwListing::from_json(&bws_list_json(self.token)?)?),
        };
        id_from_listing(listing, r)
    }
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
    BwsRefResolver::new(token).resolve_id(r)
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
    let mut resolver = BwsRefResolver::new(token);
    for (var, r) in pairs {
        let id = resolver
            .resolve_id(&r)
            .map_err(|e| name_the_manifest(manifest, &var, e))?;
        let value = bws_get_value(token, &id)?;
        out.insert(var, SecretValue::new(value));
    }
    Ok(out)
}

/// Give a "no secret matched" its context: the resolver knows only the
/// reference, and the operator needs the variable, the file, and the way out.
///
/// Wrapped here rather than in the resolver, which is deliberately ignorant of
/// manifests — threading a path down into it would make every future backend
/// carry an argument it never uses. Other resolver failures pass through
/// untouched; only this one has a manifest-level fix (issue #80).
fn name_the_manifest(manifest: &Path, var: &str, e: Error) -> Error {
    let msg = e.to_string();
    if !msg.starts_with("no secret matched") {
        return e;
    }
    Error::Message(format!(
        "{msg} ({var} in {})\n  \
         The secret may have been renamed or removed. Remove the dangling \
         mapping with: vaulted-agent refresh --prune",
        manifest.display()
    ))
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

/// Resolve a Manifest into its variables. Loads the Manager token through
/// `token_source` only for the Backends that need one, and drops it before
/// returning: a resolved Manifest never carries it (invariant 1).
pub fn resolve(
    backend: Backend,
    manifest: &Path,
    paths: &Paths,
    token_source: TokenSource,
) -> Result<HashMap<String, SecretValue>> {
    match backend {
        Backend::Plainfile => resolve_plainfile(manifest),
        Backend::Bitwarden => {
            let token = token_source.load(paths, TokenKind::Bws)?;
            resolve_bitwarden(manifest, &token)
        }
        Backend::OnePassword => {
            let token = token_source.load(paths, TokenKind::Op)?;
            resolve_onepassword(manifest, &token)
        }
        Backend::Pass => resolve_pass(manifest),
        Backend::Sops => resolve_sops(manifest, &paths.age_key_file),
    }
}

/// The Bitwarden listing, for setup, refresh and `secrets list`.
pub fn bws_listing(token: &ManagerToken) -> Result<BwListing> {
    BwListing::from_json(&bws_list_json(token)?)
}

/// Verify a 1Password service-account token without touching any item.
///
/// `op whoami` is the cheapest live check the token can pass, and unlike
/// `item list` it does not depend on the account seeing any vault yet.
pub fn op_whoami(token: &ManagerToken) -> Result<()> {
    run_capture(
        "op",
        &["whoami", "--format", "json"],
        &[("OP_SERVICE_ACCOUNT_TOKEN", token.expose())],
    )?;
    Ok(())
}

/// List 1Password items the token can see.
///
/// Items only - fields are fetched per item with `op_item_json`, because
/// `op item list` does not include them and expanding every item up front costs
/// one `op` call per item (~50s for a 60-item vault).
pub fn op_list_items(token: &ManagerToken, vault: Option<&str>) -> Result<OpListing> {
    let mut args: Vec<&str> = vec!["item", "list", "--format", "json"];
    if let Some(v) = vault {
        args.push("--vault");
        args.push(v);
    }
    let json = run_capture("op", &args, &[("OP_SERVICE_ACCOUNT_TOKEN", token.expose())])?;
    OpListing::from_json(&json)
}

/// One `op item get`, returned raw for `OpListing::expand`, which reads it
/// twice for one round trip.
///
/// `vault` is required in practice: a service-account token cannot run
/// `op item get` without one ("a vault query must be provided when this command
/// is called by a service account"), and service accounts are how this tool
/// authenticates. It stays optional so a user-authenticated `op` still works.
pub fn op_item_json(token: &ManagerToken, item_id: &str, vault: Option<&str>) -> Result<String> {
    let mut args: Vec<&str> = vec!["item", "get", item_id, "--format", "json"];
    if let Some(v) = vault.filter(|v| !v.is_empty()) {
        args.push("--vault");
        args.push(v);
    }
    run_capture("op", &args, &[("OP_SERVICE_ACCOUNT_TOKEN", token.expose())])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_ref() {
        let j = r#"[{"id":"id1","key":"openai-api-key","project":{"name":"tools"}}]"#;
        let listing = BwListing::from_json(j).unwrap();
        assert_eq!(
            id_from_listing(&listing, "name:openai-api-key").unwrap(),
            "id1"
        );
    }

    #[test]
    fn a_lookup_maps_to_the_launch_errors() {
        let listing = BwListing::from_json(
            r#"[{"id":"b","key":"DUP","project":{"name":"tools"}},
                {"id":"c","key":"DUP","project":{"name":"tools"}}]"#,
        )
        .unwrap();
        let err = |r: &str| id_from_listing(&listing, r).unwrap_err().to_string();
        assert_eq!(err("name:GONE"), "no secret matched name:GONE");
        assert_eq!(
            err("name:DUP"),
            "multiple secrets named DUP; use project:PROJECT/DUP"
        );
        // A `project:` used to take the first match in listing order.
        let e = err("project:tools/DUP");
        assert!(
            e.contains("multiple secrets match project:tools/DUP"),
            "{e}"
        );
        assert!(e.contains("uuid:UUID"), "{e}");
        // Malformed refs keep their old wording (`secrets get` skips validate).
        assert_eq!(err("project:tools"), "project: ref needs PROJECT/SECRET");
        assert_eq!(err("project:/DUP"), "no secret matched project:/DUP");
        assert_eq!(err("name:"), "no secret matched name:");
        assert_eq!(err("junk"), "bad bitwarden ref junk");
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
