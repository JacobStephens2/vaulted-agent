//! Vault backends: resolve a manifest into env var → SecretValue.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::config::parse_dotenv_keys;
use crate::error::{Error, Result};
use crate::secret::SecretValue;

pub fn resolve_plainfile(manifest: &Path) -> Result<HashMap<String, SecretValue>> {
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

pub fn resolve(
    backend: &str,
    manifest: &Path,
) -> Result<HashMap<String, SecretValue>> {
    match backend {
        "plainfile" => resolve_plainfile(manifest),
        other => Err(Error::Message(format!(
            "backend '{other}' not implemented in Rust runtime yet (plainfile works)"
        ))),
    }
}
