//! Build the child process environment: allowlist + keep= + injected secrets only.

use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};

use crate::secret::SecretValue;

/// Variables that may pass through from the parent when present.
pub const PASSTHROUGH: &[&str] = &[
    "HOME",
    "PATH",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "COLORTERM",
    "TZ",
    "LANG",
    "LC_ALL",
];

/// Manager-token env names that must never reach the child.
pub const MANAGER_TOKEN_VARS: &[&str] = &[
    "BWS_ACCESS_TOKEN",
    "OP_SERVICE_ACCOUNT_TOKEN",
    "SOPS_AGE_KEY_FILE",
];

/// Construct environment for the agent: passthrough + keep + secrets.
/// Explicit construction — not "inherit then subtract" — so nothing ambient rides along.
pub fn build_child_env(
    keep: &[String],
    secrets: &HashMap<String, SecretValue>,
) -> HashMap<OsString, OsString> {
    let mut out: HashMap<OsString, OsString> = HashMap::new();

    for &name in PASSTHROUGH {
        if let Ok(v) = env::var(name) {
            out.insert(OsString::from(name), OsString::from(v));
        }
    }
    for name in keep {
        if MANAGER_TOKEN_VARS.contains(&name.as_str()) {
            continue;
        }
        if let Ok(v) = env::var(name) {
            out.insert(OsString::from(name.as_str()), OsString::from(v));
        }
    }
    for (k, secret) in secrets {
        if MANAGER_TOKEN_VARS.contains(&k.as_str()) {
            continue;
        }
        out.insert(OsString::from(k.as_str()), OsString::from(secret.expose()));
    }
    // Never re-inject manager tokens even if present in secrets map by mistake
    for &name in MANAGER_TOKEN_VARS {
        out.remove(OsStr::new(name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize env-mutating tests
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn parent_secret_not_in_child_env() {
        let _g = LOCK.lock().unwrap();
        env::set_var("PARENT_ONLY_SECRET", "leak-me");
        env::set_var("HOME", "/tmp/home-test");
        let secrets =
            HashMap::from([("APP_DB_PASS".to_string(), SecretValue::new("injected-only"))]);
        let child = build_child_env(&[], &secrets);
        assert!(!child.contains_key(OsStr::new("PARENT_ONLY_SECRET")));
        assert_eq!(
            child
                .get(OsStr::new("APP_DB_PASS"))
                .map(|s| s.to_string_lossy()),
            Some("injected-only".into())
        );
        assert!(child.contains_key(OsStr::new("HOME")));
        env::remove_var("PARENT_ONLY_SECRET");
    }

    #[test]
    fn keep_allows_named_passthrough() {
        let _g = LOCK.lock().unwrap();
        env::set_var("SSH_AUTH_SOCK", "/tmp/ssh.sock");
        let child = build_child_env(&["SSH_AUTH_SOCK".into()], &HashMap::new());
        assert_eq!(
            child
                .get(OsStr::new("SSH_AUTH_SOCK"))
                .map(|s| s.to_string_lossy().into_owned()),
            Some("/tmp/ssh.sock".into())
        );
        env::remove_var("SSH_AUTH_SOCK");
    }

    #[test]
    fn manager_token_never_in_child_even_if_in_secrets() {
        let _g = LOCK.lock().unwrap();
        let secrets = HashMap::from([(
            "BWS_ACCESS_TOKEN".to_string(),
            SecretValue::new("should-not-leak"),
        )]);
        let child = build_child_env(&[], &secrets);
        assert!(!child.contains_key(OsStr::new("BWS_ACCESS_TOKEN")));
    }
}
