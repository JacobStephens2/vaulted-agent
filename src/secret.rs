//! Secret-safe wrappers: redacted on Display/Debug so logs and errors do not leak.

use std::fmt;

/// Vault manager token (BWS_ACCESS_TOKEN, OP_SERVICE_ACCOUNT_TOKEN, …).
#[derive(Clone)]
pub struct ManagerToken(String);

impl ManagerToken {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// Access raw material only at the vault-CLI / inject boundary.
    /// `pub(crate)`: CLI is the sole public acceptance seam (story #50).
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ManagerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagerToken([redacted])")
    }
}

impl fmt::Display for ManagerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

/// A single resolved secret value destined for the child environment.
#[derive(Clone)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([redacted])")
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_token_display_and_debug_are_redacted() {
        let t = ManagerToken::new("sk-super-secret");
        assert_eq!(format!("{t}"), "[redacted]");
        assert_eq!(format!("{t:?}"), "ManagerToken([redacted])");
        assert!(!format!("{t:?}").contains("sk-super"));
        assert_eq!(t.expose(), "sk-super-secret");
    }

    #[test]
    fn secret_value_display_and_debug_are_redacted() {
        let v = SecretValue::new("corr3ct-h0rse");
        assert_eq!(format!("{v}"), "[redacted]");
        assert!(!format!("{v:?}").contains("corr3ct"));
    }
}
