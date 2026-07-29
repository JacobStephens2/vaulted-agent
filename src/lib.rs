//! vaulted-agent library — config, secrets types, and (later) launch/backends.

pub mod config;
pub mod error;
pub mod secret;

pub use config::{AuthMode, Harness, Paths, load_auth_mode, list_harness_names};
pub use error::{Error, Result};
pub use secret::{ManagerToken, SecretValue};
