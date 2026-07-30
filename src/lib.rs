//! vaulted-agent library — config, secrets, env scrub, launch, backends.

pub mod auth;
pub mod backend;
pub mod commands;
pub mod config;
pub mod env_scrub;
pub mod error;
pub mod launch;
pub mod privilege;
pub mod refs;
pub mod resume;
pub mod secret;
pub mod validate;

pub use config::{list_harness_names, load_auth_mode, AuthMode, Backend, Harness, Paths};
pub use error::{Error, Result};
pub use secret::{ManagerToken, SecretValue};
