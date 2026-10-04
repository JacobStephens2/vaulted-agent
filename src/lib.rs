//! vaulted-agent library — config, secrets, env scrub, launch, backends.

pub mod auth;
pub mod backend;
pub mod bitwarden;
pub mod commands;
pub mod config;
pub mod env_scrub;
pub mod error;
mod harness_sync;
pub mod inventory;
pub mod launch;
pub mod manifest_entry;
pub mod onepassword;
pub mod privilege;
mod refresh;
pub mod refs;
pub mod resume;
pub mod route;
pub mod secret;
pub mod update;
pub mod validate;
mod workdir;

pub use config::{list_harness_names, load_auth_mode, AuthMode, Backend, Harness, Paths};
pub use error::{Error, Result};
pub use secret::{ManagerToken, SecretValue};
