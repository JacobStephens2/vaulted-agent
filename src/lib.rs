//! vaulted-agent library — config, secrets, env scrub, launch, backends.

pub mod auth;
pub mod backend;
pub mod bitwarden;
pub mod commands;
pub mod conf_file;
pub mod config;
pub mod defaults;
pub mod env_scrub;
pub mod error;
mod file_replace;
mod harness_sync;
pub mod inventory;
pub mod launch;
mod launch_plan;
pub mod manifest_entry;
pub mod onepassword;
mod preflight;
pub mod privilege;
mod refresh;
pub mod refs;
pub mod resume;
pub mod route;
pub mod secret;
pub mod update;
pub mod validate;
mod vault_wiring;
mod workdir;

pub use config::{list_harness_names, AuthMode, Backend, Harness, Paths};
pub use error::{Error, Result};
pub use secret::{ManagerToken, SecretValue};
