//! vaulted-agent library — config, secrets, env scrub, launch, backends.

pub mod backend;
pub mod config;
pub mod env_scrub;
pub mod error;
pub mod launch;
pub mod secret;

pub use config::{AuthMode, Harness, Paths, load_auth_mode, list_harness_names};
pub use error::{Error, Result};
pub use secret::{ManagerToken, SecretValue};
