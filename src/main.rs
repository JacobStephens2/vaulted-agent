//! vaulted-agent — launch AI coding agents with vault-resolved secrets.
//!
//! Rust runtime (migration in progress). Bash `bin/vaulted-agent` remains
//! until the release-cut ticket retires it.

use std::env;
use std::process;

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("version") | Some("--version") | Some("-V") => {
            println!("vaulted-agent {}", env!("CARGO_PKG_VERSION"));
        }
        Some(other) => {
            eprintln!(
                "vaulted-agent: unknown command '{other}' (Rust runtime; only `version` is implemented so far)"
            );
            eprintln!("usage: vaulted-agent version | --version | -V");
            process::exit(1);
        }
        None => {
            eprintln!("usage: vaulted-agent version | --version | -V");
            process::exit(1);
        }
    }
}
