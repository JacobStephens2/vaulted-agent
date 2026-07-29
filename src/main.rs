//! vaulted-agent — launch AI coding agents with vault-resolved secrets.
//!
//! Rust runtime (migration in progress). Bash `bin/vaulted-agent` remains
//! until the release-cut ticket retires it.

use std::env;
use std::process;

use vaulted_agent::config::{Harness, Paths, load_auth_mode, list_harness_names};

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("version") | Some("--version") | Some("-V") => {
            println!("vaulted-agent {}", env!("CARGO_PKG_VERSION"));
        }
        Some("auth-mode") if matches!(args.next().as_deref(), None | Some("show")) => {
            // Minimal show for config ticket (full set command later)
            let paths = Paths::discover();
            let mode = load_auth_mode(&paths);
            println!("auth_mode={}", mode.as_str());
        }
        Some(name) if !name.starts_with('-') => {
            // Config load path: prove harness loading fails closed before launch exists
            let paths = Paths::discover();
            match Harness::load(&paths, name) {
                Ok(h) => {
                    eprintln!(
                        "vaulted-agent: harness '{name}' loaded (manifest={}, command={:?}); launch not implemented yet",
                        h.manifest, h.command
                    );
                    process::exit(2);
                }
                Err(e) => {
                    eprintln!("vaulted-agent: {e}");
                    if let Ok(names) = list_harness_names(&paths) {
                        if !names.is_empty() {
                            eprintln!("harnesses: {}", names.join(", "));
                        }
                    }
                    process::exit(1);
                }
            }
        }
        Some(other) => {
            eprintln!("vaulted-agent: unknown option or command '{other}'");
            usage();
            process::exit(1);
        }
        None => {
            usage();
            let paths = Paths::discover();
            if let Ok(names) = list_harness_names(&paths) {
                if names.is_empty() {
                    eprintln!("harnesses: (none under {})", paths.harness_dir.display());
                } else {
                    eprintln!("harnesses:");
                    for n in names {
                        eprintln!("  {n}");
                    }
                }
            }
            process::exit(1);
        }
    }
}

fn usage() {
    eprintln!(
        "usage: vaulted-agent <harness> | version | auth-mode show\n       (Rust runtime — launch backends still migrating from Bash)"
    );
}
