//! vaulted-agent — launch AI coding agents with vault-resolved secrets.
//!
//! Rust runtime (migration in progress). Bash `bin/vaulted-agent` remains
//! until the release-cut ticket retires it.

use std::env;
use std::process;

use vaulted_agent::config::{Harness, Paths, load_auth_mode, list_harness_names};
use vaulted_agent::launch;

fn main() {
    // Preserve caller cwd for workdir=caller across future sudo re-exec.
    if env::var_os("VAULTED_AGENT_CALLER_CWD").is_none() {
        if let Ok(cwd) = env::current_dir() {
            // SAFETY: single-threaded at startup before threads spawn
            env::set_var("VAULTED_AGENT_CALLER_CWD", cwd);
        }
    }

    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("version") | Some("--version") | Some("-V") => {
            println!("vaulted-agent {}", env!("CARGO_PKG_VERSION"));
        }
        Some("auth-mode") if matches!(args.next().as_deref(), None | Some("show")) => {
            let paths = Paths::discover();
            let mode = load_auth_mode(&paths);
            println!("auth_mode={}", mode.as_str());
        }
        Some(name) if !name.starts_with('-') => {
            let paths = Paths::discover();
            let harness = match Harness::load(&paths, name) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("vaulted-agent: {e}");
                    if let Ok(names) = list_harness_names(&paths) {
                        if !names.is_empty() {
                            eprintln!("harnesses: {}", names.join(", "));
                        }
                    }
                    process::exit(1);
                }
            };
            if let Err(e) = launch::launch_harness(&paths, &harness) {
                eprintln!("vaulted-agent: {e}");
                process::exit(1);
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
        "usage: vaulted-agent <harness> | version | auth-mode show\n\
         config: VAULTED_AGENT_CONFIG_DIR (default /etc/vaulted-agent)\n\
         tests:  VAULTED_AGENT_HANDOFF=spawn to spawn instead of exec"
    );
}
