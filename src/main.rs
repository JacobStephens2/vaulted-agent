//! vaulted-agent — launch AI coding agents with vault-resolved secrets.
//!
//! Rust is the shipped runtime (v0.4.0+). See MIGRATION.md.

use std::env;
use std::path::Path;
use std::process;

use vaulted_agent::commands;
use vaulted_agent::config::Paths;

fn main() {
    // Preserve caller cwd for workdir=caller across sudo re-exec.
    if env::var_os("VAULTED_AGENT_CALLER_CWD").is_none() {
        if let Ok(cwd) = env::current_dir() {
            // SAFETY: single-threaded at startup
            env::set_var("VAULTED_AGENT_CALLER_CWD", cwd);
        }
    }

    let argv: Vec<String> = env::args().collect();
    let argv0 = argv.first().map(|s| s.as_str()).unwrap_or("vaulted-agent");
    let invoked = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("vaulted-agent");

    let paths = Paths::discover();

    // Conductor symlink: claude-conductor → harness "claude"
    let link_suffix = "-conductor";
    let is_primary = matches!(invoked, "vaulted-agent" | "va");
    if !is_primary {
        if let Some(harness) = invoked.strip_suffix(link_suffix) {
            // Conductor path: re-exec as service user if configured, then launch
            let mut orig: Vec<String> = vec![harness.to_string()];
            orig.extend(argv.iter().skip(1).cloned());
            if let Err(e) = commands::maybe_reexec_service_user(&paths, argv0, &orig) {
                eprintln!("vaulted-agent: {e}");
                process::exit(1);
            }
            let mut force = false;
            let mut extra = Vec::new();
            for a in argv.iter().skip(1) {
                if a == "-p" || a == "--prompt-auth" {
                    force = true;
                } else {
                    extra.push(a.clone());
                }
            }
            if let Err(e) = commands::cmd_launch_harness(&paths, harness, &extra, force) {
                eprintln!("vaulted-agent: {e}");
                process::exit(1);
            }
            return;
        }
        eprintln!(
            "vaulted-agent: symlink '{invoked}' does not end in '{link_suffix}' (and is not vaulted-agent or va)"
        );
        process::exit(1);
    }

    // Global version / help before flag parse (flags start with -)
    if matches!(
        argv.get(1).map(|s| s.as_str()),
        Some("version") | Some("--version") | Some("-V")
    ) {
        commands::cmd_version();
        return;
    }
    if matches!(
        argv.get(1).map(|s| s.as_str()),
        Some("help") | Some("--help") | Some("-h")
    ) && argv.len() == 2
    {
        commands::usage(&paths);
        process::exit(0);
    }

    // Pull launcher flags; rest are command/harness args
    let mut force_prompt = false;
    if env::var_os("VAULTED_AGENT_PROMPT_AUTH").as_deref() == Some(std::ffi::OsStr::new("1")) {
        force_prompt = true;
    }
    let mut harness_flag: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut args = argv.iter().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-p" | "--prompt-auth" => force_prompt = true,
            "-V" | "--version" => {
                commands::cmd_version();
                return;
            }
            "-H" | "--harness" => {
                harness_flag = Some(
                    args.next()
                        .cloned()
                        .unwrap_or_else(|| {
                            eprintln!("vaulted-agent: -H requires a value");
                            process::exit(1);
                        }),
                );
            }
            s if s.starts_with("--harness=") => {
                harness_flag = Some(s["--harness=".len()..].to_string());
            }
            "--" => {
                rest.extend(args.cloned());
                break;
            }
            _ => rest.push(a.clone()),
        }
    }

    let positional = if rest.first().map(|s| !s.starts_with('-')).unwrap_or(false) {
        Some(rest.remove(0))
    } else {
        None
    };

    if positional.is_some() && harness_flag.is_some() {
        eprintln!(
            "vaulted-agent: harness given twice: '{}' and -H '{}'",
            positional.as_ref().unwrap(),
            harness_flag.as_ref().unwrap()
        );
        process::exit(1);
    }

    let mut harness = positional.or(harness_flag);

    // No harness → usage
    let Some(name) = harness.take() else {
        commands::usage(&paths);
        process::exit(1);
    };

    // Reserved management commands
    if commands::is_reserved(&name, &paths) {
        let code = dispatch_mgmt(&paths, &name, &rest, force_prompt);
        process::exit(code);
    }

    // pick may have been a real harness; if reserved pick was handled above.
    // Launch harness (with service-user re-exec)
    let mut orig = vec![name.clone()];
    orig.extend(rest.iter().cloned());
    if force_prompt {
        orig.insert(1, "-p".into());
    }
    if let Err(e) = commands::maybe_reexec_service_user(&paths, argv0, &orig) {
        eprintln!("vaulted-agent: {e}");
        process::exit(1);
    }

    if let Err(e) = commands::cmd_launch_harness(&paths, &name, &rest, force_prompt) {
        eprintln!("vaulted-agent: {e}");
        // Suggest harness list on unknown
        if format!("{e}").contains("unknown harness") {
            commands::usage(&paths);
        }
        process::exit(1);
    }
}

fn dispatch_mgmt(paths: &Paths, name: &str, rest: &[String], force_prompt: bool) -> i32 {
    let result = match name {
        "version" | "--version" | "-V" => {
            commands::cmd_version();
            Ok(())
        }
        "help" | "--help" | "-h" => {
            commands::usage(paths);
            Ok(())
        }
        "auth-mode" => commands::cmd_auth_mode(paths, rest),
        "doctor" => commands::cmd_doctor(paths),
        "secrets" => commands::cmd_secrets(paths, rest),
        "setup" => commands::cmd_setup(paths, rest),
        "refresh" => commands::cmd_refresh(paths, rest),
        "uninstall" => commands::cmd_uninstall(rest),
        "run" => commands::cmd_run(paths, rest, force_prompt),
        "pick" => match commands::cmd_pick(paths) {
            Ok(chosen) => commands::cmd_launch_harness(paths, &chosen, rest, force_prompt),
            Err(e) => Err(e),
        },
        other => Err(vaulted_agent::Error::Message(format!(
            "unknown command '{other}'"
        ))),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("vaulted-agent: {e}");
            1
        }
    }
}
