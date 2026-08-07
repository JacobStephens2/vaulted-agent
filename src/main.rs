//! vaulted-agent — launch AI coding agents with vault-resolved secrets.
//!
//! Rust is the shipped runtime (v0.4.0+). See MIGRATION.md.

use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::process;

use vaulted_agent::commands;
use vaulted_agent::config::Paths;
use vaulted_agent::Error;

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
            // Honouring -H under a conductor symlink would let a caller entitled
            // to a narrow harness borrow a wider harness's manifest (bash guard).
            // -m reaches the same place by a shorter route — it names the
            // manifest outright — so it is refused here for the same reason.
            // The symlink exists so a sudoers rule can grant one harness and
            // have that mean one set of credentials.
            for a in argv.iter().skip(1) {
                if a == "-H" || a == "--harness" || a.starts_with("--harness=") {
                    eprintln!(
                        "vaulted-agent: -H/--harness is not allowed when invoked as '{invoked}' (harness is fixed by the symlink)"
                    );
                    process::exit(1);
                }
                if a == "-m" || a == "--manifest" || a.starts_with("--manifest=") {
                    eprintln!(
                        "vaulted-agent: -m/--manifest is not allowed when invoked as '{invoked}' \
                         (the harness fixes which credentials this entitlement carries)"
                    );
                    process::exit(1);
                }
            }
            // Replay original argv exactly for sudoers (story #41).
            let orig: Vec<String> = argv.iter().skip(1).cloned().collect();
            if let Err(e) = commands::maybe_reexec_service_user(&paths, argv0, &orig) {
                eprintln!("vaulted-agent: {e}");
                process::exit(1);
            }
            // The link name fixes the harness, so there is no harness token to
            // read flags in front of and every argument here belongs to the
            // agent. `-p` above all: claude, codex and kimi each use it for a
            // prompt, so eating it as --prompt-auth turned
            //
            //     kimi-conductor -p "explain this"
            //
            // into a request for a vault token, which then failed with
            // "auth_mode=prompt needs a terminal" -- an error pointing nowhere
            // near the cause, and the prompt silently dropped. Prompt auth stays
            // reachable in this mode through VAULTED_AGENT_PROMPT_AUTH=1.
            let force =
                env::var_os("VAULTED_AGENT_PROMPT_AUTH").as_deref() == Some(OsStr::new("1"));
            let mut extra: Vec<String> = argv.iter().skip(1).cloned().collect();
            // A leading `--` stays an explicit "the rest is the agent's".
            if extra.first().is_some_and(|s| s == "--") {
                extra.remove(0);
            }
            if let Err(e) = commands::cmd_launch_harness(&paths, harness, &extra, force, None) {
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

    // Global version / help only in the command position (argv[1]).
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

    // Pull launcher flags only until the first non-flag token (harness or
    // management command). Flags after that belong to the agent (e.g.
    // `va claude --version`, `va claude -p "explain this"`).
    let mut force_prompt = false;
    if env::var_os("VAULTED_AGENT_PROMPT_AUTH").as_deref() == Some(std::ffi::OsStr::new("1")) {
        force_prompt = true;
    }
    let mut harness_flag: Option<String> = None;
    let mut manifest_flag: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();
    let mut args = argv.iter().skip(1).peekable();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-p" | "--prompt-auth" => force_prompt = true,
            "-m" | "--manifest" => {
                manifest_flag = Some(args.next().cloned().unwrap_or_else(|| {
                    eprintln!("vaulted-agent: -m requires a value");
                    process::exit(1);
                }));
            }
            s if s.starts_with("--manifest=") => {
                manifest_flag = Some(s["--manifest=".len()..].to_string());
            }
            "-H" | "--harness" => {
                harness_flag = Some(args.next().cloned().unwrap_or_else(|| {
                    eprintln!("vaulted-agent: -H requires a value");
                    process::exit(1);
                }));
            }
            s if s.starts_with("--harness=") => {
                harness_flag = Some(s["--harness=".len()..].to_string());
            }
            "--" => {
                rest.extend(args.cloned());
                break;
            }
            s if s.starts_with('-') => {
                // Unknown leading flag: treat as start of positional/rest stream
                // only if we already have a harness via -H; otherwise error.
                if harness_flag.is_some() {
                    rest.push(a.clone());
                    rest.extend(args.cloned());
                    break;
                }
                eprintln!("vaulted-agent: unknown option '{s}'");
                process::exit(1);
            }
            _ => {
                // First non-flag: harness/command name; everything after is agent argv.
                rest.push(a.clone());
                rest.extend(args.cloned());
                break;
            }
        }
    }

    let positional = if rest.first().map(|s| !s.starts_with('-')).unwrap_or(false) {
        Some(rest.remove(0))
    } else {
        None
    };

    let mut harness = match (positional, harness_flag) {
        (Some(a), Some(b)) => {
            eprintln!("vaulted-agent: harness given twice: '{a}' and -H '{b}'");
            process::exit(1);
        }
        (a, b) => a.or(b),
    };

    // No harness → usage
    let Some(name) = harness.take() else {
        commands::usage(&paths);
        process::exit(1);
    };

    // Reserved management commands
    if commands::is_reserved(&name, &paths) {
        // `run` and `refresh` read their own -m from the arguments after the
        // command name. A launcher-level -m in front of one would be read by
        // neither, and silently doing nothing with a flag that names which
        // credentials to use is the wrong kind of quiet.
        if manifest_flag.is_some() {
            eprintln!(
                "vaulted-agent: -m/--manifest applies to a harness launch; \
                 for '{name}' pass it after the command name"
            );
            process::exit(1);
        }
        // doctor reports on what a launch will find, and a launch runs as
        // service_user. Take the same hop first so its filesystem checks are
        // answered by the account that will actually run the agent; otherwise
        // the report describes the caller and quietly contradicts reality.
        // A failed hop is not fatal here: doctor still has something useful to
        // say as the caller, and it labels which account answered.
        if name == "doctor" {
            let orig: Vec<String> = argv.iter().skip(1).cloned().collect();
            if let Err(e) = commands::maybe_reexec_service_user(&paths, argv0, &orig) {
                eprintln!("vaulted-agent: could not check as the service user: {e}");
            }
        }
        let code = dispatch_mgmt(&paths, &name, &rest, force_prompt);
        process::exit(code);
    }

    // Replay original argv exactly so a sudoers rule matches the command line
    // as typed (story #41). Do not rewrite into -H form or re-insert -p.
    let orig: Vec<String> = argv.iter().skip(1).cloned().collect();
    if let Err(e) = commands::maybe_reexec_service_user(&paths, argv0, &orig) {
        eprintln!("vaulted-agent: {e}");
        process::exit(1);
    }

    if let Err(e) =
        commands::cmd_launch_harness(&paths, &name, &rest, force_prompt, manifest_flag.as_deref())
    {
        eprintln!("vaulted-agent: {e}");
        if matches!(e, Error::UnknownHarness { .. }) {
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
            Ok(chosen) => commands::cmd_launch_harness(paths, &chosen, rest, force_prompt, None),
            Err(e) => Err(e),
        },
        other => Err(Error::Message(format!("unknown command '{other}'"))),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("vaulted-agent: {e}");
            1
        }
    }
}
