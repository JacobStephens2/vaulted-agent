//! vaulted-agent — launch AI coding agents with vault-resolved secrets.
//!
//! Rust is the shipped runtime (v0.4.0+). See MIGRATION.md.
//!
//! The entry point is the one adapter for the Invocation route (`route`): it
//! reads the process facts, asks for the route, then carries it out.

use std::env;
use std::path::Path;
use std::process;

use vaulted_agent::auth::TokenSource;
use vaulted_agent::commands;
use vaulted_agent::config::Paths;
use vaulted_agent::privilege;
use vaulted_agent::route::{self, Action, Hop, Verb, Via};
use vaulted_agent::{Error, Result};

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
    let args = argv.get(1..).unwrap_or_default();

    let paths = Paths::discover();

    let route = route::route(args, invoked, |name| {
        paths.harness_dir.join(format!("{name}.conf")).is_file()
    })
    .unwrap_or_else(|e| fail(e));

    if let Hop::Replay { argv, fatal } = &route.hop {
        if let Err(e) = privilege::maybe_reexec_service_user(&paths, argv0, argv) {
            if *fatal {
                fail(e);
            }
            eprintln!("vaulted-agent: could not check as the service user: {e}");
        }
    }

    match route.action {
        Action::Usage => {
            commands::usage(&paths);
            process::exit(1);
        }
        Action::Launch {
            harness,
            args,
            prompt_auth,
            manifest,
            via,
        } => {
            let token_source =
                TokenSource::from_env(&paths, prompt_auth).unwrap_or_else(|e| fail(e));
            if let Err(e) = commands::cmd_launch_harness(
                &paths,
                &harness,
                &args,
                token_source,
                manifest.as_deref(),
            ) {
                eprintln!("vaulted-agent: {e}");
                if via == Via::Direct && matches!(e, Error::UnknownHarness { .. }) {
                    commands::usage(&paths);
                }
                process::exit(1);
            }
        }
        Action::Verb {
            verb,
            args,
            prompt_auth,
            manifest,
        } => {
            // `-p` in front of a management command reaches it the same way it
            // reaches a harness launch: through the one Token source. Built
            // only for the verbs that load a token, since it reads
            // defaults.conf: the verbs that inspect or repair a broken one
            // (`auth-mode`, `doctor`, `update`, …) must still reach their code.
            let token_source = || TokenSource::from_env(&paths, prompt_auth);
            let result = match verb {
                Verb::Version => {
                    commands::cmd_version();
                    Ok(())
                }
                Verb::Help => {
                    commands::usage(&paths);
                    Ok(())
                }
                Verb::AuthMode => commands::cmd_auth_mode(&paths, &args),
                Verb::Doctor => commands::cmd_doctor(&paths),
                Verb::Secrets => {
                    token_source().and_then(|ts| commands::cmd_secrets(&paths, &args, ts))
                }
                Verb::Setup => token_source().and_then(|ts| commands::cmd_setup(&paths, &args, ts)),
                Verb::Refresh => {
                    token_source().and_then(|ts| commands::cmd_refresh(&paths, &args, ts))
                }
                Verb::Uninstall => commands::cmd_uninstall(&args),
                Verb::Update => vaulted_agent::update::cmd_update(&args),
                Verb::Run => token_source().and_then(|ts| commands::cmd_run(&paths, &args, ts)),
                Verb::EditManifest => commands::cmd_edit_manifest(&paths, &args),
                Verb::Pick => token_source()
                    .and_then(|ts| pick(&paths, argv0, &route.hop, &args, ts, manifest.as_deref())),
            };
            if let Err(e) = result {
                fail(e);
            }
        }
    }
}

fn fail(e: Error) -> ! {
    eprintln!("vaulted-agent: {e}");
    process::exit(1);
}

/// `pick` is a harness launch after the menu, and takes the Service-user hop
/// there: as though the operator had typed the chosen Harness, so a sudoers
/// grant matches that Harness and never `pick` itself.
fn pick(
    paths: &Paths,
    argv0: &str,
    hop: &Hop,
    args: &[String],
    token_source: TokenSource,
    manifest_override: Option<&str>,
) -> Result<()> {
    let Some(chosen) = commands::cmd_pick(paths)? else {
        return Ok(());
    };
    if let Hop::AfterPick { launcher_flags } = hop {
        let replay = route::pick_replay_argv(launcher_flags, &chosen, args);
        privilege::maybe_reexec_service_user(paths, argv0, &replay)?;
    }
    commands::cmd_launch_harness(paths, &chosen, args, token_source, manifest_override)
}
