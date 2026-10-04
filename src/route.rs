//! Invocation route: what one command line asks the Launcher to do.
//!
//! Pure decision with a thin adapter (the binary's `main`), like
//! `TokenSource::decide` and `plan_service_user_reexec`. The route is settled
//! once, before anything runs, from the argv after argv0, the name the binary
//! was invoked as, and one question about the filesystem -- does a Harness conf
//! of this name exist -- passed in as a query. Nothing here reads the process
//! environment or exits the process; a refusal is an `Error::Message` the
//! adapter prints as `vaulted-agent: {e}` with exit 1.
//!
//! Whether a Service-user hop happens at all (`service_user`, current user,
//! `VAULTED_AGENT_NO_REEXEC`) stays in `privilege`. The route only names which
//! argv a hop replays and whether a failed hop is fatal.

use crate::error::{Error, Result};

/// A reserved management verb. A Harness conf of the same name shadows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Version,
    Help,
    Setup,
    Refresh,
    AuthMode,
    Doctor,
    Secrets,
    Uninstall,
    Update,
    Pick,
    Run,
    EditManifest,
}

impl Verb {
    /// The one list of reserved names. The reserved-name check, the dispatch and
    /// version/help in the command position all read it.
    const NAMES: &'static [(&'static str, Verb)] = &[
        ("version", Verb::Version),
        ("--version", Verb::Version),
        ("-V", Verb::Version),
        ("setup", Verb::Setup),
        ("refresh", Verb::Refresh),
        ("auth-mode", Verb::AuthMode),
        ("doctor", Verb::Doctor),
        ("secrets", Verb::Secrets),
        ("uninstall", Verb::Uninstall),
        ("update", Verb::Update),
        ("pick", Verb::Pick),
        ("run", Verb::Run),
        ("edit-manifest", Verb::EditManifest),
        ("help", Verb::Help),
        ("--help", Verb::Help),
        ("-h", Verb::Help),
    ];

    pub fn parse(name: &str) -> Option<Verb> {
        Self::NAMES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
    }

    /// Only `pick` takes a launcher-level `-m`: it is a harness launch after the
    /// menu. `run` and `refresh` read their own `-m` from after the verb, so a
    /// launcher-level one in front of them would be read by neither.
    fn accepts_manifest(self) -> bool {
        self == Verb::Pick
    }
}

/// How the binary was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// `vaulted-agent` / `va`.
    Direct,
    /// A `*-conductor` link: the link name fixes the Harness.
    Conductor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Launch a Harness, optionally against a Manifest override.
    Launch {
        harness: String,
        args: Vec<String>,
        prompt_auth: bool,
        manifest: Option<String>,
        via: Via,
    },
    /// Run a management verb. `manifest` is only ever set for `pick`.
    Verb {
        verb: Verb,
        args: Vec<String>,
        prompt_auth: bool,
        manifest: Option<String>,
    },
    /// No harness named: print usage and exit 1.
    Usage,
}

/// The Service-user re-exec a route takes, if `privilege` decides a hop applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hop {
    None,
    /// Replay `argv` through sudo. A failed hop stops the run only if `fatal`.
    Replay {
        argv: Vec<String>,
        fatal: bool,
    },
    /// `pick`: hop after the menu with `pick_replay_argv`, so a sudoers grant
    /// matches the Harness chosen, never `pick` itself. Fatal like a launch.
    AfterPick {
        launcher_flags: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub action: Action,
    pub hop: Hop,
}

const CONDUCTOR_SUFFIX: &str = "-conductor";

/// Decide the route for one command line.
///
/// `args` is the argv after argv0, `invoked` the file name argv0 names, and
/// `harness_exists` answers whether a Harness conf of a name exists.
pub fn route(
    args: &[String],
    invoked: &str,
    harness_exists: impl Fn(&str) -> bool,
) -> Result<Route> {
    if !matches!(invoked, "vaulted-agent" | "va") {
        return conductor_route(args, invoked);
    }

    // Global version / help only in the command position.
    match args.first().map(|s| Verb::parse(s)) {
        Some(Some(Verb::Version)) => return Ok(verb_route(Verb::Version, Vec::new())),
        Some(Some(Verb::Help)) if args.len() == 1 => return Ok(verb_route(Verb::Help, Vec::new())),
        _ => {}
    }

    let flags = LauncherFlags::parse(args)?;
    let Some(name) = flags.name else {
        return Ok(Route {
            action: Action::Usage,
            hop: Hop::None,
        });
    };

    // A real Harness wins over a verb of the same name.
    if let Some(verb) = Verb::parse(&name).filter(|_| !harness_exists(&name)) {
        if flags.manifest.is_some() && !verb.accepts_manifest() {
            return Err(Error::Message(format!(
                "-m/--manifest applies to a harness launch \
                 (including pick), not to '{name}'"
            )));
        }
        let hop = match verb {
            // doctor reports on what a launch will find, and a launch runs as
            // service_user. Take the same hop first so its filesystem checks
            // are answered by the account that will actually run the agent. A
            // failed hop is not fatal: doctor still has something useful to say
            // as the caller, and it labels which account answered.
            Verb::Doctor => Hop::Replay {
                argv: args.to_vec(),
                fatal: false,
            },
            Verb::Pick => Hop::AfterPick {
                launcher_flags: flags.launcher_flags,
            },
            _ => Hop::None,
        };
        return Ok(Route {
            action: Action::Verb {
                verb,
                args: flags.rest,
                prompt_auth: flags.prompt_auth,
                manifest: flags.manifest,
            },
            hop,
        });
    }

    // Replay original argv exactly so a sudoers rule matches the command line
    // as typed (story #41). Do not rewrite into -H form or re-insert -p.
    Ok(Route {
        action: Action::Launch {
            harness: name,
            args: flags.rest,
            prompt_auth: flags.prompt_auth,
            manifest: flags.manifest,
            via: Via::Direct,
        },
        hop: Hop::Replay {
            argv: args.to_vec(),
            fatal: true,
        },
    })
}

/// The argv `pick` replays once a Harness is chosen: the launcher flags as
/// typed before `pick`, then the chosen name, then the rest. A sudoers rule
/// then sees exactly what the operator would have typed to name that Harness.
pub fn pick_replay_argv(launcher_flags: &[String], chosen: &str, rest: &[String]) -> Vec<String> {
    let mut argv = launcher_flags.to_vec();
    argv.push(chosen.to_string());
    argv.extend(rest.iter().cloned());
    argv
}

fn conductor_route(args: &[String], invoked: &str) -> Result<Route> {
    let Some(harness) = invoked.strip_suffix(CONDUCTOR_SUFFIX) else {
        return Err(Error::Message(format!(
            "symlink '{invoked}' does not end in '{CONDUCTOR_SUFFIX}' (and is not vaulted-agent or va)"
        )));
    };
    // Honouring -H under a conductor symlink would let a caller entitled to a
    // narrow harness borrow a wider harness's manifest (bash guard). -m reaches
    // the same place by a shorter route -- it names the manifest outright -- so
    // it is refused for the same reason. The symlink exists so a sudoers rule
    // can grant one harness and have that mean one set of credentials
    // (invariant 7). Checked anywhere in the argv, not only in front.
    for a in args {
        if a == "-H" || a == "--harness" || a.starts_with("--harness=") {
            return Err(Error::Message(format!(
                "-H/--harness is not allowed when invoked as '{invoked}' (harness is fixed by the symlink)"
            )));
        }
        if a == "-m" || a == "--manifest" || a.starts_with("--manifest=") {
            return Err(Error::Message(format!(
                "-m/--manifest is not allowed when invoked as '{invoked}' \
                 (the harness fixes which credentials this entitlement carries)"
            )));
        }
    }
    // The link name fixes the harness, so there is no harness token to read
    // flags in front of and every argument here belongs to the agent. `-p` above
    // all: claude, codex and kimi each use it for a prompt, so eating it as
    // --prompt-auth turned
    //
    //     kimi-conductor -p "explain this"
    //
    // into a request for a vault token, which then failed with "auth_mode=prompt
    // needs a terminal" -- an error pointing nowhere near the cause, and the
    // prompt silently dropped. Prompt auth stays reachable in this mode through
    // VAULTED_AGENT_PROMPT_AUTH=1, which the Token source reads.
    let mut agent_args = args.to_vec();
    // A leading `--` stays an explicit "the rest is the agent's".
    if agent_args.first().is_some_and(|s| s == "--") {
        agent_args.remove(0);
    }
    Ok(Route {
        action: Action::Launch {
            harness: harness.to_string(),
            args: agent_args,
            prompt_auth: false,
            manifest: None,
            via: Via::Conductor,
        },
        // Replay original argv exactly for sudoers (story #41).
        hop: Hop::Replay {
            argv: args.to_vec(),
            fatal: true,
        },
    })
}

fn verb_route(verb: Verb, args: Vec<String>) -> Route {
    Route {
        action: Action::Verb {
            verb,
            args,
            prompt_auth: false,
            manifest: None,
        },
        hop: Hop::None,
    }
}

/// Launcher flags read on the direct path, up to the first non-flag token.
struct LauncherFlags {
    prompt_auth: bool,
    manifest: Option<String>,
    /// Harness or verb name, from the command position or `-H`.
    name: Option<String>,
    /// Everything after the name: the agent's or the verb's arguments.
    rest: Vec<String>,
    /// The launcher-flag tokens as typed before the name, minus any `-H`
    /// (pick replays these in front of the Harness it chose).
    launcher_flags: Vec<String>,
}

impl LauncherFlags {
    /// Flags after the first non-flag token belong to the agent (e.g.
    /// `va claude --version`, `va claude -p "explain this"`).
    fn parse(args: &[String]) -> Result<Self> {
        let mut prompt_auth = false;
        let mut harness_flag: Option<String> = None;
        let mut manifest: Option<String> = None;
        let mut rest: Vec<String> = Vec::new();
        let mut launcher_flags: Vec<String> = Vec::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "-p" | "--prompt-auth" => {
                    prompt_auth = true;
                    launcher_flags.push(a.clone());
                }
                "-m" | "--manifest" => {
                    let v = it
                        .next()
                        .cloned()
                        .ok_or_else(|| Error::Message("-m requires a value".into()))?;
                    if v.is_empty() {
                        return Err(Error::Message("-m requires a non-empty path".into()));
                    }
                    launcher_flags.push(a.clone());
                    launcher_flags.push(v.clone());
                    manifest = Some(v);
                }
                s if s.starts_with("--manifest=") => {
                    let v = s["--manifest=".len()..].to_string();
                    if v.is_empty() {
                        return Err(Error::Message(
                            "--manifest= requires a non-empty path".into(),
                        ));
                    }
                    launcher_flags.push(a.clone());
                    manifest = Some(v);
                }
                "-H" | "--harness" => {
                    harness_flag = Some(
                        it.next()
                            .cloned()
                            .ok_or_else(|| Error::Message("-H requires a value".into()))?,
                    );
                }
                s if s.starts_with("--harness=") => {
                    harness_flag = Some(s["--harness=".len()..].to_string());
                }
                "--" => {
                    launcher_flags.push(a.clone());
                    rest.extend(it.cloned());
                    break;
                }
                s if s.starts_with('-') => {
                    // Unknown leading flag: the start of the rest only if a
                    // harness is already named via -H; otherwise an error.
                    if harness_flag.is_some() {
                        rest.push(a.clone());
                        rest.extend(it.cloned());
                        break;
                    }
                    return Err(Error::Message(format!("unknown option '{s}'")));
                }
                _ => {
                    // First non-flag: harness/command name; everything after is
                    // agent argv.
                    rest.push(a.clone());
                    rest.extend(it.cloned());
                    break;
                }
            }
        }

        let positional = if rest.first().is_some_and(|s| !s.starts_with('-')) {
            Some(rest.remove(0))
        } else {
            None
        };
        let name = match (positional, harness_flag) {
            (Some(a), Some(b)) => {
                return Err(Error::Message(format!(
                    "harness given twice: '{a}' and -H '{b}'"
                )));
            }
            (a, b) => a.or(b),
        };
        Ok(Self {
            prompt_auth,
            manifest,
            name,
            rest,
            launcher_flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &[&str]) -> Vec<String> {
        s.iter().map(|a| a.to_string()).collect()
    }

    fn direct(s: &[&str]) -> Result<Route> {
        route(&argv(s), "va", |_| false)
    }

    fn refusal(r: Result<Route>) -> String {
        match r {
            Err(Error::Message(m)) => m,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn every_reserved_name_parses_to_a_verb() {
        for name in [
            "version",
            "--version",
            "-V",
            "setup",
            "refresh",
            "auth-mode",
            "doctor",
            "secrets",
            "uninstall",
            "update",
            "pick",
            "run",
            "edit-manifest",
            "help",
            "--help",
            "-h",
        ] {
            assert!(Verb::parse(name).is_some(), "{name} should be reserved");
        }
        assert_eq!(Verb::parse("claude"), None);
    }

    #[test]
    fn harness_launch_replays_original_argv_and_hop_is_fatal() {
        let r = direct(&["-p", "claude", "-p", "explain"]).unwrap();
        assert_eq!(
            r,
            Route {
                action: Action::Launch {
                    harness: "claude".into(),
                    args: argv(&["-p", "explain"]),
                    prompt_auth: true,
                    manifest: None,
                    via: Via::Direct,
                },
                hop: Hop::Replay {
                    argv: argv(&["-p", "claude", "-p", "explain"]),
                    fatal: true,
                },
            }
        );
    }

    #[test]
    fn manifest_override_reaches_a_harness_launch() {
        let r = direct(&["--manifest=narrow.env", "claude"]).unwrap();
        match r.action {
            Action::Launch { manifest, .. } => assert_eq!(manifest.as_deref(), Some("narrow.env")),
            other => panic!("expected launch, got {other:?}"),
        }
    }

    #[test]
    fn version_only_in_the_command_position() {
        let r = direct(&["version", "extra"]).unwrap();
        assert!(matches!(
            r.action,
            Action::Verb {
                verb: Verb::Version,
                ..
            }
        ));
        assert_eq!(r.hop, Hop::None);
        // After a harness name it is the agent's.
        let r = direct(&["claude", "--version"]).unwrap();
        match r.action {
            Action::Launch { harness, args, .. } => {
                assert_eq!(harness, "claude");
                assert_eq!(args, argv(&["--version"]));
            }
            other => panic!("expected launch, got {other:?}"),
        }
    }

    #[test]
    fn version_in_the_command_position_beats_a_conf_of_that_name() {
        let r = route(&argv(&["version"]), "va", |_| true).unwrap();
        assert!(matches!(
            r.action,
            Action::Verb {
                verb: Verb::Version,
                ..
            }
        ));
    }

    #[test]
    fn help_in_the_command_position_only_when_sole_argument() {
        let r = direct(&["--help"]).unwrap();
        assert!(matches!(
            r.action,
            Action::Verb {
                verb: Verb::Help,
                ..
            }
        ));
        // With more arguments it is read as a command name, which a conf shadows.
        let r = route(&argv(&["help", "x"]), "va", |n| n == "help").unwrap();
        match r.action {
            Action::Launch { harness, args, .. } => {
                assert_eq!(harness, "help");
                assert_eq!(args, argv(&["x"]));
            }
            other => panic!("expected launch, got {other:?}"),
        }
    }

    #[test]
    fn harness_given_twice_is_refused() {
        assert_eq!(
            refusal(direct(&["-H", "codex", "claude"])),
            "harness given twice: 'claude' and -H 'codex'"
        );
    }

    #[test]
    fn harness_flag_names_the_harness_and_unknown_flags_then_belong_to_the_agent() {
        let r = direct(&["-H", "claude", "--resume", "x"]).unwrap();
        match r.action {
            Action::Launch { harness, args, .. } => {
                assert_eq!(harness, "claude");
                assert_eq!(args, argv(&["--resume", "x"]));
            }
            other => panic!("expected launch, got {other:?}"),
        }
    }

    #[test]
    fn unknown_leading_option_is_refused() {
        assert_eq!(
            refusal(direct(&["--frobnicate", "claude"])),
            "unknown option '--frobnicate'"
        );
    }

    #[test]
    fn manifest_flag_needs_a_value() {
        assert_eq!(refusal(direct(&["-m"])), "-m requires a value");
        assert_eq!(refusal(direct(&["--manifest"])), "-m requires a value");
        assert_eq!(
            refusal(direct(&["-m", "", "claude"])),
            "-m requires a non-empty path"
        );
        assert_eq!(
            refusal(direct(&["--manifest=", "claude"])),
            "--manifest= requires a non-empty path"
        );
        assert_eq!(refusal(direct(&["-H"])), "-H requires a value");
    }

    #[test]
    fn reserved_name_shadowed_by_a_conf_is_a_harness_launch() {
        let r = route(&argv(&["doctor"]), "va", |n| n == "doctor").unwrap();
        assert!(matches!(r.action, Action::Launch { ref harness, .. } if harness == "doctor"));
        assert!(matches!(r.hop, Hop::Replay { fatal: true, .. }));
    }

    #[test]
    fn no_harness_is_usage() {
        for a in [&[][..], &["-p"][..], &["--"][..]] {
            let r = direct(a).unwrap();
            assert_eq!(r.action, Action::Usage);
            assert_eq!(r.hop, Hop::None);
        }
    }

    #[test]
    fn doctor_replays_original_argv_and_a_failed_hop_is_not_fatal() {
        let r = direct(&["-p", "doctor"]).unwrap();
        assert_eq!(
            r.hop,
            Hop::Replay {
                argv: argv(&["-p", "doctor"]),
                fatal: false,
            }
        );
    }

    #[test]
    fn other_verbs_take_no_hop_and_keep_their_args() {
        let r = direct(&["-p", "secrets", "validate", "--offline"]).unwrap();
        assert_eq!(
            r,
            Route {
                action: Action::Verb {
                    verb: Verb::Secrets,
                    args: argv(&["validate", "--offline"]),
                    prompt_auth: true,
                    manifest: None,
                },
                hop: Hop::None,
            }
        );
    }

    #[test]
    fn launcher_manifest_is_refused_for_verbs_other_than_pick() {
        assert_eq!(
            refusal(direct(&["-m", "x.env", "run", "--", "env"])),
            "-m/--manifest applies to a harness launch (including pick), not to 'run'"
        );
        let r = direct(&["-m", "x.env", "pick"]).unwrap();
        assert!(matches!(
            r.action,
            Action::Verb { verb: Verb::Pick, manifest: Some(ref m), .. } if m == "x.env"
        ));
    }

    #[test]
    fn pick_hops_after_the_menu_with_the_launcher_flags_as_typed() {
        let r = direct(&["-p", "--manifest=x.env", "-m", "y.env", "pick", "--resume"]).unwrap();
        assert_eq!(
            r.hop,
            Hop::AfterPick {
                launcher_flags: argv(&["-p", "--manifest=x.env", "-m", "y.env"]),
            }
        );
        match r.action {
            Action::Verb { verb, args, .. } => {
                assert_eq!(verb, Verb::Pick);
                assert_eq!(args, argv(&["--resume"]));
            }
            other => panic!("expected pick, got {other:?}"),
        }
    }

    #[test]
    fn pick_named_through_harness_flag_does_not_replay_the_flag() {
        let r = direct(&["-H", "pick"]).unwrap();
        assert_eq!(
            r.hop,
            Hop::AfterPick {
                launcher_flags: vec![]
            }
        );
    }

    #[test]
    fn pick_replay_argv_puts_the_chosen_harness_where_pick_was() {
        assert_eq!(
            pick_replay_argv(&[], "claude-ro", &[]),
            argv(&["claude-ro"])
        );
        assert_eq!(
            pick_replay_argv(
                &argv(&["-m", "x.env"]),
                "claude-ro",
                &argv(&["--resume", "id"])
            ),
            argv(&["-m", "x.env", "claude-ro", "--resume", "id"])
        );
        assert_eq!(
            pick_replay_argv(&argv(&["-p"]), "codex", &argv(&["-p", "hi"])),
            argv(&["-p", "codex", "-p", "hi"])
        );
    }

    #[test]
    fn pick_replay_argv_reroutes_to_the_chosen_harness() {
        let r = direct(&["-p", "-m", "x.env", "pick", "--resume"]).unwrap();
        let (Hop::AfterPick { launcher_flags }, Action::Verb { args, .. }) = (r.hop, r.action)
        else {
            panic!("expected pick");
        };
        let replay = pick_replay_argv(&launcher_flags, "claude-ro", &args);
        assert_eq!(
            direct(&replay.iter().map(String::as_str).collect::<Vec<_>>())
                .unwrap()
                .action,
            Action::Launch {
                harness: "claude-ro".into(),
                args: argv(&["--resume"]),
                prompt_auth: true,
                manifest: Some("x.env".into()),
                via: Via::Direct,
            }
        );
    }

    #[test]
    fn conductor_refuses_harness_and_manifest_anywhere_in_argv() {
        for flag in ["-H", "--harness", "--harness=codex"] {
            assert_eq!(
                refusal(route(&argv(&["--resume", flag]), "claude-conductor", |_| true)),
                "-H/--harness is not allowed when invoked as 'claude-conductor' (harness is fixed by the symlink)"
            );
        }
        for flag in ["-m", "--manifest", "--manifest=wide.env"] {
            assert_eq!(
                refusal(route(&argv(&["--", "x", flag]), "claude-conductor", |_| {
                    true
                })),
                "-m/--manifest is not allowed when invoked as 'claude-conductor' \
                 (the harness fixes which credentials this entitlement carries)"
            );
        }
    }

    #[test]
    fn conductor_leaves_p_to_the_agent_and_drops_a_leading_double_dash() {
        let r = route(&argv(&["-p", "explain"]), "kimi-conductor", |_| false).unwrap();
        assert_eq!(
            r,
            Route {
                action: Action::Launch {
                    harness: "kimi".into(),
                    args: argv(&["-p", "explain"]),
                    prompt_auth: false,
                    manifest: None,
                    via: Via::Conductor,
                },
                hop: Hop::Replay {
                    argv: argv(&["-p", "explain"]),
                    fatal: true,
                },
            }
        );
        let r = route(&argv(&["--", "--resume"]), "kimi-conductor", |_| false).unwrap();
        match (r.action, r.hop) {
            (Action::Launch { args, .. }, Hop::Replay { argv: replay, .. }) => {
                assert_eq!(args, argv(&["--resume"]));
                // The hop still replays what was typed.
                assert_eq!(replay, argv(&["--", "--resume"]));
            }
            other => panic!("expected conductor launch, got {other:?}"),
        }
    }

    #[test]
    fn conductor_does_not_read_verbs() {
        let r = route(&argv(&["version"]), "claude-conductor", |_| false).unwrap();
        assert!(matches!(
            r.action,
            Action::Launch {
                via: Via::Conductor,
                ..
            }
        ));
    }

    #[test]
    fn other_symlink_names_are_refused() {
        assert_eq!(
            refusal(route(&[], "claude-wrapper", |_| true)),
            "symlink 'claude-wrapper' does not end in '-conductor' (and is not vaulted-agent or va)"
        );
    }
}
