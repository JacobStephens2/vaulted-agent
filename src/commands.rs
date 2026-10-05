//! Management subcommands: secrets, doctor, setup, auth-mode, uninstall, pick, run.
//! `refresh` lives in its own module and is re-exported here for the router.

use std::cell::RefCell;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::auth::{self, TokenKind, TokenSource};
use crate::backend;
use crate::bitwarden::BwListing;
use crate::config::{
    env_blind_agent_reason, list_harness_names, parse_dotenv_keys, set_default,
    set_harnesses_workdir, AuthMode, Backend, Harness, Paths,
};
use crate::defaults::Defaults;
use crate::error::{Error, Result};
use crate::inventory::{Binding, Inventory, ValidateTarget};
use crate::launch::{self, LaunchOpts};
use crate::onepassword;
use crate::preflight::{self, Form, Mode, VaultProbe};
use crate::refresh;
pub use crate::refresh::cmd_refresh;
use crate::refs::{self, Mapping, RefsStyle, WriteMode};
use crate::secret::ManagerToken;
use crate::validate::validate_manifest_file;
use crate::vault_wiring;
use crate::workdir::{self, CallerContext};

pub fn cmd_version() {
    // The git description is appended when a repository was present at build
    // time, so a build patched in place is distinguishable from the release it
    // started as. Release tarballs have no repository and print the bare
    // version, exactly as before.
    let build = env!("VA_BUILD_DESC");
    if build.is_empty() {
        println!("vaulted-agent {}", env!("CARGO_PKG_VERSION"));
    } else {
        println!("vaulted-agent {} ({build})", env!("CARGO_PKG_VERSION"));
    }
}

pub fn cmd_auth_mode(paths: &Paths, args: &[String]) -> Result<()> {
    // Bare `auth-mode` on a TTY is interactive (install/README parity).
    // Explicit `show` always prints without prompting.
    let sub = args.first().map(|s| s.as_str());
    match sub {
        None => {
            if can_prompt_user() {
                // The menu's default is the configured mode, so it needs the
                // file to load. The explicit form below does not.
                let current = Defaults::load(paths)
                    .map_err(|e| {
                        Error::Message(format!(
                            "{e}\n  `vaulted-agent auth-mode file|prompt` sets auth_mode \
                             without reading the rest of defaults.conf"
                        ))
                    })?
                    .auth_mode;
                let mode = prompt_auth_mode_choice(current)?;
                write_auth_mode(paths, mode)?;
                println!("auth_mode={}", mode.as_str());
            } else {
                println!("auth_mode={}", Defaults::load(paths)?.auth_mode.as_str());
            }
            Ok(())
        }
        Some("show") | Some("") => {
            let mode = Defaults::load(paths)?.auth_mode;
            println!("auth_mode={}", mode.as_str());
            Ok(())
        }
        // The repair path for a typo'd auth_mode: the Conf file edit touches
        // only that key and never parses defaults.conf.
        Some("file") | Some("prompt") => {
            let mode = AuthMode::parse(sub.unwrap()).unwrap();
            write_auth_mode(paths, mode)?;
            println!("auth_mode={}", mode.as_str());
            Ok(())
        }
        Some(other) => Err(Error::Message(format!(
            "unknown auth-mode '{other}' (want file, prompt, or show)"
        ))),
    }
}

/// True when a human can answer interactive menus (setup / auth-mode).
/// Match install.sh: require a usable controlling terminal, not merely /dev/tty present.
fn can_prompt_user() -> bool {
    io::IsTerminal::is_terminal(&io::stdin())
        && fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .is_ok()
}

fn read_tty_line() -> Result<String> {
    let mut line = String::new();
    let mut tty = io::BufReader::new(
        fs::File::open("/dev/tty").map_err(|e| Error::Message(format!("tty: {e}")))?,
    );
    tty.read_line(&mut line)
        .map_err(|e| Error::Message(format!("tty read: {e}")))?;
    Ok(line)
}

/// Parse an auth-mode menu reply. Empty keeps `current`. Unknown keeps `current`.
fn parse_auth_mode_choice(choice: &str, current: AuthMode) -> AuthMode {
    match choice.trim() {
        "1" | "file" | "disk" => AuthMode::File,
        "2" | "prompt" | "p" => AuthMode::Prompt,
        "" => current,
        _ => current,
    }
}

/// Interactive auth-mode menu (install.sh parity). Writes nothing; caller persists.
fn prompt_auth_mode_choice(current: AuthMode) -> Result<AuthMode> {
    let default = current.as_str();
    eprintln!("\nHow should vault tokens be supplied at launch?");
    eprintln!("  1) file    — store once in op.env / bws.env (no prompt each run)");
    eprintln!("  2) prompt  — paste token each launch; nothing stored on disk");
    eprintln!("     (same as always running with -p / --prompt-auth)");
    eprint!("choice [1-2, default {default}]: ");
    let _ = io::stderr().flush();
    let line = read_tty_line()?;
    let trimmed = line.trim();
    if !trimmed.is_empty() && !matches!(trimmed, "1" | "file" | "disk" | "2" | "prompt" | "p") {
        eprintln!("  unknown choice '{trimmed}'; keeping {default}");
    }
    Ok(parse_auth_mode_choice(trimmed, current))
}

/// When interactive, ask how manager tokens are obtained and persist the choice.
/// Non-interactive runs leave the existing defaults.conf value alone.
fn ensure_auth_mode_for_setup(paths: &Paths, token_source: TokenSource) -> Result<TokenSource> {
    if !can_prompt_user() {
        return Ok(token_source);
    }
    let current = Defaults::load(paths)?.auth_mode;
    let mode = prompt_auth_mode_choice(current)?;
    write_auth_mode(paths, mode)?;
    Ok(token_source.with_auth_mode(mode))
}

fn write_auth_mode(paths: &Paths, mode: AuthMode) -> Result<()> {
    set_default(paths, "auth_mode", Some(mode.as_str()))
}

/// Interactive: who agents run as (defaults to "you" = no service_user).
/// Non-interactive: leave defaults alone.
fn ensure_service_user_for_setup(paths: &Paths) -> Result<Option<String>> {
    let configured = || Defaults::load(paths).map(|d| d.service_user);
    if !can_prompt_user() {
        return configured();
    }
    let me = crate::privilege::current_user();
    let me_label = if me.is_empty() {
        "you".to_string()
    } else {
        me.clone()
    };
    let current = configured()?;
    eprintln!("\nRun agents as:");
    eprintln!("  1) you ({me_label})            [default]");
    eprintln!("  2) a dedicated service account");
    if let Some(ref svc) = current {
        eprintln!("     (currently service_user = {svc})");
    }
    eprint!("choice [1-2, default 1]: ");
    let _ = io::stderr().flush();
    let line = read_tty_line()?;
    let choice = line.trim();
    match choice {
        "" | "1" | "you" | "me" => {
            set_default(paths, "service_user", None)?;
            println!("service_user: (unset — agents run as the invoking user)");
            Ok(None)
        }
        "2" | "service" | "svc" => {
            eprint!("service account name: ");
            let _ = io::stderr().flush();
            let name = read_tty_line()?.trim().to_string();
            if name.is_empty() {
                eprintln!("  empty name; leaving service_user unchanged");
                return configured();
            }
            set_default(paths, "service_user", Some(&name))?;
            println!("service_user = {name}");
            eprintln!(
                "  NOTE: with service_user, `va run` is disabled unless allow_run = yes \
                 in defaults.conf."
            );
            eprintln!(
                "  Token files written by setup will be chowned root:{name} (mode 0640) \
                 when run as root."
            );
            Ok(Some(name))
        }
        other => {
            eprintln!("  unknown choice '{other}'; leaving service_user unchanged");
            configured()
        }
    }
}

/// Interactive: where agents start (default = caller cwd).
/// Non-interactive: leave harnesses alone.
fn ensure_workdir_for_setup(paths: &Paths, service_user: Option<&str>) -> Result<()> {
    if !can_prompt_user() {
        return Ok(());
    }
    eprintln!("\nStart agents in:");
    eprintln!("  1) the directory you run the command from   [default]");
    eprintln!("  2) a fixed directory");
    eprint!("choice [1-2, default 1]: ");
    let _ = io::stderr().flush();
    let line = read_tty_line()?;
    let workdir = match line.trim() {
        "" | "1" | "caller" => "caller".to_string(),
        "2" | "fixed" | "absolute" => {
            eprint!("absolute path (or $HOME/…): ");
            let _ = io::stderr().flush();
            let p = read_tty_line()?.trim().to_string();
            if p.is_empty() {
                eprintln!("  empty path; using workdir = caller");
                "caller".to_string()
            } else {
                p
            }
        }
        other => {
            eprintln!("  unknown choice '{other}'; using workdir = caller");
            "caller".to_string()
        }
    };

    let n = set_harnesses_workdir(paths, &workdir)?;
    if n == 0 {
        println!(
            "workdir = {workdir} (no harness confs yet — new harnesses should set this; \
             install auto-harness uses caller)"
        );
    } else {
        println!("workdir = {workdir} on {n} harness conf(s)");
    }

    if workdir == "caller" {
        if let Some(svc) = service_user.filter(|s| !s.is_empty()) {
            eprintln!("  {}", workdir::setup_note(svc, &CallerContext::from_env()));
        }
    }
    Ok(())
}

pub fn cmd_secrets(paths: &Paths, args: &[String], token_source: TokenSource) -> Result<()> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    match sub {
        "" | "-h" | "--help" | "help" => {
            println!(
                "usage: vaulted-agent secrets list\n\
                 \x20      vaulted-agent secrets get <ref>\n\
                 \x20      vaulted-agent secrets which\n\
                 \x20      vaulted-agent secrets validate [manifest-or-harness] [--offline]\n\
                 \x20      vaulted-agent secrets refresh [manifest] [--all]\n\
                 \nrefs: UUID | uuid:UUID | name:KEY | project:PROJECT/KEY\n\
                 list/get use Bitwarden Secrets Manager (bws) with the same auth as launches."
            );
            Ok(())
        }
        "refresh" => cmd_refresh(paths, &args[1..], token_source),
        "list" => {
            let token = token_source.load(paths, TokenKind::Bws)?;
            let listing = backend::bws_listing(&token)?;
            drop(token);
            println!("Secrets visible to this token:");
            for (i, s) in listing.secrets().iter().enumerate() {
                println!("  {:2}) {:36}  {}{}", i + 1, s.id, s.key, s.project_note());
            }
            Ok(())
        }
        "get" => {
            let r = args
                .get(1)
                .ok_or_else(|| Error::Message("usage: vaulted-agent secrets get <ref>".into()))?;
            let token = token_source.load(paths, TokenKind::Bws)?;
            let id = backend::bws_resolve_ref(&token, r)?;
            let value = backend::bws_secret_value(&token, &id)?;
            drop(token);
            println!("{value}");
            Ok(())
        }
        "which" => {
            println!("Harness → variables (names only; values never printed)\n");
            // A read-only listing: one bad file is reported in its place
            // rather than hiding every Harness after it.
            for entry in Inventory::load(paths)?.harnesses() {
                let name = &entry.name;
                let v = match &entry.loaded {
                    Ok(v) => v,
                    Err(e) => {
                        println!("{name}  (unreadable: {e})");
                        continue;
                    }
                };
                let (be, man) = (v.binding.backend, &v.harness.manifest);
                println!("{name}  (backend={be} manifest={man})");
                let man_path = &v.binding.manifest;
                if man_path.is_file() {
                    if let Ok(text) = fs::read_to_string(man_path) {
                        if let Ok(map) = parse_dotenv_keys(&text) {
                            for k in map.keys() {
                                println!("  {k}");
                            }
                        }
                    }
                } else {
                    println!("  (manifest missing: {})", man_path.display());
                }
            }
            Ok(())
        }
        "validate" => {
            // Live by default: a gate that never asks the vault is not a gate.
            // --offline keeps the old cheap check for somewhere without a token.
            let rest: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();
            let mut offline = false;
            let mut positional: Vec<&str> = Vec::new();
            for s in rest {
                match s {
                    "--offline" => offline = true,
                    flag if flag.starts_with('-') => {
                        return Err(Error::Message(format!(
                            "secrets validate: unknown option '{flag}' (try --offline)"
                        )));
                    }
                    other => positional.push(other),
                }
            }
            // Everything this machine reads, not everything it launches. The
            // manifest an operator forgets is exactly the one nothing launches
            // from, and a gate that walks launch profiles alone reports it
            // green while the units that read it are down.
            let inventory = Inventory::load(paths)?;
            let single: Binding;
            let (targets, form) = match positional.first().copied() {
                None => (inventory.validate_targets(), Form::All),
                Some(name) => {
                    single = match inventory.harness(name) {
                        // A named Harness whose conf will not load fails the
                        // command with that error.
                        Some(entry) => match &entry.loaded {
                            Ok(v) => v.binding.clone(),
                            Err(e) => return Err(Error::Message(e.to_string())),
                        },
                        None => Binding {
                            manifest: paths.resolve_manifest(name),
                            // positional, not args[2]: --offline may sit anywhere.
                            backend: match positional.get(1) {
                                Some(s) => s.parse()?,
                                None => inventory.default_backend(),
                            },
                        },
                    };
                    let target = ValidateTarget {
                        label: single.manifest.display().to_string(),
                        check: Ok(&single),
                    };
                    (vec![target], Form::Single)
                }
            };
            let mut probe = VaultProbe::new(paths, token_source);
            let mode = if offline {
                Mode::Offline
            } else {
                Mode::Live(&mut probe)
            };
            let report = preflight::run(&targets, mode);
            let rendered = report.render(form);
            print!("{}", rendered.stdout);
            eprint!("{}", rendered.stderr);
            report.outcome(form)
        }
        other => Err(Error::Message(format!(
            "unknown secrets subcommand '{other}' (try: list, get, which, validate, refresh)"
        ))),
    }
}

/// Report whether a vault token file is present, missing, or unreadable.
/// Returns 1 when the file is unreadable (counts as a doctor error), else 0.
fn report_token_file(
    label: &str,
    path: &std::path::Path,
    running_as: &str,
    service_user: Option<&str>,
) -> usize {
    use crate::auth::{token_file_status, TokenFileStatus};
    match token_file_status(path) {
        TokenFileStatus::Present => {
            println!("{label}: present");
            0
        }
        TokenFileStatus::Missing => {
            println!("{label}: missing");
            0
        }
        TokenFileStatus::Unreadable { source } => {
            let who = if running_as.is_empty() {
                "this process".to_string()
            } else {
                running_as.to_string()
            };
            println!("{label}: unreadable ({source} as {who})");
            if service_user.is_none() {
                println!(
                    "  HINT: no service_user set — launches never hop to the account that can read this file"
                );
            }
            1
        }
    }
}

/// What, if anything, to say about a harness's `workdir`.
///
/// Under a Service user, the Workdir audit probes the paths a launch would
/// need (issue #58) by the same rules the launch preflight uses (#128).
/// Otherwise, nudge agent harnesses toward `workdir = caller`.
fn workdir_warning(
    service_user: Option<&str>,
    workdir: Option<&str>,
    harness: &str,
    caller: &CallerContext,
) -> Option<String> {
    if service_user.is_some_and(|s| !s.is_empty()) {
        return workdir::audit(workdir, caller, service_user);
    }
    let is_agent = matches!(
        harness,
        "claude" | "codex" | "grok" | "kimi" | "agy" | "muse"
    );
    (is_agent && workdir != Some("caller")).then(|| "agent harness without workdir=caller".into())
}

/// Names for a one-line report: the first few, then a count of the rest.
///
/// A whole-vault manifest puts 81 names in one warning, repeated for every
/// harness pointing at that manifest. Five harnesses turned a health report
/// into five screens of names, which is the same as printing nothing: the
/// operator scrolls past it to find the summary. Enough names to recognise
/// which manifest is meant, and a count for the scale of it.
fn sample(names: &[String]) -> String {
    const SHOWN: usize = 8;
    if names.len() <= SHOWN {
        return names.join(", ");
    }
    format!(
        "{}, and {} more",
        names[..SHOWN].join(", "),
        names.len() - SHOWN
    )
}

pub fn cmd_doctor(paths: &Paths) -> Result<()> {
    let mut issues = 0usize;
    let mut warn = 0usize;
    // Legacy-name warnings are about the *manifest*, not the harness. Five
    // harnesses on one whole-vault file would otherwise reprint the same
    // sample five times and inflate the summary (follow-up to #60/#61).
    let mut legacy_warned: HashSet<PathBuf> = HashSet::new();
    println!("vaulted-agent doctor");
    println!("config: {}", paths.config_dir.display());
    // A defaults.conf that will not load is one finding; the checks below
    // still run, against the built-in values, labelled as such.
    let (defaults, label) = match Defaults::load(paths) {
        Ok(d) => (d, ""),
        Err(e) => {
            println!("ERROR: {e}");
            issues += 1;
            (Defaults::default(), " (built-in)")
        }
    };
    println!("auth_mode: {}{label}", defaults.auth_mode.as_str());
    println!("default_backend: {}{label}", defaults.default_backend);

    // Nearly every check below is a filesystem question -- is op.env readable,
    // is the manifest readable, is the harness bin executable -- and the answer
    // depends on who is asking. Launches run as service_user, so a report
    // produced as the calling user can describe an account that never runs an
    // agent: on the host this was found, doctor called op.env "missing" while
    // the launcher read it without trouble. main re-execs doctor through the
    // same hop a launch uses; name the account that answered so the report is
    // never read against the wrong one.
    let running_as = crate::privilege::current_user();
    let service_user = defaults.service_user;
    let caller = CallerContext::from_env();
    match service_user.as_deref() {
        Some(svc) if svc != running_as => {
            // Only reached when the hop was declined (VAULTED_AGENT_NO_REEXEC)
            // or could not run, so say plainly that the findings do not apply.
            println!("checked as: {running_as}");
            println!("service_user: {svc}");
            println!("  WARN: launches run as {svc}; these checks describe {running_as} instead");
            warn += 1;
        }
        Some(svc) => println!("checked as: {svc} (service_user, same as a launch)"),
        None => println!("checked as: {running_as} (no service_user set, same as a launch)"),
    }

    // Redirect stdout so `command -v` path noise never pollutes the report.
    let have = |bin: &str| {
        Command::new("sh")
            .args(["-c", &format!("command -v {bin} >/dev/null 2>&1")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    let have_bws = have("bws");
    let have_op = have("op");
    let have_sops = have("sops");
    let have_pass = have("pass");
    println!(
        "tools: bws={} op={} sops={} pass={}",
        yn(have_bws),
        yn(have_op),
        yn(have_sops),
        yn(have_pass)
    );

    // Three states, not two: is_file() used to report EACCES as "missing"
    // (issue #51), which sent operators hunting for a file that was present
    // and steered them toward pasting a vault token by hand.
    issues += report_token_file(
        "bws.env",
        &paths.bws_env_file,
        &running_as,
        service_user.as_deref(),
    );
    issues += report_token_file(
        "op.env",
        &paths.op_env_file,
        &running_as,
        service_user.as_deref(),
    );

    let names = list_harness_names(paths)?;
    if names.is_empty() {
        println!("harnesses: (none)");
        warn += 1;
    }
    let be_default = defaults.default_backend;
    for name in &names {
        println!("\nharness: {name}");
        let h = match Harness::load(paths, name) {
            Ok(h) => h,
            Err(e) => {
                println!("  ERROR: {e}");
                issues += 1;
                continue;
            }
        };
        let be = h.backend.unwrap_or(be_default);
        let wd = h.workdir.as_deref().unwrap_or("(default)");
        println!("  backend={be} manifest={} workdir={wd}", h.manifest);
        let man_path = h.resolve_manifest_path(paths);
        if !man_path.is_file() {
            println!("  ERROR: cannot read {}", man_path.display());
            issues += 1;
        } else if let Err(e) = validate_manifest_file(&man_path, be) {
            println!("  ERROR: manifest: {e}");
            issues += 1;
        } else {
            println!("  manifest syntax ok ({})", man_path.display());
            // Syntax is dotenv shape and nothing more. A reference that op's
            // scanner cannot read passes it and then aborts the injection of
            // the whole manifest at launch, so a report that stops at syntax
            // hands out a green that the next launch immediately contradicts.
            // Checked offline: this reads the file, never the vault.
            if be == Backend::OnePassword {
                // Only values that claim to be references. A plain literal
                // (region, URL, phone) is valid in a template: op inject
                // passes non-op:// text through. Treating "not a reference"
                // as "malformed reference" painted healthy manifests red
                // (issue #53).
                let mut unparseable: Vec<String> = fs::read_to_string(&man_path)
                    .ok()
                    .and_then(|t| parse_dotenv_keys(&t).ok())
                    .map(|m| {
                        m.into_iter()
                            .filter(|(_, v)| v.starts_with("op://") && !onepassword::is_readable(v))
                            .map(|(k, _)| k)
                            .collect()
                    })
                    .unwrap_or_default();
                // `op inject` resolves every reference in the file, comments
                // included. The dotenv parser drops comments, so without this
                // a file that cannot inject at all was reported healthy.
                // Shared helper with edit-manifest so the two agree.
                if let Ok(text) = fs::read_to_string(&man_path) {
                    let in_comments = crate::validate::comment_lines_with_op_refs(&text);
                    if !in_comments.is_empty() {
                        println!(
                            "  ERROR: {} comment line(s) contain a secret reference ({}). \
                             `op inject` resolves references in comments too, and one that \
                             fails aborts the whole manifest — every variable, not just \
                             these. Remove the reference or reword the comment.",
                            in_comments.len(),
                            in_comments
                                .iter()
                                .map(|n| format!("line {n}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                        issues += 1;
                    }
                }
                if !unparseable.is_empty() {
                    unparseable.sort();
                    println!(
                        "  ERROR: op cannot parse {} reference(s), which aborts the whole \
                         manifest, not just these: {}",
                        unparseable.len(),
                        unparseable.join(", ")
                    );
                    println!("  Re-run `vaulted-agent refresh` to rewrite them.");
                    issues += 1;
                }
                // Names generated before default section labels were dropped.
                // Reported, not an error: they resolve exactly as they always
                // did. The point is that the next `refresh` writes a different
                // name for the same field, and finding that out here beats
                // finding it out when something reading the old name breaks.
                let mut legacy: Vec<String> = fs::read_to_string(&man_path)
                    .ok()
                    .and_then(|t| parse_dotenv_keys(&t).ok())
                    .map(|m| {
                        m.into_iter()
                            .filter(|(k, v)| onepassword::has_legacy_name(k, v))
                            .map(|(k, _)| k)
                            .collect()
                    })
                    .unwrap_or_default();
                if !legacy.is_empty() && legacy_warned.insert(man_path.clone()) {
                    legacy.sort();
                    println!(
                        "  WARN: {} variable(s) in {} carry a 1Password default section \
                         label in the name ({}). They work; `refresh` now generates the \
                         shorter name for the same field. See MIGRATION.md.",
                        legacy.len(),
                        man_path
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or("manifest"),
                        sample(&legacy)
                    );
                    warn += 1;
                }
            }
            // Syntactically fine and completely empty is the shape `setup`
            // leaves behind when it auto-detects an agent before a vault is
            // wired: a comments-only refs file. The harness then launches
            // perfectly, with nothing in its environment, and the agent fails
            // later for reasons that look nothing like a launcher problem.
            // Say it here instead — unless listed in etc/env-blind-agents,
            // where empty.env is the expected shape (inject is a no-op).
            let defined = fs::read_to_string(&man_path)
                .ok()
                .and_then(|t| parse_dotenv_keys(&t).ok())
                .map(|m| m.len())
                .unwrap_or(0);
            let env_blind = h.command_basename().and_then(env_blind_agent_reason);
            if let Some(reason) = env_blind {
                if defined > 0 {
                    println!("  WARN: manifest defines {defined} variable(s), but {reason}");
                    warn += 1;
                } else {
                    println!(
                        "  note: empty manifest is expected for this agent ({})",
                        h.command_basename().unwrap_or("?")
                    );
                }
                if !h.aliases.is_empty() {
                    println!(
                        "  WARN: alias= is set on an env-blind agent; aliases only rename \
                         child-env variables and do not reach this tool's config file"
                    );
                    warn += 1;
                }
            } else if defined == 0 {
                println!(
                    "  WARN: manifest defines no variables, so this harness launches with no secrets (finish `vaulted-agent setup`, or point it at a real manifest)"
                );
                warn += 1;
            }
        }
        match be {
            Backend::Bitwarden if !have_bws => {
                println!("  ERROR: bws not on PATH");
                issues += 1;
            }
            Backend::OnePassword if !have_op => {
                println!("  ERROR: op not on PATH");
                issues += 1;
            }
            Backend::Sops if !have_sops => {
                println!("  ERROR: sops not on PATH");
                issues += 1;
            }
            Backend::Pass if !have_pass => {
                println!("  ERROR: pass not on PATH");
                issues += 1;
            }
            Backend::Plainfile
            | Backend::Bitwarden
            | Backend::OnePassword
            | Backend::Sops
            | Backend::Pass => {}
        }
        if let Some(msg) =
            workdir_warning(service_user.as_deref(), h.workdir.as_deref(), name, &caller)
        {
            println!("  WARN: {msg}");
            warn += 1;
        }
    }
    println!("\nSummary: {issues} error(s), {warn} warning(s)");
    if issues > 0 {
        println!("Fix errors before relying on launches. Try: vaulted-agent setup");
        return Err(Error::Message(format!("{issues} doctor error(s)")));
    }
    println!("Ready (syntax checks only; live vault access not probed).");
    Ok(())
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// The Backend `setup <name>` sets up. `plainfile` is not a vault.
fn setup_backend(name: &str) -> Result<Backend> {
    match Backend::parse_loose(name) {
        Some(be) if be != Backend::Plainfile => Ok(be),
        _ => Err(Error::Message(format!(
            "setup: unknown backend '{name}' (want bitwarden, onepassword, pass, sops)"
        ))),
    }
}

/// Vault wiring for `be`, then its report.
fn wire(paths: &Paths, be: Backend) -> Result<()> {
    let inventory = Inventory::load(paths)?;
    let plan = vault_wiring::plan(paths, &inventory, be)
        .map_err(|e| Error::Message(format!("setup: cannot wire {be}: {e}")))?;
    plan.apply(paths)?;
    print!("{}", plan.report());
    Ok(())
}

/// Legacy fallback for `Capture::UseExisting`: load the token the usual way
/// (env var, existing file, or prompt) and, under `auth_mode=file`, persist it
/// so rotating through an exported token still lands on disk.
fn store_existing_token(
    paths: &Paths,
    kind: TokenKind,
    token_source: TokenSource,
) -> Result<ManagerToken> {
    let token = token_source.load(paths, kind)?;
    let path = kind.file(paths).to_path_buf();
    if token_source.auth_mode() == AuthMode::File {
        let svc = Defaults::load(paths)?.service_user;
        auth::write_token_file(&path, kind.env_var(), &token, svc.as_deref())?;
        println!("wrote {} (0640)", path.display());
    } else {
        println!("auth_mode=prompt — token not written to disk (good).");
        println!(
            "  To store it: vaulted-agent auth-mode file, then re-run setup {}.",
            kind.backend_name()
        );
    }
    Ok(token)
}

fn setup_bitwarden(paths: &Paths, token_source: TokenSource, set_token: bool) -> Result<()> {
    println!("\nBitwarden Secrets Manager");
    println!("  Needs a Machine Account access token (BWS_ACCESS_TOKEN),");
    println!("  not your personal vault master password or login API key.\n");
    // Token capture: setup is the only place that may obtain and store a
    // manager token (issue #77). `bws secret list` is both the liveness check
    // that keeps an invalid token off disk and the data the rest of setup
    // needs, so keep the result instead of paying for a second round trip.
    let listed: RefCell<Option<BwListing>> = RefCell::new(None);
    let verify = |t: &ManagerToken| {
        *listed.borrow_mut() = Some(backend::bws_listing(t)?);
        Ok(())
    };
    let token = match auth::capture_token(
        paths,
        TokenKind::Bws,
        token_source.auth_mode(),
        set_token,
        &verify,
    )? {
        auth::Capture::Token(t) => t,
        auth::Capture::UseExisting => store_existing_token(paths, TokenKind::Bws, token_source)?,
        auth::Capture::Skipped => {
            // Everything left here needs the token to talk to the vault.
            println!("Skipping vault work. When you have a token:");
            println!("  vaulted-agent setup bitwarden");
            return Ok(());
        }
    };
    let secrets = match listed.borrow_mut().take() {
        Some(secrets) => secrets,
        None => backend::bws_listing(&token)?,
    };
    drop(token);
    if secrets.is_empty() {
        println!("No secrets in this machine account yet. Create one in SM, then:");
        println!("  vaulted-agent secrets list");
        println!("  vaulted-agent refresh");
        return Ok(());
    }
    println!("{} secret(s) visible.", secrets.len());
    let man_path = refresh::default_refs_file(paths, Backend::Bitwarden)?;
    fs::create_dir_all(&paths.manifest_dir).ok();
    let mode = WriteMode::settle(None, &man_path);
    let written = refs::write_refs(
        &man_path,
        &Mapping::bitwarden_selection(&secrets, None),
        mode,
        RefsStyle::Bitwarden,
        "vaulted-agent setup",
    )?;
    if mode == WriteMode::Merge {
        if written.recovered > 0 {
            println!(
                "Split {} mapping(s) that were glued onto one line (va 0.3.0 refresh)",
                written.recovered
            );
        }
        println!("Merged into {} (+{})", man_path.display(), written.added);
    } else {
        println!("Wrote {}", man_path.display());
    }
    Ok(())
}

fn setup_onepassword(paths: &Paths, token_source: TokenSource, set_token: bool) -> Result<()> {
    println!("\n1Password service account");
    println!("  Needs OP_SERVICE_ACCOUNT_TOKEN (not your personal account password).\n");
    // Token capture (issue #77); `op whoami` verifies before anything is written.
    let verify = |t: &ManagerToken| backend::op_whoami(t);
    match auth::capture_token(
        paths,
        TokenKind::Op,
        token_source.auth_mode(),
        set_token,
        &verify,
    )? {
        auth::Capture::Token(token) => drop(token),
        auth::Capture::UseExisting => {
            drop(store_existing_token(paths, TokenKind::Op, token_source)?)
        }
        // A declined paste skips the token, not the rest of setup: the guidance
        // below is what tells the operator how to wire a harness (install.sh
        // parity — its skip is a skip of the token write only).
        auth::Capture::Skipped => {}
    }
    println!("Manifests use op:// references; op inject runs at launch.");
    Ok(())
}

pub fn cmd_setup(paths: &Paths, args: &[String], token_source: TokenSource) -> Result<()> {
    // `--set-token` is the piped-capture / rotation door. Not `auth-mode`:
    // that verb is about *how* tokens are supplied, not *what* the token is.
    let set_token = args.iter().any(|a| a == "--set-token");
    // `--wire-only` is the installer's door: Vault wiring, then stop before
    // Token capture, so a machine with no token yet still gets wired.
    let wire_only = args.iter().any(|a| a == "--wire-only");

    // Explicit backend: setup [bitwarden|onepassword|bws|op|pass|sops]
    let want = args
        .iter()
        .map(|s| s.as_str())
        .find(|s| !s.starts_with('-'));

    if wire_only && set_token {
        return Err(Error::Message(
            "setup: --wire-only stops before Token capture; it cannot be used with --set-token"
                .into(),
        ));
    }
    if wire_only && want.is_none() {
        return Err(Error::Message(
            "setup --wire-only: name the backend, e.g.\n  \
             vaulted-agent setup bitwarden --wire-only"
                .into(),
        ));
    }

    println!("vaulted-agent setup");
    println!("config: {}", paths.config_dir.display());

    if wire_only {
        // The installer asks its own questions and then calls this: asking
        // them again here would ask twice.
        return wire(paths, setup_backend(want.unwrap_or_default())?);
    }

    // Ask how manager tokens are obtained (file on disk vs paste each launch)
    // before any backend work that may write op.env / bws.env.
    let token_source = ensure_auth_mode_for_setup(paths, token_source)?;
    println!("auth_mode: {}", token_source.auth_mode().as_str());

    // Who agents run as, and where they start — both shape every later launch,
    // and interact (service_user + workdir=caller on a 0700 home). Ask before
    // token write so chown root:service_user is right (issue #55).
    let service_user = ensure_service_user_for_setup(paths)?;
    ensure_workdir_for_setup(paths, service_user.as_deref())?;

    // Vault wiring first: it needs no token, so a missing or rejected token
    // still leaves the machine wired (installer order).
    let choose = |name: &str| -> Result<()> {
        let be = setup_backend(name)?;
        if set_token && !be.needs_manager_token() {
            return Err(Error::Message(format!(
                "setup --set-token: {be} has no manager token file \
                 (pass uses GPG, sops uses an age key)"
            )));
        }
        wire(paths, be)?;
        match be {
            Backend::Bitwarden => setup_bitwarden(paths, token_source, set_token),
            Backend::OnePassword => setup_onepassword(paths, token_source, set_token),
            Backend::Pass => {
                println!("\npass backend uses the passwordstore.org store (GPG).");
                println!("No token file. Ensure `pass` is on PATH for the service account.");
                Ok(())
            }
            Backend::Sops | Backend::Plainfile => {
                println!(
                    "\nsops backend uses age identity at {}",
                    paths.age_key_file.display()
                );
                println!("Place the age key there (0640) and encrypt manifests with sops.");
                Ok(())
            }
        }
    };

    if let Some(name) = want {
        return choose(name);
    }

    // Auto: prefer whichever token is already available (env or file).
    if env::var_os("BWS_ACCESS_TOKEN").is_some() || paths.bws_env_file.is_file() {
        return choose("bitwarden");
    }
    if env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_some() || paths.op_env_file.is_file() {
        return choose("onepassword");
    }

    // Nothing on disk or in env to infer from: a piped token has no backend to
    // go with, and guessing would store a credential against the wrong vault.
    if set_token {
        return Err(Error::Message(
            "setup --set-token: name the backend, e.g.\n  \
             printf %s \"$TOKEN\" | vaulted-agent setup bitwarden --set-token"
                .into(),
        ));
    }

    // Interactive menu when TTY; else print usage.
    if can_prompt_user() {
        eprintln!("\nChoose vault backend:");
        eprintln!("  1) bitwarden   (Bitwarden Secrets Manager)");
        eprintln!("  2) onepassword (1Password service account)");
        eprintln!("  3) pass");
        eprintln!("  4) sops");
        eprint!("backend [1-4]: ");
        let _ = io::stderr().flush();
        let line = read_tty_line()?;
        let choice = line.trim();
        let name = match choice {
            "1" | "bitwarden" | "bws" => "bitwarden",
            "2" | "onepassword" | "op" | "1password" => "onepassword",
            "3" | "pass" => "pass",
            "4" | "sops" => "sops",
            "" => {
                println!("Nothing configured. Re-run: vaulted-agent setup bitwarden|onepassword");
                return Ok(());
            }
            other => {
                return Err(Error::Message(format!("setup: bad choice '{other}'")));
            }
        };
        return choose(name);
    }

    println!(
        "No vault token yet. Non-interactive examples:\n\
         \x20 export BWS_ACCESS_TOKEN=… && vaulted-agent setup bitwarden\n\
         \x20 export OP_SERVICE_ACCOUNT_TOKEN=… && vaulted-agent setup onepassword\n\
         \x20 Or write {} / {} and re-run setup.",
        paths.bws_env_file.display(),
        paths.op_env_file.display()
    );
    Ok(())
}

pub fn cmd_uninstall(args: &[String]) -> Result<()> {
    let mut purge = false;
    let mut dry = false;
    let mut yes = false;
    let mut link_users: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--purge" => purge = true,
            "--dry-run" => dry = true,
            "-y" | "--yes" => yes = true,
            "-h" | "--help" => {
                println!(
                    "usage: vaulted-agent uninstall [--purge] [--dry-run] [-y|--yes] [--link-user USER]\n\
                     Removes the launcher, conductor symlinks, sudoers rule, and optional user-local links.\n\
                     Keeps config unless --purge. Never removes op.env / bws.env credentials."
                );
                return Ok(());
            }
            "--link-user" => {
                i += 1;
                let u = args
                    .get(i)
                    .ok_or_else(|| {
                        Error::Message("uninstall: --link-user needs a username".into())
                    })?
                    .clone();
                link_users.push(u);
            }
            s if s.starts_with("--link-user=") => {
                link_users.push(s["--link-user=".len()..].to_string());
            }
            other => {
                return Err(Error::Message(format!(
                    "uninstall: unknown option '{other}'"
                )));
            }
        }
        i += 1;
    }

    // Also consider SUDO_USER when present (install.sh parity).
    if let Ok(u) = env::var("SUDO_USER") {
        if !u.is_empty() && !link_users.iter().any(|x| x == &u) {
            link_users.push(u);
        }
    }

    let prefix = env::var("VAULTED_AGENT_BIN_DIR").unwrap_or_else(|_| "/usr/local/bin".into());
    let config =
        env::var("VAULTED_AGENT_CONFIG_DIR").unwrap_or_else(|_| "/etc/vaulted-agent".into());
    let launcher = PathBuf::from(&prefix).join("vaulted-agent");
    let va = PathBuf::from(&prefix).join("va");

    let mut targets: Vec<PathBuf> = Vec::new();
    if launcher.exists() || launcher.is_symlink() {
        targets.push(launcher.clone());
    }
    if va.is_symlink() || va.exists() {
        targets.push(va);
    }
    // conductor symlinks
    if let Ok(rd) = fs::read_dir(&prefix) {
        for ent in rd.flatten() {
            let p = ent.path();
            let name = ent.file_name().to_string_lossy().into_owned();
            if name.ends_with("-conductor") && p.is_symlink() {
                targets.push(p);
            }
        }
    }

    // User-local symlinks (~/.local/bin/vaulted-agent and va)
    for u in &link_users {
        if let Some(home) = crate::privilege::account_home(u) {
            for name in ["vaulted-agent", "va"] {
                let p = home.join(".local/bin").join(name);
                if p.exists() || p.is_symlink() {
                    targets.push(p);
                }
            }
        }
    }

    // Sudoers rule left by install.sh (story #26) — dangling NOPASSWD is worse than gone.
    let sudoers = PathBuf::from("/etc/sudoers.d/vaulted-agent");
    if sudoers.exists() {
        targets.push(sudoers);
    }

    println!("vaulted-agent uninstall");
    for t in &targets {
        println!("  remove {}", t.display());
    }
    if purge {
        println!("  purge config {}", config);
    }
    if dry {
        println!("dry-run: no changes");
        return Ok(());
    }
    if !yes && io::IsTerminal::is_terminal(&io::stdin()) {
        eprint!("Proceed? [y/N]: ");
        let _ = io::stderr().flush();
        let mut line = String::new();
        io::stdin().read_line(&mut line).ok();
        if !matches!(line.trim(), "y" | "Y" | "yes" | "YES") {
            println!("Aborted.");
            return Ok(());
        }
    }

    for t in &targets {
        if let Err(e) = fs::remove_file(t) {
            eprintln!("warn: could not remove {}: {e}", t.display());
        }
    }
    if purge {
        // Never remove credential files if present alone — remove whole tree except note
        // Spec: never remove backend credentials intentionally — but --purge removes config dir.
        // Match bash: --purge removes config dir contents carefully.
        let protect = ["op.env", "bws.env", "age.key"];
        if let Ok(rd) = fs::read_dir(&config) {
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().into_owned();
                if protect.contains(&name.as_str()) {
                    println!("  keep credential {}", ent.path().display());
                    continue;
                }
                let p = ent.path();
                if p.is_dir() {
                    let _ = fs::remove_dir_all(&p);
                } else {
                    let _ = fs::remove_file(&p);
                }
            }
        }
    }
    println!("Done.");
    Ok(())
}

/// Why `run` is refused, or None when it may proceed.
///
/// Every other entry point can only start a `command =` line that root wrote
/// into a harness file. `run` takes its command from the caller, which makes it
/// the one subcommand that turns this launcher into a general executor.
///
/// That is harmless on a single-operator machine, and it is the whole ballgame
/// once a service account exists: the account agents run as typically holds
/// broad sudo, so a grant of this launcher meant for one harness would also
/// carry `run -- /bin/sh` as that account. Configuring `service_user` is the
/// signal that the launcher is delegated, so `run` is off by default there and
/// takes an explicit `allow_run = yes` to restore.
fn run_refusal(service_user: Option<&str>, allow_run: bool) -> Option<String> {
    match service_user {
        Some(svc) if !allow_run => Some(format!(
            "run is disabled while service_user={svc} is configured: it takes its command from the caller, so a grant of this launcher would also carry `run -- /bin/sh` as {svc}. Set `allow_run = yes` in defaults.conf to re-enable it."
        )),
        _ => None,
    }
}

pub fn cmd_run(paths: &Paths, args: &[String], token_source: TokenSource) -> Result<()> {
    let defaults = Defaults::load(paths)?;
    if let Some(msg) = run_refusal(defaults.service_user.as_deref(), defaults.allow_run) {
        return Err(Error::Message(msg));
    }
    let mut manifest: Option<String> = None;
    let mut backend = defaults.default_backend;
    let mut workdir: Option<String> = Some("caller".into());
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!(
                    "usage: vaulted-agent run -m MANIFEST [--backend NAME] [--workdir DIR] -- cmd [args...]\n\
                     Inject vault-resolved secrets into any command (no harness file)."
                );
                return Ok(());
            }
            "-m" | "--manifest" => {
                i += 1;
                manifest = Some(
                    args.get(i)
                        .ok_or_else(|| Error::Message("run: -m needs a path".into()))?
                        .clone(),
                );
            }
            s if s.starts_with("--manifest=") => {
                manifest = Some(s["--manifest=".len()..].to_string());
            }
            "--backend" => {
                i += 1;
                let name = args
                    .get(i)
                    .ok_or_else(|| Error::Message("run: --backend needs a name".into()))?;
                backend = name.parse()?;
            }
            s if s.starts_with("--backend=") => {
                backend = s["--backend=".len()..].parse()?;
            }
            "--workdir" => {
                i += 1;
                workdir = Some(
                    args.get(i)
                        .ok_or_else(|| Error::Message("run: --workdir needs a path".into()))?
                        .clone(),
                );
            }
            s if s.starts_with("--workdir=") => {
                workdir = Some(s["--workdir=".len()..].to_string());
            }
            "--" => {
                i += 1;
                break;
            }
            s if s.starts_with('-') => {
                return Err(Error::Message(format!("run: unknown option '{s}'")));
            }
            _ => break,
        }
        i += 1;
    }
    let cmd: Vec<String> = args[i..].to_vec();
    if cmd.is_empty() {
        return Err(Error::Message(
            "run: missing command after options (try: run -m MANIFEST -- cmd)".into(),
        ));
    }
    let man = manifest.ok_or_else(|| Error::Message("run: need -m/--manifest".into()))?;
    let man_path = paths.resolve_manifest(&man);
    launch::launch_run(
        paths,
        &man_path,
        backend,
        workdir.as_deref(),
        &cmd,
        token_source,
    )
}

/// The pick menu. `None` when the operator quits without choosing.
pub fn cmd_pick(paths: &Paths) -> Result<Option<String>> {
    let inventory = Inventory::load(paths)?;
    let entries = inventory.harnesses();
    if entries.is_empty() {
        return Err(Error::Message(format!(
            "no harnesses configured in {}",
            paths.harness_dir.display()
        )));
    }
    if !io::IsTerminal::is_terminal(&io::stdout()) {
        return Err(Error::Message(
            "'pick' needs an interactive terminal; name the harness instead".into(),
        ));
    }
    eprintln!();
    for (i, e) in entries.iter().enumerate() {
        let h = e.loaded.as_ref().ok().map(|v| &v.harness);
        let cmd = h.map(|h| h.command.join(" ")).unwrap_or_default();
        let man = h.map(|h| h.manifest.as_str()).unwrap_or_default();
        eprintln!("  {:2}) {:16} {:38} {}", i + 1, e.name, cmd, man);
    }
    eprintln!();
    loop {
        eprint!("harness [1-{}, q to quit]: ", entries.len());
        let _ = io::stderr().flush();
        let mut line = String::new();
        let mut tty = match fs::File::open("/dev/tty") {
            Ok(f) => io::BufReader::new(f),
            Err(_) => {
                return Err(Error::Message("pick needs /dev/tty".into()));
            }
        };
        if tty.read_line(&mut line).is_err() {
            return Err(Error::Message("pick aborted".into()));
        }
        let choice = line.trim();
        if matches!(choice, "q" | "Q" | "quit" | "exit") {
            eprintln!("Nothing launched.");
            return Ok(None);
        }
        if let Ok(n) = choice.parse::<usize>() {
            if n >= 1 && n <= entries.len() {
                return Ok(Some(entries[n - 1].name.clone()));
            }
            eprintln!("  out of range");
        } else {
            eprintln!("  not a number");
        }
    }
}

/// Launch a harness, optionally against a manifest other than its configured one.
///
/// The override serves the direct `va <harness>` path (and `va pick`) only.
/// Under a `*-conductor` symlink it is refused before this is reached, alongside
/// `-H` and for the same reason: the symlink is what lets a sudoers rule grant
/// one harness and have that mean one set of credentials. On the direct path
/// the caller can already reach `run -m` with any manifest they like, so
/// refusing here would cost convenience and buy no safety.
pub fn cmd_launch_harness(
    paths: &Paths,
    name: &str,
    extra_args: &[String],
    token_source: TokenSource,
    manifest_override: Option<&str>,
) -> Result<()> {
    let mut harness = Harness::load(paths, name)?;
    if let Some(manifest) = manifest_override {
        harness.manifest = manifest.to_string();
        // Checked here rather than at injection, so a typo is a clear message
        // instead of a manifest that reads as empty and an agent that starts
        // with nothing in its environment and fails much later.
        let path = harness.resolve_manifest_path(paths);
        if !path.is_file() {
            return Err(Error::Message(format!(
                "no manifest at {} (-m takes a file in {} or an absolute path)",
                path.display(),
                paths.manifest_dir.display()
            )));
        }
        // Announce it. A flag that quietly changes which credentials an agent
        // carries is the kind of thing nobody notices until afterwards, and
        // this line is what a scrollback search finds.
        eprintln!(
            "vaulted-agent: {name} launching with manifest '{}' instead of its configured one",
            harness.manifest
        );
    }
    let harness = harness;
    launch::launch_harness(
        paths,
        &harness,
        &LaunchOpts {
            token_source,
            extra_args: extra_args.to_vec(),
            handoff: None,
        },
    )
}

pub fn usage(paths: &Paths) {
    let defaults = match Defaults::load(paths) {
        Ok(d) => format!(
            "default auth_mode: {}  (file = token on disk; prompt = paste each launch)\n\
             default backend:   {}",
            d.auth_mode.as_str(),
            d.default_backend
        ),
        Err(e) => format!("defaults: {e}"),
    };
    eprintln!(
        "usage: vaulted-agent [-m MANIFEST] <harness> [args...]\n\
         \x20      va [-m MANIFEST] <harness> [args...]\n\
         \x20      vaulted-agent run -m MANIFEST [--backend NAME] -- cmd [args...]\n\
         \x20      vaulted-agent pick [args...]\n\
         \x20      vaulted-agent doctor\n\
         \x20      vaulted-agent secrets …\n\
         \x20      vaulted-agent setup [bitwarden|onepassword|pass|sops] [--set-token|--wire-only]\n\
         \x20      vaulted-agent refresh [file]\n\
         \x20      vaulted-agent edit-manifest [name]\n\
         \x20      vaulted-agent auth-mode [mode]\n\
         \x20      vaulted-agent version\n\
         \x20      vaulted-agent update [VERSION]\n\
         \x20      vaulted-agent uninstall [opts]\n\
         \nlauncher flags:  --prompt-auth|-p   prompt for vault token this launch\n\
         \x20                --manifest|-m     launch the harness against this manifest\n\
         \x20                                  instead of its configured one (before the\n\
         \x20                                  harness name; not allowed under a\n\
         \x20                                  *-conductor symlink)\n\
         {defaults}\n\
         config: VAULTED_AGENT_CONFIG_DIR (default /etc/vaulted-agent)\n\
         (tests only: VAULTED_AGENT_HANDOFF=spawn spawns instead of exec)"
    );
    // Read the Harness confs directly: the list needs no Backend, so a
    // defaults.conf that does not load must not hide it.
    if let Ok(names) = list_harness_names(paths) {
        eprintln!("\nharnesses in {}:", paths.harness_dir.display());
        if names.is_empty() {
            eprintln!("  (none configured)");
        } else {
            for name in &names {
                match Harness::load(paths, name) {
                    Ok(h) => eprintln!("  {:16} {}", name, h.command.join(" ")),
                    Err(_) => eprintln!("  {name}"),
                }
            }
        }
    }
}

/// Files under `manifests/` that are candidates to edit.
///
/// Backups and the launcher's own shipped samples are skipped. Offering one in
/// a menu invites editing a file nothing reads, and the operator only finds out
/// when the change has no effect.
fn editable_manifests(paths: &Paths) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let Ok(entries) = fs::read_dir(&paths.manifest_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let skip = name.ends_with(".example")
            || name.ends_with('~')
            || name.contains(".bak-")
            || name.contains(".bak.")
            || name.ends_with(".orig")
            || name.starts_with('.');
        if !skip {
            out.push(path);
        }
    }
    out.sort();
    out
}

/// The editor to hand the file to: $VISUAL, then $EDITOR, then vi.
fn editor_command() -> String {
    for key in ["VISUAL", "EDITOR"] {
        if let Ok(v) = env::var(key) {
            if !v.trim().is_empty() {
                return v;
            }
        }
    }
    "vi".to_string()
}

/// Open `path` in the operator's editor and wait.
///
/// A manifest is root-owned and the operator usually is not, so the write goes
/// through `sudoedit` when we cannot write it ourselves: it copies the file out,
/// runs the editor as the caller, and copies it back. Running the editor itself
/// as root would be the wrong trade — `vi` can spawn a shell, so it would turn
/// "may edit a manifest" into "may become root".
fn open_in_editor(path: &Path) -> Result<()> {
    let editor = editor_command();
    let writable = fs::OpenOptions::new().append(true).open(path).is_ok();
    let mut cmd = if writable {
        let mut c = std::process::Command::new("sh");
        c.arg("-c")
            .arg(format!("{editor} \"$1\"",))
            .arg("sh")
            .arg(path);
        c
    } else {
        let mut c = std::process::Command::new("sudoedit");
        c.env("SUDO_EDITOR", &editor).arg(path);
        c
    };
    let status = cmd.status().map_err(|e| {
        Error::Message(format!(
            "could not start the editor ({e}). Set $EDITOR, or edit {} directly.",
            path.display()
        ))
    })?;
    if !status.success() {
        return Err(Error::Message(format!(
            "editor exited without saving ({}); {} is unchanged",
            status,
            path.display()
        )));
    }
    Ok(())
}

/// Print the manifests and let the operator choose one.
fn pick_manifest(paths: &Paths) -> Result<PathBuf> {
    let candidates = editable_manifests(paths);
    if candidates.is_empty() {
        return Err(Error::Message(format!(
            "no manifests in {}",
            paths.manifest_dir.display()
        )));
    }
    // Which harness uses which file is the fact that decides whether an edit is
    // safe, so it belongs in the menu rather than a page of documentation.
    // By resolved path: a Harness may name the file absolutely.
    let inventory = Inventory::load(paths).ok();

    println!("Manifests in {}:", paths.manifest_dir.display());
    for (i, path) in candidates.iter().enumerate() {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let count = fs::read_to_string(path)
            .ok()
            .and_then(|t| crate::config::parse_dotenv_keys(&t).ok())
            .map(|m| m.len());
        let users = inventory
            .as_ref()
            .map(|inv| inv.harnesses_using(path))
            .unwrap_or_default();
        let used = if users.is_empty() {
            "unused".to_string()
        } else {
            format!("used by {}", users.join(", "))
        };
        match count {
            Some(n) => println!("  {:2}) {name}  ({n} variable(s), {used})", i + 1),
            // A file that will not parse is exactly the one worth opening.
            None => println!("  {:2}) {name}  (unreadable, {used})", i + 1),
        }
    }
    println!();
    eprint!("Edit which? [1-{}]: ", candidates.len());
    let _ = io::stderr().flush();
    let line = read_tty_line()?;
    let choice: usize = line
        .trim()
        .parse()
        .map_err(|_| Error::Message(format!("not a number: {}", line.trim())))?;
    if choice == 0 || choice > candidates.len() {
        return Err(Error::Message(format!("no manifest {choice}")));
    }
    Ok(candidates[choice - 1].clone())
}

/// `vaulted-agent edit-manifest [name]` — open a manifest, then check it.
///
/// The point is not that `$EDITOR /etc/vaulted-agent/manifests/x` is long to
/// type. It is that the launcher knows where its manifests are, which ones a
/// harness actually reads, and what makes one fail at launch — and none of that
/// is available to a bare editor.
pub fn cmd_edit_manifest(paths: &Paths, args: &[String]) -> Result<()> {
    let mut wanted: Option<String> = None;
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => {
                println!(
                    "usage: vaulted-agent edit-manifest [manifest]\n\
                     Open a manifest in $EDITOR (vi by default) and check it on save.\n\
                     With no argument, lists the manifests and asks which to edit.\n\
                     Uses sudoedit when the file is not yours to write."
                );
                return Ok(());
            }
            s if s.starts_with('-') => {
                return Err(Error::Message(format!(
                    "edit-manifest: unknown option '{s}'"
                )));
            }
            s => {
                if wanted.is_some() {
                    return Err(Error::Message(format!(
                        "edit-manifest: extra argument '{s}'"
                    )));
                }
                wanted = Some(s.to_string());
            }
        }
    }

    // The check on save judges the file against the Backends that read it,
    // which takes the machine default Backend: a defaults.conf that does not
    // load stops here, before the editor opens.
    Defaults::load(paths)?;

    let path = match wanted {
        Some(name) => {
            if name.contains('/') || name == ".." || name == "." {
                return Err(Error::Message(
                    "edit-manifest: give a manifest name, not a path".into(),
                ));
            }
            let path = paths.manifest_dir.join(&name);
            if !path.is_file() {
                // A name that does not exist is far more often a typo than a
                // new file, so creating one is never the silent default.
                return Err(Error::Message(format!(
                    "no manifest named '{name}' in {}. Run `vaulted-agent edit-manifest` \
                     with no argument to see what is there.",
                    paths.manifest_dir.display()
                )));
            }
            path
        }
        None => {
            if !can_prompt_user() {
                return Err(Error::Message(
                    "edit-manifest: no terminal to choose from — name the manifest".into(),
                ));
            }
            pick_manifest(paths)?
        }
    };

    // Judge the file as everything that reads it would. The file is saved
    // before we look, so an Inventory that will not load degrades to the
    // Backend-blind check rather than refusing the edit.
    let backends = Inventory::load(paths)
        .map(|inv| inv.backends_reading(&path))
        .unwrap_or_default();

    loop {
        open_in_editor(&path)?;
        let text = fs::read_to_string(&path).map_err(|e| Error::Io {
            path: path.clone(),
            source: e,
        })?;
        let checked = crate::validate::check_manifest(&text, &backends);
        let problems = checked.problems;
        if problems.is_empty() {
            let skipped = if backends.is_empty() {
                " Backend checks skipped: no Harness reads this file."
            } else {
                ""
            };
            println!(
                "{}: {} variable(s), no problems found.{skipped}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                checked.entries.len()
            );
            return Ok(());
        }

        eprintln!("\n{} problem(s) in {}:", problems.len(), path.display());
        for p in &problems {
            eprintln!("  {p}");
        }
        // Saved already — sudoedit wrote it back before we could look. Offer the
        // editor again rather than pretending the file is still clean.
        if !can_prompt_user() {
            return Err(Error::Message(
                "manifest saved with problems; re-run edit-manifest to fix".into(),
            ));
        }
        eprint!("\nEdit again? [Y/n]: ");
        let _ = io::stderr().flush();
        let answer = read_tty_line()?;
        if matches!(answer.trim().to_ascii_lowercase().as_str(), "n" | "no") {
            if problems.iter().any(|p| p.blocks) {
                eprintln!(
                    "Left as saved. A launch using this manifest will fail until it is fixed."
                );
            } else {
                eprintln!("Left as saved.");
            }
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_lists_short_sets_whole_and_truncates_long_ones() {
        let three: Vec<String> = ["A", "B", "C"].iter().map(|s| s.to_string()).collect();
        assert_eq!(sample(&three), "A, B, C");
        assert_eq!(sample(&[]), "");

        // At the boundary nothing is hidden, so no misleading "and 0 more".
        let eight: Vec<String> = (0..8).map(|i| format!("V{i}")).collect();
        assert_eq!(sample(&eight), eight.join(", "));

        let nine: Vec<String> = (0..9).map(|i| format!("V{i}")).collect();
        let out = sample(&nine);
        assert!(out.ends_with("and 1 more"), "{out}");
        assert!(!out.contains("V8"), "{out}");
    }

    #[test]
    fn parse_auth_mode_choice_accepts_aliases() {
        assert_eq!(
            parse_auth_mode_choice("1", AuthMode::Prompt),
            AuthMode::File
        );
        assert_eq!(
            parse_auth_mode_choice("file", AuthMode::Prompt),
            AuthMode::File
        );
        assert_eq!(
            parse_auth_mode_choice("disk", AuthMode::Prompt),
            AuthMode::File
        );
        assert_eq!(
            parse_auth_mode_choice("2", AuthMode::File),
            AuthMode::Prompt
        );
        assert_eq!(
            parse_auth_mode_choice("prompt", AuthMode::File),
            AuthMode::Prompt
        );
        assert_eq!(
            parse_auth_mode_choice("p", AuthMode::File),
            AuthMode::Prompt
        );
    }

    #[test]
    fn run_is_refused_once_a_service_user_exists() {
        let msg = run_refusal(Some("conductor"), false).expect("should refuse");
        assert!(msg.contains("conductor"));
        assert!(msg.contains("allow_run"));
    }

    #[test]
    fn run_stays_available_on_a_single_operator_machine() {
        // No service account, so `run` grants nothing the caller lacks.
        assert_eq!(run_refusal(None, false), None);
        assert_eq!(run_refusal(None, true), None);
    }

    #[test]
    fn allow_run_restores_it_explicitly() {
        assert_eq!(run_refusal(Some("conductor"), true), None);
    }

    #[test]
    fn parse_auth_mode_choice_empty_or_unknown_keeps_current() {
        assert_eq!(parse_auth_mode_choice("", AuthMode::File), AuthMode::File);
        assert_eq!(
            parse_auth_mode_choice("", AuthMode::Prompt),
            AuthMode::Prompt
        );
        assert_eq!(
            parse_auth_mode_choice("nope", AuthMode::Prompt),
            AuthMode::Prompt
        );
        assert_eq!(
            parse_auth_mode_choice("  file  ", AuthMode::Prompt),
            AuthMode::File
        );
    }

    #[test]
    fn agent_without_caller_still_warns_when_no_service_user() {
        let caller = CallerContext::default();
        assert_eq!(
            workdir_warning(None, Some("/srv/x"), "claude", &caller).as_deref(),
            Some("agent harness without workdir=caller")
        );
        assert_eq!(
            workdir_warning(None, None, "claude", &caller).as_deref(),
            Some("agent harness without workdir=caller")
        );
        assert_eq!(
            workdir_warning(None, Some("caller"), "claude", &caller),
            None
        );
    }

    #[test]
    fn non_agent_harness_is_not_nagged_about_workdir() {
        let caller = CallerContext::default();
        assert_eq!(
            workdir_warning(None, Some("/srv/x"), "backup", &caller),
            None
        );
    }
}
