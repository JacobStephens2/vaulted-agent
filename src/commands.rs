//! Management subcommands: secrets, doctor, setup, refresh, auth-mode, uninstall, pick, run.

use std::cell::RefCell;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::auth::{self, TokenKind};
use crate::backend;
use crate::config::{
    env_blind_agent_reason, list_harness_names, load_allow_run, load_auth_mode,
    load_default_backend, load_service_user, parse_dotenv_keys, AuthMode, Backend, Harness, Paths,
};
use crate::error::{Error, Result};
use crate::launch::{self, auth_mode_from_env_or_config, force_prompt_from_env, LaunchOpts};
use crate::refs;
use crate::secret::ManagerToken;
use crate::validate::validate_manifest_file;

pub fn default_backend(paths: &Paths) -> Backend {
    load_default_backend(paths)
}

fn force_prompt() -> bool {
    force_prompt_from_env()
}

fn auth_mode(paths: &Paths) -> AuthMode {
    auth_mode_from_env_or_config(paths)
}

fn service_user_for_token(paths: &Paths) -> Option<String> {
    load_service_user(paths)
}

fn load_bws(paths: &Paths) -> Result<ManagerToken> {
    load_bws_with(paths, auth_mode(paths))
}

fn load_bws_with(paths: &Paths, mode: AuthMode) -> Result<ManagerToken> {
    auth::load_manager_token(paths, mode, TokenKind::Bws, force_prompt())
}

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
                let mode = prompt_auth_mode_choice(load_auth_mode(paths))?;
                write_auth_mode(paths, mode)?;
                println!("auth_mode={}", mode.as_str());
            } else {
                println!("auth_mode={}", load_auth_mode(paths).as_str());
            }
            Ok(())
        }
        Some("show") | Some("") => {
            let mode = load_auth_mode(paths);
            println!("auth_mode={}", mode.as_str());
            Ok(())
        }
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
fn ensure_auth_mode_for_setup(paths: &Paths) -> Result<AuthMode> {
    if !can_prompt_user() {
        return Ok(auth_mode(paths));
    }
    let current = load_auth_mode(paths);
    let mode = prompt_auth_mode_choice(current)?;
    write_auth_mode(paths, mode)?;
    Ok(mode)
}

fn write_auth_mode(paths: &Paths, mode: AuthMode) -> Result<()> {
    write_defaults_key(paths, "auth_mode", Some(mode.as_str()))
}

/// Set or remove a key in defaults.conf, preserving all other lines.
fn write_defaults_key(paths: &Paths, key: &str, value: Option<&str>) -> Result<()> {
    let existing = fs::read_to_string(&paths.defaults_file).unwrap_or_default();
    let mut lines: Vec<String> = Vec::new();
    let mut saw = false;
    if existing.trim().is_empty() {
        lines.push("# Machine-wide launcher defaults.".into());
    }
    for raw in existing.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            lines.push(raw.to_string());
            continue;
        }
        if let Some((k, _)) = line.split_once('=') {
            if k.trim() == key {
                if let Some(v) = value {
                    lines.push(format!("{key} = {v}"));
                    saw = true;
                }
                // value None → drop the key
                continue;
            }
        }
        lines.push(raw.to_string());
    }
    if !saw {
        if let Some(v) = value {
            lines.push(format!("{key} = {v}"));
        }
    }
    let body = lines.join("\n") + "\n";
    if let Some(parent) = paths.defaults_file.parent() {
        fs::create_dir_all(parent).map_err(|e| Error::config_write(parent, e))?;
    }
    fs::write(&paths.defaults_file, body)
        .map_err(|e| Error::config_write(&paths.defaults_file, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(&paths.defaults_file) {
            let mut p = meta.permissions();
            p.set_mode(0o644);
            let _ = fs::set_permissions(&paths.defaults_file, p);
        }
    }
    Ok(())
}

/// Interactive: who agents run as (defaults to "you" = no service_user).
/// Non-interactive: leave defaults alone.
fn ensure_service_user_for_setup(paths: &Paths) -> Result<Option<String>> {
    if !can_prompt_user() {
        return Ok(load_service_user(paths));
    }
    let me = crate::privilege::current_user();
    let me_label = if me.is_empty() {
        "you".to_string()
    } else {
        me.clone()
    };
    let current = load_service_user(paths);
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
            write_defaults_key(paths, "service_user", None)?;
            println!("service_user: (unset — agents run as the invoking user)");
            Ok(None)
        }
        "2" | "service" | "svc" => {
            eprint!("service account name: ");
            let _ = io::stderr().flush();
            let name = read_tty_line()?.trim().to_string();
            if name.is_empty() {
                eprintln!("  empty name; leaving service_user unchanged");
                return Ok(load_service_user(paths));
            }
            write_defaults_key(paths, "service_user", Some(&name))?;
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
            Ok(load_service_user(paths))
        }
    }
}

/// Set `workdir = …` on every harness conf, inserting if missing.
fn set_harnesses_workdir(paths: &Paths, workdir: &str) -> Result<usize> {
    let dir = &paths.harness_dir;
    if !dir.is_dir() {
        return Ok(0);
    }
    let mut n = 0usize;
    for ent in fs::read_dir(dir).map_err(|e| Error::Io {
        path: dir.clone(),
        source: e,
    })? {
        let ent = ent.map_err(|e| Error::Io {
            path: dir.clone(),
            source: e,
        })?;
        let path = ent.path();
        if path.extension().and_then(|s| s.to_str()) != Some("conf") {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|e| Error::Io {
            path: path.clone(),
            source: e,
        })?;
        let mut lines: Vec<String> = Vec::new();
        let mut saw = false;
        for raw in text.lines() {
            let trimmed = raw.trim();
            if let Some((k, _)) = trimmed.split_once('=') {
                if k.trim() == "workdir" {
                    lines.push(format!("workdir  = {workdir}"));
                    saw = true;
                    continue;
                }
            }
            lines.push(raw.to_string());
        }
        if !saw {
            lines.push(format!("workdir  = {workdir}"));
        }
        let body = lines.join("\n") + "\n";
        fs::write(&path, body).map_err(|e| Error::config_write(&path, e))?;
        n += 1;
    }
    Ok(n)
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
            eprintln!(
                "  NOTE: service_user={svc} with workdir=caller needs {svc} to traverse your cwd.\n  \
                 If launches fail at exec from a 0700 home:\n    \
                 setfacl -m u:{svc}:x ~   # traverse only — does not allow listing\n  \
                 (or pick a fixed workdir {svc} can enter)"
            );
        }
    }
    Ok(())
}

/// Resolve every reference in a manifest, exactly as a launch would.
///
/// `validate` used to check reference *shape* and stop. A reference can be
/// perfectly well-formed and name an item that no longer exists — after a
/// rename in the vault, say — and the check passed while every launch died.
/// CONTEXT.md calls this command the pre-flight gate that must not fail open,
/// so it has to ask the vault.
///
/// The resolution goes through `backend::resolve`, the same call a launch
/// makes, so this agrees with a launch by construction rather than by a second
/// implementation that can drift from it.
///
/// The resolved values are counted and dropped. They are never printed, logged,
/// or returned: the point is whether they resolve, and a validate command that
/// wrote secrets to a terminal would be a worse bug than the one it fixes.
fn resolve_for_validation(paths: &Paths, backend: Backend, manifest: &Path) -> Result<usize> {
    let mode = auth_mode(paths);
    let token = match backend {
        Backend::Bitwarden => Some(auth::load_manager_token(
            paths,
            mode,
            TokenKind::Bws,
            force_prompt(),
        )?),
        Backend::OnePassword => Some(auth::load_manager_token(
            paths,
            mode,
            TokenKind::Op,
            force_prompt(),
        )?),
        Backend::Pass | Backend::Sops | Backend::Plainfile => None,
    };
    let resolved = backend::resolve(backend, manifest, paths, token.as_ref())?;
    drop(token);
    let n = resolved.len();
    drop(resolved);
    Ok(n)
}

/// Shape-check a manifest, then either stop (offline) or resolve as a launch would.
///
/// Returns `None` for offline (syntax only) and `Some(n)` for the number of
/// variables `backend::resolve` returned. Values themselves are never kept.
fn validate_manifest_against_vault(
    paths: &Paths,
    backend: Backend,
    manifest: &Path,
    offline: bool,
) -> Result<Option<usize>> {
    validate_manifest_file(manifest, backend)?;
    if offline {
        return Ok(None);
    }
    resolve_for_validation(paths, backend, manifest).map(Some)
}

fn format_validate_ok(resolved: Option<usize>) -> String {
    match resolved {
        None => "ok (syntax only; vault not probed)".to_string(),
        Some(n) => format!("ok ({n} variable(s) resolved)"),
    }
}

fn print_validate_blame(manifest: &Path, error: &str, to_stdout: bool) {
    let blamed = crate::validate::blame_manifest_lines(manifest, error);
    if blamed.is_empty() {
        return;
    }
    if to_stdout {
        for b in blamed {
            println!("    {b}");
        }
    } else {
        eprintln!("{}: could not resolve:", manifest.display());
        for b in &blamed {
            eprintln!("    {b}");
        }
    }
}

pub fn cmd_secrets(paths: &Paths, args: &[String]) -> Result<()> {
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
        "refresh" => cmd_refresh(paths, &args[1..]),
        "list" => {
            let token = load_bws(paths)?;
            let rows = backend::bws_list_secrets(&token)?;
            drop(token);
            println!("Secrets visible to this token:");
            for (i, (id, key, proj)) in rows.iter().enumerate() {
                if proj.is_empty() {
                    println!("  {:2}) {:36}  {}", i + 1, id, key);
                } else {
                    println!("  {:2}) {:36}  {}  (project: {})", i + 1, id, key, proj);
                }
            }
            Ok(())
        }
        "get" => {
            let r = args
                .get(1)
                .ok_or_else(|| Error::Message("usage: vaulted-agent secrets get <ref>".into()))?;
            let token = load_bws(paths)?;
            let id = backend::bws_resolve_ref(&token, r)?;
            let value = backend::bws_secret_value(&token, &id)?;
            drop(token);
            println!("{value}");
            Ok(())
        }
        "which" => {
            println!("Harness → variables (names only; values never printed)\n");
            let names = list_harness_names(paths)?;
            let be_default = default_backend(paths);
            for name in names {
                let h = Harness::load(paths, &name)?;
                let be = h.backend.unwrap_or(be_default);
                let man = &h.manifest;
                println!("{name}  (backend={be} manifest={man})");
                let man_path = h.resolve_manifest_path(paths);
                if man_path.is_file() {
                    if let Ok(text) = fs::read_to_string(&man_path) {
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
            let target = positional.first().copied();
            match target {
                None => {
                    // Everything this machine reads, not everything it
                    // launches. The manifest an operator forgets is exactly
                    // the one nothing launches from, and a gate that walks
                    // launch profiles alone reports it green while the units
                    // that read it are down.
                    let be_default = default_backend(paths);
                    let mut targets: Vec<(String, Backend, PathBuf)> = Vec::new();
                    for name in list_harness_names(paths)? {
                        let h = Harness::load(paths, &name)?;
                        let man_path = h.resolve_manifest_path(paths);
                        // The manifest is named on every line because several
                        // harnesses commonly share one file: six green
                        // harnesses can be one file checked six times, and the
                        // operator cannot see which files were covered
                        // otherwise.
                        let label = format!("{name} ({})", man_path.display());
                        targets.push((label, h.backend.unwrap_or(be_default), man_path));
                    }
                    // Fails closed on an entry it cannot read: an unusable
                    // line means a file the operator believes is checked is
                    // not being checked.
                    for extra in crate::config::load_extra_manifests(paths)? {
                        let label = extra.path.display().to_string();
                        targets.push((label, extra.backend.unwrap_or(be_default), extra.path));
                    }

                    let mut err = false;
                    for (label, be, man_path) in targets {
                        print!("{label}: ");
                        match validate_manifest_against_vault(paths, be, &man_path, offline) {
                            Ok(n) => println!("{}", format_validate_ok(n)),
                            Err(e) => {
                                println!("FAIL ({e})");
                                print_validate_blame(&man_path, &format!("{e}"), true);
                                err = true;
                            }
                        }
                    }
                    if err {
                        Err(Error::Message("validation failed".into()))
                    } else {
                        Ok(())
                    }
                }
                Some(man) => {
                    let conf = paths.harness_dir.join(format!("{man}.conf"));
                    let (man_path, be) = if conf.is_file() {
                        let h = Harness::load(paths, man)?;
                        let be = h.backend.unwrap_or_else(|| default_backend(paths));
                        (h.resolve_manifest_path(paths), be)
                    } else {
                        let p = Path::new(man);
                        let man_path = if p.is_absolute() {
                            p.to_path_buf()
                        } else {
                            paths.manifest_dir.join(p)
                        };
                        // positional, not args[2]: --offline may sit anywhere.
                        let be = match positional.get(1) {
                            Some(s) => s.parse()?,
                            None => default_backend(paths),
                        };
                        (man_path, be)
                    };
                    match validate_manifest_against_vault(paths, be, &man_path, offline) {
                        Ok(n) => {
                            println!("{}: {}", man_path.display(), format_validate_ok(n));
                            Ok(())
                        }
                        Err(e) => {
                            print_validate_blame(&man_path, &format!("{e}"), false);
                            Err(e)
                        }
                    }
                }
            }
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
/// `workdir=caller` + `service_user` used to always warn from config shape
/// alone (issue #58). That cried wolf once homes had `setfacl …:x`. Doctor
/// already runs as the service account, so probe real paths and warn only when
/// traversal actually fails — same primitive as the launch preflight (#56).
fn workdir_warning(
    service_user: Option<&str>,
    workdir: Option<&str>,
    harness: &str,
) -> Option<String> {
    let is_agent = matches!(harness, "claude" | "codex" | "grok" | "kimi" | "agy");
    let wd_is_caller = workdir == Some("caller");
    match (service_user, wd_is_caller) {
        (Some(svc), true) => {
            let failed: Vec<_> = launch::caller_probe_paths()
                .into_iter()
                .filter(|p| launch::path_is_traversable(p).is_err())
                .collect();
            if failed.is_empty() {
                return None;
            }
            let paths = failed
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let example = failed[0].display();
            Some(format!(
                "workdir=caller with service_user={svc}, and {svc} cannot enter {paths} \
                 (Permission denied). Launching from there fails at exec. \
                 Fix: setfacl -m u:{svc}:x {example}   # traverse only — does not allow listing \
                 (or set an absolute workdir {svc} can enter)"
            ))
        }
        (Some(svc), false) => {
            // Absolute / fixed workdir: probe the resolved path when we can.
            let raw = workdir.filter(|s| !s.is_empty())?;
            if raw == "caller" {
                return None;
            }
            let path = {
                let s = if let Some(rest) = raw.strip_prefix("$HOME") {
                    format!("{}{rest}", std::env::var("HOME").unwrap_or_default())
                } else if let Some(rest) = raw.strip_prefix("${HOME}") {
                    format!("{}{rest}", std::env::var("HOME").unwrap_or_default())
                } else {
                    raw.to_string()
                };
                std::path::PathBuf::from(s)
            };
            if launch::path_is_traversable(&path).is_ok() {
                return None;
            }
            Some(format!(
                "workdir={raw} with service_user={svc}, and {svc} cannot enter {} \
                 (Permission denied). Fix: setfacl -m u:{svc}:x {} or pick a path {svc} can enter",
                path.display(),
                path.display()
            ))
        }
        (None, false) if is_agent => Some("agent harness without workdir=caller".to_string()),
        _ => None,
    }
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
    println!("auth_mode: {}", load_auth_mode(paths).as_str());
    println!("default_backend: {}", default_backend(paths));

    // Nearly every check below is a filesystem question -- is op.env readable,
    // is the manifest readable, is the harness bin executable -- and the answer
    // depends on who is asking. Launches run as service_user, so a report
    // produced as the calling user can describe an account that never runs an
    // agent: on the host this was found, doctor called op.env "missing" while
    // the launcher read it without trouble. main re-execs doctor through the
    // same hop a launch uses; name the account that answered so the report is
    // never read against the wrong one.
    let running_as = crate::privilege::current_user();
    let service_user = load_service_user(paths);
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
    let be_default = default_backend(paths);
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
                            .filter(|(_, v)| {
                                v.starts_with("op://") && !refs::op_reference_is_parseable(v)
                            })
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
                            .filter(|(k, v)| {
                                v.starts_with("op://")
                                    && v.split('/').any(refs::op_section_is_default)
                                    && refs::name_folds_default_section(k)
                            })
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
        if let Some(msg) = workdir_warning(service_user.as_deref(), h.workdir.as_deref(), name) {
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

pub fn cmd_refresh(paths: &Paths, args: &[String]) -> Result<()> {
    let mut man_path: Option<String> = None;
    let mut take_all = false;
    let mut mode: Option<&str> = None;
    let mut backend_arg: Option<String> = None;
    let mut exclude: Vec<String> = Vec::new();
    let mut prune = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!(
                    "usage: vaulted-agent refresh [manifest] [--all] [--merge|--replace] [--prune] [--backend NAME] [--exclude PATTERN]\n\
                     Update a refs file after adding secrets in the vault.\n\
                     Backend defaults to the one your harnesses use (bitwarden or onepassword).\n\
                     bitwarden   : pick from the secrets the token can see\n\
                     onepassword : pick items from the vault; each item's fields become refs\n\
                     --exclude   : a VAR name refresh must not map ('*' and '?' allowed).\n\
                     \x20             Repeatable, recorded in the manifest, honoured by later runs.\n\
                     --prune     : fix what the scan found — remove dangling refs\n\
                     \x20             (matching nothing the token can see) and, on\n\
                     \x20             bitwarden, repair renamed ones keeping the variable\n\
                     \x20             name. Reported either way.\n\
                     Secret values are never stored — only references."
                );
                return Ok(());
            }
            "--all" | "-a" => take_all = true,
            "--prune" => prune = true,
            "-x" | "--exclude" => {
                i += 1;
                exclude.push(
                    args.get(i)
                        .ok_or_else(|| Error::Message("refresh: --exclude needs a pattern".into()))?
                        .clone(),
                );
            }
            s if s.starts_with("--exclude=") => {
                exclude.push(s["--exclude=".len()..].to_string());
            }
            "-b" | "--backend" => {
                i += 1;
                backend_arg = Some(
                    args.get(i)
                        .ok_or_else(|| Error::Message("refresh: --backend needs a name".into()))?
                        .clone(),
                );
            }
            s if s.starts_with("--backend=") => {
                backend_arg = Some(s["--backend=".len()..].to_string());
            }
            "--merge" => mode = Some("merge"),
            "--replace" | "--rewrite" => mode = Some("replace"),
            "-m" | "--manifest" => {
                i += 1;
                man_path = Some(
                    args.get(i)
                        .ok_or_else(|| Error::Message("refresh: -m needs a path".into()))?
                        .clone(),
                );
            }
            s if s.starts_with("--manifest=") => {
                man_path = Some(s["--manifest=".len()..].to_string());
            }
            s if s.starts_with('-') => {
                return Err(Error::Message(format!("refresh: unknown option '{s}'")));
            }
            s => {
                if man_path.is_some() {
                    return Err(Error::Message(format!("refresh: extra argument '{s}'")));
                }
                man_path = Some(s.to_string());
            }
        }
        i += 1;
    }

    println!("vaulted-agent refresh\n");

    // Which vault are we refreshing against? Explicit flag wins; otherwise use
    // the backend the harnesses actually use. Before this, refresh always went
    // to Bitwarden and a 1Password install failed with a confusing "needs
    // bws.env" even when default_backend was onepassword.
    let be = match &backend_arg {
        Some(name) => Backend::parse_loose(name)
            .ok_or_else(|| Error::Message(format!("refresh: unknown backend '{name}'")))?,
        None => refresh_backend(paths),
    };

    match be {
        Backend::Bitwarden => {
            if !exclude.is_empty() {
                return Err(Error::Message(
                    "refresh: --exclude applies to the onepassword backend only".into(),
                ));
            }
            refresh_bitwarden(paths, man_path, take_all, mode, prune)
        }
        Backend::OnePassword => {
            refresh_onepassword(paths, man_path, take_all, mode, &exclude, prune)
        }
        other => Err(Error::Message(format!(
            "refresh does not apply to backend '{}'. It builds refs files, which only \
             bitwarden and onepassword use; {} manifests are edited directly.",
            other.as_str(),
            other.as_str()
        ))),
    }
}

/// Backend for a bare `refresh`: whichever refs-using backend the harnesses
/// resolve to.
///
/// Falls back to Bitwarden, NOT to `default_backend`, when there is no positive
/// signal. `refresh` meant Bitwarden for its whole history, while
/// `load_default_backend` returns OnePassword when nothing is configured - so
/// deferring to it here would silently retarget `refresh` on installs that have
/// no harnesses and no defaults.conf. Ties break the same way.
fn refresh_backend(paths: &Paths) -> Backend {
    let be_default = default_backend(paths);
    let mut seen: Vec<Backend> = Vec::new();
    if let Ok(names) = list_harness_names(paths) {
        for name in names {
            if let Ok(h) = Harness::load(paths, &name) {
                let be = h.backend.unwrap_or(be_default);
                if matches!(be, Backend::Bitwarden | Backend::OnePassword) && !seen.contains(&be) {
                    seen.push(be);
                }
            }
        }
    }
    match seen.as_slice() {
        [one] => *one,
        _ => Backend::Bitwarden,
    }
}

fn refresh_bitwarden(
    paths: &Paths,
    man_path: Option<String>,
    take_all: bool,
    mode: Option<&str>,
    prune: bool,
) -> Result<()> {
    let token = load_bws(paths)?;
    let secrets = backend::bws_list_secrets(&token)?;
    drop(token);
    if secrets.is_empty() {
        return Err(Error::Message(
            "No secrets visible to this token yet.".into(),
        ));
    }

    let path = match man_path {
        Some(man) => {
            if Path::new(&man).is_absolute() {
                PathBuf::from(&man)
            } else {
                paths.manifest_dir.join(&man)
            }
        }
        None => default_bitwarden_manifest(paths)?,
    };

    let mode = mode.unwrap_or(if path.is_file() { "merge" } else { "replace" });

    ensure_manifest_writable(&path)?;

    report_and_fix_refs(paths, &path, &secrets, mode == "replace", prune)?;

    let indices = if take_all {
        None // all
    } else if !std::io::IsTerminal::is_terminal(&io::stdin()) {
        // non-interactive without --all: all for replace, or merge all new
        None
    } else {
        // print list and ask
        println!("Secrets:");
        for (i, (id, key, proj)) in secrets.iter().enumerate() {
            println!("  {:2}) {}  {}  {}", i + 1, id, key, proj);
        }
        eprint!("Secrets to include [all]: ");
        let _ = io::stderr().flush();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_err() || line.trim().is_empty() {
            None
        } else {
            Some(refs::parse_index_list(line.trim(), secrets.len())?)
        }
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }

    match mode {
        "replace" => {
            refs::write_refs_replace(&path, &secrets, indices.as_deref(), "vaulted-agent refresh")?;
            println!("Wrote refs file (replace): {}", path.display());
        }
        _ => {
            let merge = refs::write_refs_merge(
                &path,
                &secrets,
                indices.as_deref(),
                "vaulted-agent refresh",
            )?;
            if merge.recovered > 0 {
                println!(
                    "Split {} mapping(s) that were glued onto one line (va 0.3.0 refresh): {}",
                    merge.recovered,
                    path.display()
                );
            }
            if merge.added == 0 {
                if merge.recovered == 0 {
                    println!("No new mappings to add: {}", path.display());
                }
            } else {
                println!(
                    "Updated refs file (+{} mapping(s)): {}",
                    merge.added,
                    path.display()
                );
            }
        }
    }
    Ok(())
}

/// Report what the scan found in a Bitwarden manifest, and act on it when the
/// operator has said to: dangling refs removed, renamed refs repaired.
///
/// Reporting happens on every run; changing the file never does on its own.
/// Both kinds of change ride the one `--prune` / confirmation gate, because
/// they are the same intent — fix this manifest — and a run that repairs one
/// line while leaving another broken would be harder to reason about than
/// either alone.
///
/// Exit status is unaffected either way — `refresh` is not a gate, `secrets
/// validate` is (invariant 5), and it already fails on a dangling ref.
fn report_and_fix_refs(
    paths: &Paths,
    path: &Path,
    secrets: &[(String, String, String)],
    mode_is_replace: bool,
    prune: bool,
) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }
    let text = fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let scan = refs::scan_bitwarden_refs(&text, secrets);
    // `--replace` regenerates from the listing instead of repairing, so the
    // report must not promise a repair it will not perform.
    print_ref_report(paths, path, &scan, !mode_is_replace);

    apply_ref_edits(path, &scan, mode_is_replace, prune)
}

/// Decide what to do about a scan's pending edits, then do it.
///
/// Shared by both backends: the gate (`--prune`, an interactive yes, or report
/// and leave) and the surgical write are the same act whatever made a line
/// dangling. Only the classification differs.
fn apply_ref_edits(
    path: &Path,
    scan: &[refs::ScannedRef],
    mode_is_replace: bool,
    prune: bool,
) -> Result<()> {
    let edits = refs::plan_ref_edits(scan);
    if edits.is_empty() {
        return Ok(());
    }
    let what = refs::describe_ref_edits(&edits);

    let apply = match refs::ref_fix_choice(
        edits.len(),
        prune,
        mode_is_replace,
        std::io::IsTerminal::is_terminal(&io::stdin()),
    ) {
        refs::RefFixChoice::NothingPending => return Ok(()),
        refs::RefFixChoice::ReplaceRegenerates => {
            println!("  --replace rewrites the file, so these go with it.\n");
            return Ok(());
        }
        refs::RefFixChoice::Report => {
            println!("  Left in place. Re-run with --prune to apply.\n");
            return Ok(());
        }
        refs::RefFixChoice::Apply => true,
        refs::RefFixChoice::Ask => {
            eprint!("{what}? [y/N]: ");
            let _ = io::stderr().flush();
            let mut line = String::new();
            io::stdin().read_line(&mut line).is_ok()
                && matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
        }
    };
    if !apply {
        println!("  Left in place.\n");
        return Ok(());
    }

    let applied = refs::edit_refs_lines(path, &edits)?;
    // Verbatim, because scrollback is the recovery path — refresh writes no
    // backup file into the root-owned manifest directory.
    println!("{}:", refs::describe_ref_edits(&applied));
    for (line, edit) in &applied {
        match edit {
            refs::RefEdit::Remove => println!("  - {line}"),
            refs::RefEdit::Rewrite(new) => {
                println!("  - {line}");
                println!("  + {new}");
            }
        }
    }
    println!();
    Ok(())
}

/// Report what the scan found in a 1Password manifest, and act on it under the
/// same gate as Bitwarden.
///
/// Judged against what this run already fetched: the item listing, plus the
/// fields of the items it expanded. Nothing here costs an extra `op` call
/// (ADR-0005).
fn report_and_fix_op_refs(
    paths: &Paths,
    path: &Path,
    world: &refs::OpWorld,
    exclusions: &[String],
    mode_is_replace: bool,
    prune: bool,
) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }
    let text = fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let scan = refs::scan_op_refs(&text, world);
    // No repair to promise: an `op://` line records no source id, so a renamed
    // item is indistinguishable from a deleted one (ADR-0005).
    print_ref_report(paths, path, &scan, false);
    print_excluded_report(path, &scan, exclusions);
    apply_ref_edits(path, &scan, mode_is_replace, prune)
}

/// Mappings that resolve but whose variable name an exclusion now covers.
///
/// Listed, never removed. An exclusion says what `refresh` may **add**; these
/// lines still work, and prune removes only what does not resolve (ADR-0005).
/// Naming the file and the fix keeps the operator from having to guess why a
/// pattern did not make an existing variable go away.
fn print_excluded_report(path: &Path, scan: &[refs::ScannedRef], exclusions: &[String]) {
    let excluded = refs::excluded_refs(scan, exclusions);
    if excluded.is_empty() {
        return;
    }
    print_ref_group(
        &format!(
            "Mapped but excluded in {} ({} matching a recorded exclusion — kept, because \
             they still resolve):",
            path.display(),
            excluded.len()
        ),
        &excluded,
        Some("Remove one by hand if you meant it to go: vaulted-agent edit-manifest"),
    );
    println!();
}

/// What the scan found, said before anything is decided about it.
fn print_ref_report(paths: &Paths, path: &Path, scan: &[refs::ScannedRef], will_repair: bool) {
    let dangling = refs::dangling_refs(scan);
    let renamed = refs::renamed_refs(scan);
    if !renamed.is_empty() {
        // Named as a rename because the recorded UUID proves it is one. The old
        // guess — "one went dangling, one appeared" — was rejected in #80, and
        // a wrong label is worse than none.
        println!(
            "Renamed secrets in {} ({} mapping(s) whose key changed in the vault):",
            path.display(),
            renamed.len()
        );
        for r in &renamed {
            println!("    {}", r.line);
            match (will_repair, r.repaired_line(), r.renamed_to.as_deref()) {
                (true, Some(new), _) => println!("      -> {new}"),
                (false, _, Some(key)) => println!("      now named {key} in the vault"),
                _ => {}
            }
        }
        // A repair keeps the variable name, so an `alias =` reading it keeps
        // working — that is why it keeps the name. `--replace` gives no such
        // promise: it remaps the secret under its new key and the old variable
        // goes. That is the one piece of cleanup refresh cannot do itself
        // (ADR-0003), so it has to be said out loud.
        if !will_repair {
            for warning in alias_warnings(
                paths,
                &renamed,
                "a mapping whose secret was renamed in the vault. --replace remaps it \
                 under the new key, so the alias will fail that launch closed",
            ) {
                println!("  ! {warning}");
            }
        }
    }
    if !dangling.is_empty() {
        print_ref_group(
            &format!(
                "Dangling refs in {} ({} matching nothing this token can see):",
                path.display(),
                dangling.len()
            ),
            &dangling,
            None,
        );
        for warning in alias_warnings(
            paths,
            &dangling,
            "a dangling mapping. Pruning it leaves the alias to fail that launch closed",
        ) {
            println!("  ! {warning}");
        }
    }
    let unchecked = refs::unchecked_refs(scan);
    if !unchecked.is_empty() {
        // Said out loud rather than passed over, because silence here would
        // read as "these are fine". They are simply unexamined: the item is
        // there, and what it costs to look inside is the reason refresh asks
        // which items to expand (ADR-0005).
        print_ref_group(
            &format!(
                "Refs this run did not check ({} — into items whose fields it did not read):",
                unchecked.len()
            ),
            &unchecked,
            Some(
                "Items you did not select, or that could not be read this run. \
                 `--all` expands every item.",
            ),
        );
        println!();
    }
    let unjudged = refs::unjudged_refs(scan);
    if !unjudged.is_empty() {
        // Reported separately and never pruned: prune removes what does not
        // resolve, and these have not been shown not to.
        print_ref_group(
            &format!(
                "Refs refresh cannot judge ({} — shape is `vaulted-agent secrets validate`'s job):",
                unjudged.len()
            ),
            &unjudged,
            None,
        );
        println!();
    }
}

/// One heading, the lines under it verbatim, and an optional closing note.
///
/// Every group the report prints has this shape, and they are read together —
/// an operator comparing "dangling" against "cannot judge" is comparing two
/// lists of file lines. Printing them through one function is what keeps them
/// looking like one report.
fn print_ref_group(heading: &str, refs: &[&refs::ScannedRef], note: Option<&str>) {
    println!("{heading}");
    for r in refs {
        println!("    {}", r.line);
    }
    if let Some(n) = note {
        println!("  {n}");
    }
}

/// Harness aliases that name a variable about to disappear.
///
/// A warning, never a block: refresh changes the manifest, and the `alias =`
/// line naming it is in a harness file refresh does not own. The caller supplies
/// `consequence` because the two ways a variable can vanish — pruned, or
/// regenerated away by `--replace` — need different advice.
fn alias_warnings(
    paths: &Paths,
    vanishing: &[&refs::ScannedRef],
    consequence: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(names) = list_harness_names(paths) else {
        return out;
    };
    for name in names {
        let Ok(h) = Harness::load(paths, &name) else {
            continue;
        };
        for (target, source) in &h.aliases {
            if vanishing.iter().any(|r| r.var == *source) {
                out.push(format!(
                    "harness {name}: alias = {target} = {source} reads {consequence} \
                     — edit the harness too."
                ));
            }
        }
    }
    out
}

/// Fail now if the refs file cannot be written later.
///
/// Manifests live in a root-owned directory, so `refresh` run as the operator
/// or as the service user cannot write one. Nothing about that is visible from
/// the menu, and the expensive part sits between the two points.
fn ensure_manifest_writable(path: &Path) -> Result<()> {
    let writable = if path.is_file() {
        fs::OpenOptions::new().append(true).open(path).is_ok()
    } else {
        // Not there yet, so the directory is what must accept a new file.
        // There is no portable "may I create here" short of trying.
        let dir = path.parent().unwrap_or(Path::new("."));
        let probe = dir.join(".vaulted-agent-write-probe");
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
        {
            Ok(_) => {
                let _ = fs::remove_file(&probe);
                true
            }
            Err(_) => false,
        }
    };
    if writable {
        return Ok(());
    }
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "vaulted-agent".to_string());
    Err(Error::Message(format!(
        "cannot write {} as `{}`.\n  \
         Manifests are root-owned. Re-run as root, by full path — sudo's \
         secure_path will not have the launcher on it:\n    \
         sudo {exe} refresh",
        path.display(),
        crate::privilege::current_user(),
    )))
}

fn load_op_with(paths: &Paths, mode: AuthMode) -> Result<ManagerToken> {
    auth::load_manager_token(paths, mode, TokenKind::Op, force_prompt())
}

fn load_op(paths: &Paths) -> Result<ManagerToken> {
    load_op_with(paths, auth_mode(paths))
}

/// 1Password: pick items from the vault, then turn each picked item's fields
/// into `VAR=op://VAULT/ITEM/FIELD` lines.
///
/// Selection is at ITEM level, not field level, for two reasons: an item is the
/// unit a person recognises, and `op item list` returns every item in one call
/// while fields cost one `op item get` per item. Expanding all items up front
/// would mean a per-item round trip before the menu could even be printed
/// (~50s on a 60-item vault). Only the chosen items are expanded.
fn refresh_onepassword(
    paths: &Paths,
    man_path: Option<String>,
    take_all: bool,
    mode: Option<&str>,
    exclude: &[String],
    prune: bool,
) -> Result<()> {
    let token = load_op(paths)?;
    let items = backend::op_list_items(&token, None)?;
    if items.is_empty() {
        return Err(Error::Message(
            "No 1Password items visible to this token yet.".into(),
        ));
    }

    let path = match man_path {
        Some(man) => {
            if Path::new(&man).is_absolute() {
                PathBuf::from(&man)
            } else {
                paths.manifest_dir.join(&man)
            }
        }
        None => default_onepassword_manifest(paths)?,
    };
    let mode = mode.unwrap_or(if path.is_file() { "merge" } else { "replace" });

    // Checked before the menu, not after the reads. Expanding every item costs
    // a round trip apiece (~a minute on a 65-item vault); discovering the file
    // is root-owned only at the write meant paying all of that to learn
    // something knowable at the start.
    ensure_manifest_writable(&path)?;

    // Patterns already recorded in the manifest, plus any given on this run.
    // Reading them here rather than inside the writer keeps the filtering
    // visible: what was skipped is reported below, never silently dropped.
    let mut exclusions = if path.is_file() {
        refs::read_exclusions(&fs::read_to_string(&path).unwrap_or_default())
    } else {
        Vec::new()
    };
    for p in exclude {
        if !exclusions.iter().any(|q| q == p) {
            exclusions.push(p.clone());
        }
    }

    let indices: Vec<usize> = if take_all || !std::io::IsTerminal::is_terminal(&io::stdin()) {
        (0..items.len()).collect()
    } else {
        println!("Items visible to this token:");
        for (i, it) in items.iter().enumerate() {
            println!("  {:2}) {}  ({})", i + 1, it.title, it.vault);
        }
        println!();
        eprint!("Items to include (e.g. 1,4,7 or 1-5,9 - blank for all): ");
        let _ = io::stderr().flush();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_err() || line.trim().is_empty() {
            (0..items.len()).collect()
        } else {
            refs::parse_index_list(line.trim(), items.len())?
        }
    };

    // Fields are fetched only for the items actually chosen.
    let mut entries: Vec<(String, String)> = Vec::new();
    let mut unreadable: Vec<String> = Vec::new();
    let mut unrepresentable: Vec<String> = Vec::new();
    let mut excluded: Vec<String> = Vec::new();
    // What the run learned, for judging the mappings already in the file. Only
    // the items expanded below land in it: `refresh` judges what it fetched and
    // nothing more (ADR-0005).
    let mut world = refs::OpWorld {
        items: items.clone(),
        fields: std::collections::HashMap::new(),
    };
    for i in indices {
        let backend::OpItem {
            id, title, vault, ..
        } = &items[i];
        // A per-item failure (transient 502 from the vault API, an item the
        // token cannot read) must not discard the whole run - reading 60 items
        // takes ~a minute, and refresh defaults to merge, so the next run picks
        // up whatever was missed. Skips are reported, never silent.
        // One `op item get`, read twice: the fields worth mapping, and every
        // field identity a reference may name. The second view is wider — an
        // OTP or empty-valued field is one `refresh` will not map and `op` will
        // still resolve — and judging an existing mapping against the narrow
        // one would call a working line dangling.
        let json = match backend::op_item_json(&token, id, Some(vault.as_str())) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("  warn: {title}: {e}");
                unreadable.push(title.clone());
                continue;
            }
        };
        let fields = match backend::parse_op_item_fields_json(&json)
            .and_then(|f| backend::parse_op_item_field_refs(&json).map(|r| (f, r)))
        {
            Ok((fields, field_refs)) => {
                world.fields.insert(id.clone(), field_refs);
                fields
            }
            Err(e) => {
                eprintln!("  warn: {title}: {e}");
                unreadable.push(title.clone());
                continue;
            }
        };
        if fields.is_empty() {
            println!("  {title}: no referenceable fields, skipped");
            continue;
        }
        // Named per item, because dropping a default section label can make two
        // of an item's fields want one name and only the whole item shows that.
        let mut representable: Vec<backend::OpField> = Vec::new();
        for f in fields {
            let section = f.section.as_deref();
            // An item has an opaque ID to fall back on when its title does not
            // parse; a section or field label has no such fallback. Report and
            // skip those rather than writing a reference that would abort the
            // injection of every other variable in the file.
            if !section.map(refs::op_component_is_safe).unwrap_or(true)
                || !refs::op_component_is_safe(&f.label)
            {
                eprintln!(
                    "  warn: {title}: field '{}' has characters op cannot parse, skipped",
                    f.label
                );
                unrepresentable.push(title.clone());
                continue;
            }
            representable.push(f);
        }

        for f in &representable {
            let section = f.section.as_deref();
            let plain = refs::op_ref_var(title, section, &f.label);
            // Two fields reduced to the same name are two different secrets, so
            // keep the section on both rather than let either win. Rare: it
            // needs one item holding the same label inside and outside its
            // default section.
            let clashes = representable
                .iter()
                .filter(|g| refs::op_ref_var(title, g.section.as_deref(), &g.label) == plain)
                .count()
                > 1;
            let var = if clashes {
                refs::op_ref_var_qualified(title, section, &f.label)
            } else {
                plain
            };
            if refs::is_excluded(&exclusions, &var) {
                excluded.push(var);
                continue;
            }
            entries.push((
                var,
                refs::op_reference(vault, refs::op_item_component(title, id), section, &f.label),
            ));
        }
    }
    drop(token);

    if !excluded.is_empty() {
        println!(
            "\n{} field(s) matched an exclusion and were left out: {}",
            excluded.len(),
            excluded.join(", ")
        );
    }

    if !unrepresentable.is_empty() {
        let mut names = unrepresentable.clone();
        names.sort();
        names.dedup();
        println!(
            "\n{} field(s) on {} item(s) cannot be written as a reference and were \
             left out: {}\n\
             Rename the section or field in the vault to use letters, digits, \
             spaces, '.', '_' or '-' if you need them.",
            unrepresentable.len(),
            names.len(),
            names.join(", ")
        );
    }

    if !unreadable.is_empty() {
        println!(
            "\n{} item(s) could not be read and were left out: {}\n\
             Re-run refresh to pick them up (merge only adds what is missing).",
            unreadable.len(),
            unreadable.join(", ")
        );
    }

    // After the reads, because the fields they returned are what makes a
    // field-level verdict possible; before the write, so a dangling line is
    // gone by the time merge decides what to append.
    report_and_fix_op_refs(paths, &path, &world, &exclusions, mode == "replace", prune)?;

    if entries.is_empty() {
        return Err(Error::Message(if excluded.is_empty() {
            "Nothing selected has a referenceable field.".into()
        } else {
            // Distinguishable from "the vault gave us nothing", because the
            // operator's own patterns caused this and the fix is to relax one.
            format!(
                "Every referenceable field on what you selected matched an exclusion \
                 ({} field(s)). Loosen a pattern in {} to map any of them.",
                excluded.len(),
                path.display()
            )
        }));
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }

    match mode {
        "replace" => {
            refs::write_op_refs_replace(&path, &entries, &exclusions, "vaulted-agent refresh")?;
            println!(
                "\nWrote refs file (replace, {} mapping(s)): {}",
                entries.len(),
                path.display()
            );
        }
        _ => {
            let added =
                refs::write_op_refs_merge(&path, &entries, &exclusions, "vaulted-agent refresh")?;
            if added == 0 {
                println!("\nNo new mappings to add: {}", path.display());
            } else {
                println!(
                    "\nUpdated refs file (+{added} mapping(s)): {}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

/// Resolve the refs file for a bare 1Password `refresh` from harness config,
/// mirroring `default_bitwarden_manifest`.
fn default_onepassword_manifest(paths: &Paths) -> Result<PathBuf> {
    let be_default = default_backend(paths);
    let mut candidates: Vec<PathBuf> = Vec::new();
    for name in list_harness_names(paths)? {
        let h = Harness::load(paths, &name)?;
        let be = h.backend.unwrap_or(be_default);
        if be == Backend::OnePassword {
            candidates.push(h.resolve_manifest_path(paths));
        }
    }
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [one] => Ok(one.clone()),
        [] => Ok(paths.manifest_dir.join("onepassword.refs")),
        many => Err(Error::Message(format!(
            "multiple onepassword manifests ({}); pass one explicitly: vaulted-agent refresh <file>",
            many.iter()
                .map(|p| p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Resolve the refs file for bare `refresh` / setup from harness config (story #13).
fn default_bitwarden_manifest(paths: &Paths) -> Result<PathBuf> {
    let be_default = default_backend(paths);
    let mut candidates: Vec<PathBuf> = Vec::new();
    for name in list_harness_names(paths)? {
        let h = Harness::load(paths, &name)?;
        let be = h.backend.unwrap_or(be_default);
        if be == Backend::Bitwarden {
            candidates.push(h.resolve_manifest_path(paths));
        }
    }
    candidates.sort();
    candidates.dedup();
    match candidates.as_slice() {
        [one] => Ok(one.clone()),
        [] => {
            let fallback = paths.manifest_dir.join("openai.env.refs");
            if fallback.is_file() {
                Ok(fallback)
            } else {
                // No harness yet — create the conventional default.
                Ok(fallback)
            }
        }
        many => Err(Error::Message(format!(
            "multiple bitwarden manifests ({}); pass one explicitly: vaulted-agent refresh <file>",
            many.iter()
                .map(|p| p
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("?")
                    .to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Legacy fallback for `Capture::UseExisting`: load the token the usual way
/// (env var, existing file, or prompt) and, under `auth_mode=file`, persist it
/// so rotating through an exported token still lands on disk.
fn store_existing_token(paths: &Paths, kind: TokenKind, mode: AuthMode) -> Result<ManagerToken> {
    let token = auth::load_manager_token(paths, mode, kind, force_prompt())?;
    let path = kind.file(paths).to_path_buf();
    if mode == AuthMode::File {
        let svc = service_user_for_token(paths);
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

fn setup_bitwarden(paths: &Paths, mode: AuthMode, set_token: bool) -> Result<()> {
    println!("\nBitwarden Secrets Manager");
    println!("  Needs a Machine Account access token (BWS_ACCESS_TOKEN),");
    println!("  not your personal vault master password or login API key.\n");
    // Token capture: setup is the only place that may obtain and store a
    // manager token (issue #77). `bws secret list` is both the liveness check
    // that keeps an invalid token off disk and the data the rest of setup
    // needs, so keep the result instead of paying for a second round trip.
    let listed: RefCell<Option<Vec<(String, String, String)>>> = RefCell::new(None);
    let verify = |t: &ManagerToken| {
        *listed.borrow_mut() = Some(backend::bws_list_secrets(t)?);
        Ok(())
    };
    let token = match auth::capture_token(paths, TokenKind::Bws, mode, set_token, &verify)? {
        auth::Capture::Token(t) => t,
        auth::Capture::UseExisting => store_existing_token(paths, TokenKind::Bws, mode)?,
        auth::Capture::Skipped => {
            // Everything left here needs the token to talk to the vault.
            println!("Skipping vault work. When you have a token:");
            println!("  vaulted-agent setup bitwarden");
            return Ok(());
        }
    };
    let secrets = match listed.borrow_mut().take() {
        Some(secrets) => secrets,
        None => backend::bws_list_secrets(&token)?,
    };
    drop(token);
    if secrets.is_empty() {
        println!("No secrets in this machine account yet. Create one in SM, then:");
        println!("  vaulted-agent secrets list");
        println!("  vaulted-agent refresh");
        return Ok(());
    }
    println!("{} secret(s) visible.", secrets.len());
    let man_path = default_bitwarden_manifest(paths)?;
    fs::create_dir_all(&paths.manifest_dir).ok();
    if man_path.is_file() {
        let merge = refs::write_refs_merge(&man_path, &secrets, None, "vaulted-agent setup")?;
        if merge.recovered > 0 {
            println!(
                "Split {} mapping(s) that were glued onto one line (va 0.3.0 refresh)",
                merge.recovered
            );
        }
        println!("Merged into {} (+{})", man_path.display(), merge.added);
    } else {
        refs::write_refs_replace(&man_path, &secrets, None, "vaulted-agent setup")?;
        println!("Wrote {}", man_path.display());
    }
    if let Some(name) = man_path.file_name().and_then(|s| s.to_str()) {
        println!("Point a harness at it with: manifest = {name}");
    }
    Ok(())
}

fn setup_onepassword(paths: &Paths, mode: AuthMode, set_token: bool) -> Result<()> {
    println!("\n1Password service account");
    println!("  Needs OP_SERVICE_ACCOUNT_TOKEN (not your personal account password).\n");
    // Token capture (issue #77); `op whoami` verifies before anything is written.
    let verify = |t: &ManagerToken| backend::op_whoami(t);
    match auth::capture_token(paths, TokenKind::Op, mode, set_token, &verify)? {
        auth::Capture::Token(token) => drop(token),
        auth::Capture::UseExisting => drop(store_existing_token(paths, TokenKind::Op, mode)?),
        // A declined paste skips the token, not the rest of setup: the guidance
        // below is what tells the operator how to wire a harness (install.sh
        // parity — its skip is a skip of the token write only).
        auth::Capture::Skipped => {}
    }
    println!("Manifests use op:// references; op inject runs at launch.");
    println!("Example harness: backend = onepassword");
    Ok(())
}

pub fn cmd_setup(paths: &Paths, args: &[String]) -> Result<()> {
    println!("vaulted-agent setup");
    println!("config: {}", paths.config_dir.display());

    // Ask how manager tokens are obtained (file on disk vs paste each launch)
    // before any backend work that may write op.env / bws.env.
    let mode = ensure_auth_mode_for_setup(paths)?;
    println!("auth_mode: {}", mode.as_str());

    // Who agents run as, and where they start — both shape every later launch,
    // and interact (service_user + workdir=caller on a 0700 home). Ask before
    // token write so chown root:service_user is right (issue #55).
    let service_user = ensure_service_user_for_setup(paths)?;
    ensure_workdir_for_setup(paths, service_user.as_deref())?;

    // `--set-token` is the piped-capture / rotation door. Not `auth-mode`:
    // that verb is about *how* tokens are supplied, not *what* the token is.
    let set_token = args.iter().any(|a| a == "--set-token");

    // Explicit backend: setup [bitwarden|onepassword|bws|op]
    let want = args
        .first()
        .map(|s| s.as_str())
        .filter(|s| !s.starts_with('-'));

    let choose = |name: &str| -> Result<()> {
        match name {
            "bitwarden" | "bws" => setup_bitwarden(paths, mode, set_token),
            "onepassword" | "op" | "1password" => setup_onepassword(paths, mode, set_token),
            "pass" | "sops" if set_token => Err(Error::Message(format!(
                "setup --set-token: {name} has no manager token file \
                 (pass uses GPG, sops uses an age key)"
            ))),
            "pass" => {
                println!("\npass backend uses the passwordstore.org store (GPG).");
                println!("No token file. Ensure `pass` is on PATH for the service account.");
                Ok(())
            }
            "sops" => {
                println!(
                    "\nsops backend uses age identity at {}",
                    paths.age_key_file.display()
                );
                println!("Place the age key there (0640) and encrypt manifests with sops.");
                Ok(())
            }
            other => Err(Error::Message(format!(
                "setup: unknown backend '{other}' (want bitwarden, onepassword, pass, sops)"
            ))),
        }
    };

    if let Some(name) = want {
        return choose(name);
    }

    // Auto: prefer whichever token is already available (env or file).
    if env::var_os("BWS_ACCESS_TOKEN").is_some() || paths.bws_env_file.is_file() {
        return setup_bitwarden(paths, mode, set_token);
    }
    if env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_some() || paths.op_env_file.is_file() {
        return setup_onepassword(paths, mode, set_token);
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

fn user_home(user: &str) -> Option<PathBuf> {
    let out = Command::new("sh")
        .args([
            "-c",
            &format!(
                "getent passwd {user} 2>/dev/null | cut -d: -f6 || \
                 dscl . -read /Users/{user} NFSHomeDirectory 2>/dev/null | awk '{{print $2}}'"
            ),
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let home = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if home.is_empty() {
        None
    } else {
        Some(PathBuf::from(home))
    }
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
        if let Some(home) = user_home(u) {
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

pub fn cmd_run(paths: &Paths, args: &[String], force_prompt: bool) -> Result<()> {
    if let Some(msg) = run_refusal(load_service_user(paths).as_deref(), load_allow_run(paths)) {
        return Err(Error::Message(msg));
    }
    let mut manifest: Option<String> = None;
    let mut backend = default_backend(paths);
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
    let man_path = if Path::new(&man).is_absolute() {
        PathBuf::from(&man)
    } else {
        paths.manifest_dir.join(&man)
    };
    launch::launch_run(
        paths,
        &man_path,
        backend,
        workdir.as_deref(),
        &cmd,
        force_prompt,
    )
}

pub fn cmd_pick(paths: &Paths) -> Result<String> {
    let names = list_harness_names(paths)?;
    if names.is_empty() {
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
    for (i, n) in names.iter().enumerate() {
        let h = Harness::load(paths, n).ok();
        let cmd = h.as_ref().map(|h| h.command.join(" ")).unwrap_or_default();
        let man = h.map(|h| h.manifest).unwrap_or_default();
        eprintln!("  {:2}) {:16} {:38} {}", i + 1, n, cmd, man);
    }
    eprintln!();
    loop {
        eprint!("harness [1-{}, q to quit]: ", names.len());
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
            std::process::exit(0);
        }
        if let Ok(n) = choice.parse::<usize>() {
            if n >= 1 && n <= names.len() {
                return Ok(names[n - 1].clone());
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
    force_prompt: bool,
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
            force_prompt,
            extra_args: extra_args.to_vec(),
            handoff: None,
        },
    )
}

/// When service_user is configured and current uid differs, re-exec via sudo.
/// Policy lives in `privilege`; this is a thin adapter for CLI/main.
pub fn maybe_reexec_service_user(paths: &Paths, argv0: &str, orig_args: &[String]) -> Result<()> {
    crate::privilege::maybe_reexec_service_user(paths, argv0, orig_args)
}

pub fn usage(paths: &Paths) {
    let mode = load_auth_mode(paths);
    let be = default_backend(paths);
    eprintln!(
        "usage: vaulted-agent [-m MANIFEST] <harness> [args...]\n\
         \x20      va [-m MANIFEST] <harness> [args...]\n\
         \x20      vaulted-agent run -m MANIFEST [--backend NAME] -- cmd [args...]\n\
         \x20      vaulted-agent pick [args...]\n\
         \x20      vaulted-agent doctor\n\
         \x20      vaulted-agent secrets …\n\
         \x20      vaulted-agent setup [bitwarden|onepassword] [--set-token]\n\
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
         default auth_mode: {}  (file = token on disk; prompt = paste each launch)\n\
         default backend:   {}\n\
         config: VAULTED_AGENT_CONFIG_DIR (default /etc/vaulted-agent)\n\
         (tests only: VAULTED_AGENT_HANDOFF=spawn spawns instead of exec)",
        mode.as_str(),
        be
    );
    if let Ok(names) = list_harness_names(paths) {
        eprintln!("\nharnesses in {}:", paths.harness_dir.display());
        if names.is_empty() {
            eprintln!("  (none configured)");
        } else {
            for n in names {
                if let Ok(h) = Harness::load(paths, &n) {
                    eprintln!("  {:16} {}", n, h.command.join(" "));
                } else {
                    eprintln!("  {n}");
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
    let harnesses: Vec<(String, String)> = list_harness_names(paths)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|n| Harness::load(paths, &n).ok().map(|h| (n, h.manifest)))
        .collect();

    println!("Manifests in {}:", paths.manifest_dir.display());
    for (i, path) in candidates.iter().enumerate() {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let count = fs::read_to_string(path)
            .ok()
            .and_then(|t| crate::config::parse_dotenv_keys(&t).ok())
            .map(|m| m.len());
        let users: Vec<&str> = harnesses
            .iter()
            .filter(|(_, m)| m.as_str() == name)
            .map(|(n, _)| n.as_str())
            .collect();
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

    loop {
        open_in_editor(&path)?;
        let text = fs::read_to_string(&path).map_err(|e| Error::Io {
            path: path.clone(),
            source: e,
        })?;
        let problems = crate::validate::manifest_problems(&text);
        if problems.is_empty() {
            let n = crate::config::parse_dotenv_keys(&text)
                .map(|m| m.len())
                .unwrap_or(0);
            println!(
                "{}: {n} variable(s), no problems found.",
                path.file_name().unwrap_or_default().to_string_lossy()
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
            eprintln!("Left as saved. A launch using this manifest will fail until it is fixed.");
            return Ok(());
        }
    }
}

/// Reserved management command names (unless a harness .conf of that name exists).
pub fn is_reserved(name: &str, paths: &Paths) -> bool {
    let reserved = [
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
    ];
    if !reserved.contains(&name) {
        return false;
    }
    // Real harness wins
    if paths.harness_dir.join(format!("{name}.conf")).is_file() {
        return false;
    }
    true
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
    fn workdir_caller_is_silent_when_probe_paths_are_traversable() {
        // Test cwd is always traversable; config shape alone must not warn.
        assert_eq!(
            workdir_warning(Some("conductor"), Some("caller"), "claude"),
            None
        );
    }

    #[test]
    fn workdir_caller_warns_only_when_a_probe_path_fails() {
        let uid = std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
            })
            .unwrap_or(0);
        if uid == 0 {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let blocked = tmp.path().join("no-enter");
        fs::create_dir(&blocked).unwrap();
        let mut perms = fs::metadata(&blocked).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o000);
        fs::set_permissions(&blocked, perms).unwrap();

        std::env::set_var("VAULTED_AGENT_CALLER_CWD", &blocked);
        let w = workdir_warning(Some("conductor"), Some("caller"), "claude")
            .expect("blocked caller path should warn");
        assert!(w.contains("cannot enter"), "{w}");
        assert!(w.contains("conductor"), "{w}");
        assert!(w.contains("setfacl"), "{w}");
        std::env::remove_var("VAULTED_AGENT_CALLER_CWD");

        let mut perms = fs::metadata(&blocked).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&blocked, perms).unwrap();
    }

    #[test]
    fn absolute_workdir_is_fine_under_a_service_user_when_traversable() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            workdir_warning(
                Some("conductor"),
                Some(tmp.path().to_str().unwrap()),
                "claude"
            ),
            None
        );
    }

    #[test]
    fn agent_without_caller_still_warns_when_no_service_user() {
        assert_eq!(
            workdir_warning(None, Some("/srv/x"), "claude").as_deref(),
            Some("agent harness without workdir=caller")
        );
        assert_eq!(workdir_warning(None, Some("caller"), "claude"), None);
    }

    #[test]
    fn non_agent_harness_is_not_nagged_about_workdir() {
        assert_eq!(workdir_warning(None, Some("/srv/x"), "backup"), None);
    }
}
