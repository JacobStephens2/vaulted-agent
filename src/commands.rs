//! Management subcommands: secrets, doctor, setup, refresh, auth-mode, uninstall, pick, run.

use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::auth::{self, TokenKind};
use crate::backend;
use crate::config::{
    list_harness_names, load_auth_mode, load_default_backend, load_service_user, parse_dotenv_keys,
    AuthMode, Backend, Harness, Paths,
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
    println!("vaulted-agent {}", env!("CARGO_PKG_VERSION"));
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
    if !trimmed.is_empty()
        && !matches!(
            trimmed,
            "1" | "file" | "disk" | "2" | "prompt" | "p"
        )
    {
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
    // Preserve other defaults keys (default_backend, service_user, …).
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
            if k.trim() == "auth_mode" {
                lines.push(format!("auth_mode = {}", mode.as_str()));
                saw = true;
                continue;
            }
        }
        lines.push(raw.to_string());
    }
    if !saw {
        lines.push(format!("auth_mode = {}", mode.as_str()));
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

pub fn cmd_secrets(paths: &Paths, args: &[String]) -> Result<()> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("");
    match sub {
        "" | "-h" | "--help" | "help" => {
            println!(
                "usage: vaulted-agent secrets list\n\
                 \x20      vaulted-agent secrets get <ref>\n\
                 \x20      vaulted-agent secrets which\n\
                 \x20      vaulted-agent secrets validate [manifest-or-harness]\n\
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
            let target = args.get(1).map(|s| s.as_str());
            match target {
                None => {
                    let mut err = false;
                    let names = list_harness_names(paths)?;
                    let be_default = default_backend(paths);
                    for name in names {
                        let h = Harness::load(paths, &name)?;
                        let be = h.backend.unwrap_or(be_default);
                        let man_path = h.resolve_manifest_path(paths);
                        print!("{name}: ");
                        match validate_manifest_file(&man_path, be) {
                            Ok(_) => println!("ok"),
                            Err(e) => {
                                println!("FAIL ({e})");
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
                        let be = match args.get(2) {
                            Some(s) => s.parse()?,
                            None => default_backend(paths),
                        };
                        (man_path, be)
                    };
                    validate_manifest_file(&man_path, be)?;
                    println!("ok: {}", man_path.display());
                    Ok(())
                }
            }
        }
        other => Err(Error::Message(format!(
            "unknown secrets subcommand '{other}' (try: list, get, which, validate, refresh)"
        ))),
    }
}

pub fn cmd_doctor(paths: &Paths) -> Result<()> {
    let mut issues = 0usize;
    let mut warn = 0usize;
    println!("vaulted-agent doctor");
    println!("config: {}", paths.config_dir.display());
    println!("auth_mode: {}", load_auth_mode(paths).as_str());
    println!("default_backend: {}", default_backend(paths));

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

    if paths.bws_env_file.is_file() {
        println!("bws.env: present");
    } else {
        println!("bws.env: missing");
    }
    if paths.op_env_file.is_file() {
        println!("op.env: present");
    } else {
        println!("op.env: missing");
    }

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
        if matches!(name.as_str(), "claude" | "codex" | "grok" | "kimi")
            && h.workdir.as_deref() != Some("caller")
        {
            println!("  WARN: agent harness without workdir=caller");
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
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!(
                    "usage: vaulted-agent refresh [manifest] [--all] [--merge|--replace]\n\
                     Update a Bitwarden refs file after adding secrets in SM.\n\
                     Secret values are never stored — only references."
                );
                return Ok(());
            }
            "--all" | "-a" => take_all = true,
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
            let added = refs::write_refs_merge(
                &path,
                &secrets,
                indices.as_deref(),
                "vaulted-agent refresh",
            )?;
            if added == 0 {
                println!("No new mappings to add: {}", path.display());
            } else {
                println!(
                    "Updated refs file (+{added} mapping(s)): {}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

fn load_op_with(paths: &Paths, mode: AuthMode) -> Result<ManagerToken> {
    auth::load_manager_token(paths, mode, TokenKind::Op, force_prompt())
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

fn setup_bitwarden(paths: &Paths, mode: AuthMode) -> Result<()> {
    println!("\nBitwarden Secrets Manager");
    println!("  Needs a Machine Account access token (BWS_ACCESS_TOKEN),");
    println!("  not your personal vault master password or login API key.\n");
    let token = load_bws_with(paths, mode)?;
    if mode == AuthMode::File {
        // Always write so token rotation works (parity with setup onepassword).
        let svc = service_user_for_token(paths);
        auth::write_token_file(
            &paths.bws_env_file,
            "BWS_ACCESS_TOKEN",
            &token,
            svc.as_deref(),
        )?;
        println!("wrote {}", paths.bws_env_file.display());
    } else {
        println!("auth_mode=prompt — token not written to disk.");
    }
    let secrets = backend::bws_list_secrets(&token)?;
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
        let added = refs::write_refs_merge(&man_path, &secrets, None, "vaulted-agent setup")?;
        println!("Merged into {} (+{added})", man_path.display());
    } else {
        refs::write_refs_replace(&man_path, &secrets, None, "vaulted-agent setup")?;
        println!("Wrote {}", man_path.display());
    }
    if let Some(name) = man_path.file_name().and_then(|s| s.to_str()) {
        println!("Point a harness at it with: manifest = {name}");
    }
    Ok(())
}

fn setup_onepassword(paths: &Paths, mode: AuthMode) -> Result<()> {
    println!("\n1Password service account");
    println!("  Needs OP_SERVICE_ACCOUNT_TOKEN (not your personal account password).\n");
    let token = load_op_with(paths, mode)?;
    if mode == AuthMode::File {
        let svc = service_user_for_token(paths);
        auth::write_token_file(
            &paths.op_env_file,
            "OP_SERVICE_ACCOUNT_TOKEN",
            &token,
            svc.as_deref(),
        )?;
        println!("wrote {} (0640)", paths.op_env_file.display());
    } else {
        println!("auth_mode=prompt — token not written to disk (good).");
        println!("  To store it: vaulted-agent auth-mode file, then re-run setup onepassword.");
    }
    drop(token);
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

    // Explicit backend: setup [bitwarden|onepassword|bws|op]
    let want = args
        .first()
        .map(|s| s.as_str())
        .filter(|s| !s.starts_with('-'));

    let choose = |name: &str| -> Result<()> {
        match name {
            "bitwarden" | "bws" => setup_bitwarden(paths, mode),
            "onepassword" | "op" | "1password" => setup_onepassword(paths, mode),
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
        return setup_bitwarden(paths, mode);
    }
    if env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_some() || paths.op_env_file.is_file() {
        return setup_onepassword(paths, mode);
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

pub fn cmd_run(paths: &Paths, args: &[String], force_prompt: bool) -> Result<()> {
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

/// Launch a named harness with optional extra agent args.
pub fn cmd_launch_harness(
    paths: &Paths,
    name: &str,
    extra_args: &[String],
    force_prompt: bool,
) -> Result<()> {
    let harness = Harness::load(paths, name)?;
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
        "usage: vaulted-agent <harness> [args...]\n\
         \x20      va <harness> [args...]\n\
         \x20      vaulted-agent run -m MANIFEST [--backend NAME] -- cmd [args...]\n\
         \x20      vaulted-agent pick [args...]\n\
         \x20      vaulted-agent doctor\n\
         \x20      vaulted-agent secrets …\n\
         \x20      vaulted-agent setup\n\
         \x20      vaulted-agent refresh [file]\n\
         \x20      vaulted-agent auth-mode [mode]\n\
         \x20      vaulted-agent version\n\
         \x20      vaulted-agent uninstall [opts]\n\
         \nlauncher flags:  --prompt-auth|-p   prompt for vault token this launch\n\
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
        "pick",
        "run",
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
        assert_eq!(parse_auth_mode_choice("p", AuthMode::File), AuthMode::Prompt);
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
}
