//! Management subcommands: secrets, doctor, setup, refresh, auth-mode, uninstall, pick, run.

use std::env;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::auth::{self, TokenKind};
use crate::backend;
use crate::config::{
    AuthMode, Harness, Paths, load_auth_mode, list_harness_names, parse_dotenv_keys,
};
use crate::error::{Error, Result};
use crate::launch::{self, LaunchOpts};
use crate::refs;
use crate::secret::ManagerToken;
use crate::validate::validate_manifest_file;

pub fn default_backend(paths: &Paths) -> String {
    crate::config::load_default_backend(paths)
}

fn force_prompt() -> bool {
    env::var_os("VAULTED_AGENT_PROMPT_AUTH").as_deref() == Some(std::ffi::OsStr::new("1"))
}

fn auth_mode(paths: &Paths) -> AuthMode {
    match env::var("VAULTED_AGENT_AUTH_MODE").as_deref() {
        Ok("prompt") => AuthMode::Prompt,
        Ok("file") => AuthMode::File,
        _ => load_auth_mode(paths),
    }
}

fn load_bws(paths: &Paths) -> Result<ManagerToken> {
    auth::load_manager_token(paths, auth_mode(paths), TokenKind::Bws, force_prompt())
}

pub fn cmd_version() {
    println!("vaulted-agent {}", env!("CARGO_PKG_VERSION"));
}

pub fn cmd_auth_mode(paths: &Paths, args: &[String]) -> Result<()> {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("show");
    match sub {
        "show" | "" => {
            let mode = load_auth_mode(paths);
            println!("auth_mode={}", mode.as_str());
            Ok(())
        }
        "file" | "prompt" => {
            let mode = AuthMode::parse(sub).unwrap();
            write_auth_mode(paths, mode)?;
            println!("auth_mode={}", mode.as_str());
            Ok(())
        }
        other => Err(Error::Message(format!(
            "unknown auth-mode '{other}' (want file, prompt, or show)"
        ))),
    }
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
        fs::create_dir_all(parent).map_err(|e| Error::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    fs::write(&paths.defaults_file, body).map_err(|e| Error::Io {
        path: paths.defaults_file.clone(),
        source: e,
    })?;
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
                    println!(
                        "  {:2}) {:36}  {}  (project: {})",
                        i + 1,
                        id,
                        key,
                        proj
                    );
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
                let be = h.backend.as_deref().unwrap_or(&be_default);
                let man = &h.manifest;
                println!("{name}  (backend={be} manifest={man})");
                let man_path = h.resolve_manifest_path(paths);
                if man_path.is_file() {
                    if let Ok(text) = fs::read_to_string(&man_path) {
                        for k in parse_dotenv_keys(&text).keys() {
                            println!("  {k}");
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
                        let be = h.backend.clone().unwrap_or_else(|| be_default.clone());
                        let man_path = h.resolve_manifest_path(paths);
                        print!("{name}: ");
                        match validate_manifest_file(&man_path, &be) {
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
                        let be = h
                            .backend
                            .clone()
                            .unwrap_or_else(|| default_backend(paths));
                        (h.resolve_manifest_path(paths), be)
                    } else {
                        let p = Path::new(man);
                        let man_path = if p.is_absolute() {
                            p.to_path_buf()
                        } else {
                            paths.manifest_dir.join(p)
                        };
                        let be = args
                            .get(2)
                            .cloned()
                            .unwrap_or_else(|| default_backend(paths));
                        (man_path, be)
                    };
                    validate_manifest_file(&man_path, &be)?;
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

    let have = |bin: &str| Command::new("sh").args(["-c", &format!("command -v {bin}")]).status().map(|s| s.success()).unwrap_or(false);
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
        let be = h.backend.as_deref().unwrap_or(&be_default);
        println!("  backend={be} manifest={} workdir={:?}", h.manifest, h.workdir);
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
            "bitwarden" if !have_bws => {
                println!("  ERROR: bws not on PATH");
                issues += 1;
            }
            "onepassword" if !have_op => {
                println!("  ERROR: op not on PATH");
                issues += 1;
            }
            "sops" if !have_sops => {
                println!("  ERROR: sops not on PATH");
                issues += 1;
            }
            "pass" if !have_pass => {
                println!("  ERROR: pass not on PATH");
                issues += 1;
            }
            "plainfile" | "bitwarden" | "onepassword" | "sops" | "pass" => {}
            other => {
                println!("  ERROR: unknown backend {other}");
                issues += 1;
            }
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
        return Err(Error::Message("No secrets visible to this token yet.".into()));
    }

    let man = man_path.unwrap_or_else(|| "openai.env.refs".into());
    let path = if Path::new(&man).is_absolute() {
        PathBuf::from(&man)
    } else {
        paths.manifest_dir.join(&man)
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
            let added =
                refs::write_refs_merge(&path, &secrets, indices.as_deref(), "vaulted-agent refresh")?;
            if added == 0 {
                println!("No new mappings to add: {}", path.display());
            } else {
                println!("Updated refs file (+{added} mapping(s)): {}", path.display());
            }
        }
    }
    Ok(())
}

fn load_op(paths: &Paths) -> Result<ManagerToken> {
    auth::load_manager_token(paths, auth_mode(paths), TokenKind::Op, force_prompt())
}

fn setup_bitwarden(paths: &Paths) -> Result<()> {
    println!("\nBitwarden Secrets Manager");
    println!("  Needs a Machine Account access token (BWS_ACCESS_TOKEN),");
    println!("  not your personal vault master password or login API key.\n");
    let token = load_bws(paths)?;
    if auth_mode(paths) == AuthMode::File {
        if !paths.bws_env_file.is_file() {
            auth::write_token_file(&paths.bws_env_file, "BWS_ACCESS_TOKEN", &token)?;
            println!("wrote {}", paths.bws_env_file.display());
        }
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
    let man_path = paths.manifest_dir.join("openai.env.refs");
    fs::create_dir_all(&paths.manifest_dir).ok();
    if man_path.is_file() {
        let added = refs::write_refs_merge(&man_path, &secrets, None, "vaulted-agent setup")?;
        println!("Merged into {} (+{added})", man_path.display());
    } else {
        refs::write_refs_replace(&man_path, &secrets, None, "vaulted-agent setup")?;
        println!("Wrote {}", man_path.display());
    }
    println!("Point a harness at it with: manifest = openai.env.refs");
    Ok(())
}

fn setup_onepassword(paths: &Paths) -> Result<()> {
    println!("\n1Password service account");
    println!("  Needs OP_SERVICE_ACCOUNT_TOKEN (not your personal account password).\n");
    let token = load_op(paths)?;
    if auth_mode(paths) == AuthMode::File {
        auth::write_token_file(
            &paths.op_env_file,
            "OP_SERVICE_ACCOUNT_TOKEN",
            &token,
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
    println!("auth_mode: {}", auth_mode(paths).as_str());

    // Explicit backend: setup [bitwarden|onepassword|bws|op]
    let want = args
        .first()
        .map(|s| s.as_str())
        .filter(|s| !s.starts_with('-'));

    let choose = |name: &str| -> Result<()> {
        match name {
            "bitwarden" | "bws" => setup_bitwarden(paths),
            "onepassword" | "op" | "1password" => setup_onepassword(paths),
            "pass" => {
                println!("\npass backend uses the passwordstore.org store (GPG).");
                println!("No token file. Ensure `pass` is on PATH for the service account.");
                Ok(())
            }
            "sops" => {
                println!("\nsops backend uses age identity at {}", paths.age_key_file.display());
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
        return setup_bitwarden(paths);
    }
    if env::var_os("OP_SERVICE_ACCOUNT_TOKEN").is_some() || paths.op_env_file.is_file() {
        return setup_onepassword(paths);
    }

    // Interactive menu when TTY; else print usage.
    if io::IsTerminal::is_terminal(&io::stdin()) && Path::new("/dev/tty").exists() {
        eprintln!("Choose vault backend:");
        eprintln!("  1) bitwarden   (Bitwarden Secrets Manager)");
        eprintln!("  2) onepassword (1Password service account)");
        eprintln!("  3) pass");
        eprintln!("  4) sops");
        eprint!("backend [1-4]: ");
        let _ = io::stderr().flush();
        let mut line = String::new();
        let mut tty = io::BufReader::new(fs::File::open("/dev/tty").map_err(|e| {
            Error::Message(format!("tty: {e}"))
        })?);
        tty.read_line(&mut line)
            .map_err(|e| Error::Message(format!("tty read: {e}")))?;
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
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--purge" => purge = true,
            "--dry-run" => dry = true,
            "-y" | "--yes" => yes = true,
            "-h" | "--help" => {
                println!(
                    "usage: vaulted-agent uninstall [--purge] [--dry-run] [-y|--yes]\n\
                     Removes the launcher and conductor symlinks.\n\
                     Keeps config unless --purge. Never removes op.env / bws.env credentials."
                );
                return Ok(());
            }
            "--link-user" => {
                i += 1; // accepted for parity; ignored in pure binary uninstall
            }
            other => {
                return Err(Error::Message(format!("uninstall: unknown option '{other}'")));
            }
        }
        i += 1;
    }

    let prefix = env::var("VAULTED_AGENT_BIN_DIR").unwrap_or_else(|_| "/usr/local/bin".into());
    let config = env::var("VAULTED_AGENT_CONFIG_DIR").unwrap_or_else(|_| "/etc/vaulted-agent".into());
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
            if name.ends_with("-conductor") {
                if p.is_symlink() {
                    targets.push(p);
                }
            }
        }
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
                backend = args
                    .get(i)
                    .ok_or_else(|| Error::Message("run: --backend needs a name".into()))?
                    .clone();
            }
            s if s.starts_with("--backend=") => {
                backend = s["--backend=".len()..].to_string();
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
        &backend,
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
        let cmd = h
            .as_ref()
            .map(|h| h.command.join(" "))
            .unwrap_or_default();
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
        },
    )
}

/// When service_user is configured (env or defaults.conf) and current uid differs, re-exec via sudo.
pub fn maybe_reexec_service_user(paths: &Paths, argv0: &str, orig_args: &[String]) -> Result<()> {
    let Some(service) = crate::config::load_service_user(paths) else {
        return Ok(());
    };
    if service.is_empty() {
        return Ok(());
    }
    // Who am I?
    let me = Command::new("id")
        .arg("-un")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();
    if me == service {
        return Ok(());
    }
    // Skip re-exec in test handoff / when disabled
    if env::var_os("VAULTED_AGENT_NO_REEXEC").is_some() {
        return Ok(());
    }
    let caller_cwd = env::var("VAULTED_AGENT_CALLER_CWD").unwrap_or_else(|_| {
        env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".into())
    });
    let bin_dir = env::var("VAULTED_AGENT_BIN_DIR").unwrap_or_else(|_| "/usr/local/bin".into());
    let invoked = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("vaulted-agent");
    let launcher = PathBuf::from(&bin_dir).join(invoked);
    let launcher = if launcher.is_file() {
        launcher
    } else {
        PathBuf::from(argv0)
    };

    let mut cmd = Command::new("sudo");
    cmd.arg("-u").arg(&service).arg("env").arg(format!(
        "VAULTED_AGENT_CALLER_CWD={caller_cwd}"
    ));
    if let Ok(c) = env::var("VAULTED_AGENT_CONFIG_DIR") {
        cmd.arg(format!("VAULTED_AGENT_CONFIG_DIR={c}"));
    }
    cmd.arg(&launcher);
    for a in orig_args {
        cmd.arg(a);
    }
    let err = {
        use std::os::unix::process::CommandExt;
        cmd.exec()
    };
    Err(Error::Message(format!("sudo re-exec failed: {err}")))
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
         tests:  VAULTED_AGENT_HANDOFF=spawn to spawn instead of exec",
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
