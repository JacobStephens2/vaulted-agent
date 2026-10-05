//! **Setup interview**: the questions interactive `setup` asks — Auth mode,
//! Service user, Workdir and, when no Backend is named or inferred, Backend.
//!
//! Three steps, in order. The command line is checked first, so a refused
//! invocation fails before any question is asked. The questions are then asked
//! through one line-reading seam ([`LineReader`]: the terminal in production,
//! scripted lines in tests) and the replies collected as data; nothing is
//! written while they are asked. Only then are the answers applied: Machine
//! defaults ([`Answers::apply`]), the Workdir on each Harness the Inventory
//! loads, and — by the caller — Vault wiring and Token capture.
//!
//! Each reply is parsed by a pure function (`*_reply`), which owns the menu's
//! aliases, its default for an empty reply and its fallback for an unknown one.

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

use crate::auth::{self, DoorFacts, TokenKind};
use crate::conf_file::ConfFile;
use crate::config::{set_default, AuthMode, Backend, Paths};
use crate::defaults::Defaults;
use crate::error::{Error, Result};
use crate::inventory::Inventory;
use crate::privilege;
use crate::workdir::{self, CallerContext};

/// The seam the questions are answered through: one reply line per call.
pub(crate) type LineReader<'a> = dyn FnMut() -> Result<String> + 'a;

/// The production [`LineReader`]: one line from the controlling terminal.
pub(crate) fn read_tty_line() -> Result<String> {
    let mut line = String::new();
    let mut tty = io::BufReader::new(
        fs::File::open("/dev/tty").map_err(|e| Error::Message(format!("tty: {e}")))?,
    );
    tty.read_line(&mut line)
        .map_err(|e| Error::Message(format!("tty read: {e}")))?;
    Ok(line)
}

/// Write a question's text; the reply is read next.
fn ask(read: &mut LineReader, text: &str) -> Result<String> {
    eprint!("{text}");
    let _ = io::stderr().flush();
    read()
}

fn note(text: &str) {
    eprintln!("  {text}");
}

// ---------------------------------------------------------------------------
// The command line
// ---------------------------------------------------------------------------

/// `setup`'s command line, checked. Everything it can refuse is refused here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Command {
    /// `--set-token`: the piped-capture / rotation door.
    pub set_token: bool,
    /// `--wire-only`: the installer's door. Vault wiring, then stop before
    /// Token capture, so a machine with no token yet still gets wired.
    pub wire_only: bool,
    /// `setup [bitwarden|onepassword|bws|op|pass|sops]`.
    pub backend: Option<Backend>,
}

impl Command {
    pub(crate) fn parse(args: &[String]) -> Result<Self> {
        let set_token = args.iter().any(|a| a == "--set-token");
        let wire_only = args.iter().any(|a| a == "--wire-only");
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
        let backend = want.map(setup_backend).transpose()?;
        if let Some(be) = backend.filter(|be| set_token && !be.needs_manager_token()) {
            return Err(Error::Message(format!(
                "setup --set-token: {be} has no manager token file \
                 (pass uses GPG, sops uses an age key)"
            )));
        }
        Ok(Self {
            set_token,
            wire_only,
            backend,
        })
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

// ---------------------------------------------------------------------------
// Facts and answers
// ---------------------------------------------------------------------------

/// What the interview reads from the machine before asking anything.
#[derive(Debug, Clone)]
pub(crate) struct Context {
    /// A human can answer a prompt ([`auth::interactive_tty`]).
    pub tty: bool,
    /// Configured Auth mode: the auth-mode menu's default.
    pub auth_mode: AuthMode,
    /// Configured Service user, shown on the run-as menu.
    pub service_user: Option<String>,
    /// The invoking user, for the run-as menu.
    pub me: String,
    /// The Backend setup picks when none is named: Token capture's doors.
    pub auto_backend: Option<Backend>,
}

impl Context {
    pub(crate) fn from_runtime(paths: &Paths) -> Result<Self> {
        let defaults = Defaults::load(paths)?;
        let doors = |kind| DoorFacts::from_runtime(paths, kind);
        Ok(Self {
            tty: auth::interactive_tty(),
            auth_mode: defaults.auth_mode,
            service_user: defaults.service_user,
            me: privilege::current_user(),
            auto_backend: auth::auto_pick(doors(TokenKind::Bws), doors(TokenKind::Op))
                .map(TokenKind::backend),
        })
    }
}

/// The Service user answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServiceUser {
    /// Agents run as the invoking user: `service_user` is removed.
    Unset,
    Set(String),
    /// Leave `service_user` as configured.
    Unchanged,
}

/// The replies to the questions asked at a terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Answers {
    pub auth_mode: AuthMode,
    pub service_user: ServiceUser,
    pub workdir: String,
}

/// Which Backend setup goes on to wire and capture a token for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackendChoice {
    Use(Backend),
    /// An empty reply to the backend menu: skip the vault, keep the rest.
    Skipped,
    /// No terminal, and nothing named or inferred.
    Undecided,
}

/// What the interview settled, before anything is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Interview {
    /// `--wire-only`: no questions, no Context read.
    WireOnly(Backend),
    Setup {
        set_token: bool,
        /// `None` when there is no terminal: nothing was asked.
        answers: Option<Answers>,
        backend: BackendChoice,
    },
}

/// Check the command line, then ask the questions. Writes nothing.
///
/// `context` is read only once the command line passes, and `read` is called
/// only at a terminal.
pub(crate) fn interview(
    args: &[String],
    config_dir: &Path,
    context: impl FnOnce() -> Result<Context>,
    read: &mut LineReader,
) -> Result<Interview> {
    let command = Command::parse(args)?;
    println!("vaulted-agent setup");
    println!("config: {}", config_dir.display());
    if command.wire_only {
        // The installer asks its own questions and then calls this: asking
        // them again here would ask twice. `parse` refuses it unnamed.
        let be = command.backend.expect("--wire-only names a backend");
        return Ok(Interview::WireOnly(be));
    }
    let ctx = context()?;

    // Nothing named or inferred: a piped token has no backend to go with,
    // and guessing would store a credential against the wrong vault.
    let known = command.backend.or(ctx.auto_backend);
    if known.is_none() && command.set_token {
        return Err(Error::Message(
            "setup --set-token: name the backend, e.g.\n  \
             printf %s \"$TOKEN\" | vaulted-agent setup bitwarden --set-token"
                .into(),
        ));
    }

    if !ctx.tty {
        return Ok(Interview::Setup {
            set_token: command.set_token,
            answers: None,
            backend: known.map_or(BackendChoice::Undecided, BackendChoice::Use),
        });
    }

    let answers = Answers {
        auth_mode: ask_auth_mode(ctx.auth_mode, read)?,
        service_user: ask_service_user(&ctx, read)?,
        workdir: ask_workdir(read)?,
    };
    let backend = match known {
        Some(be) => BackendChoice::Use(be),
        None => ask_backend(read)?,
    };
    Ok(Interview::Setup {
        set_token: command.set_token,
        answers: Some(answers),
        backend,
    })
}

// ---------------------------------------------------------------------------
// The questions. `ask_*` asks; `*_reply` parses, purely.
// ---------------------------------------------------------------------------

/// Where a reply leads: an answer (with a note for a fallback), or the
/// menu's follow-up question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step<T> {
    Answer(T, Option<String>),
    FollowUp,
}

/// Auth-mode menu reply. Empty keeps `current`; unknown keeps it with a note.
pub(crate) fn auth_mode_reply(reply: &str, current: AuthMode) -> (AuthMode, Option<String>) {
    match reply.trim() {
        "1" | "file" | "disk" => (AuthMode::File, None),
        "2" | "prompt" | "p" => (AuthMode::Prompt, None),
        "" => (current, None),
        other => (
            current,
            Some(format!(
                "unknown choice '{other}'; keeping {}",
                current.as_str()
            )),
        ),
    }
}

/// How should vault tokens be supplied at launch? Shared by `setup` and
/// bare `auth-mode`.
pub(crate) fn ask_auth_mode(current: AuthMode, read: &mut LineReader) -> Result<AuthMode> {
    let default = current.as_str();
    eprintln!("\nHow should vault tokens be supplied at launch?");
    eprintln!("  1) file    — store once in op.env / bws.env (no prompt each run)");
    eprintln!("  2) prompt  — paste token each launch; nothing stored on disk");
    eprintln!("     (same as always running with -p / --prompt-auth)");
    let reply = ask(read, &format!("choice [1-2, default {default}]: "))?;
    let (mode, fallback) = auth_mode_reply(&reply, current);
    if let Some(n) = fallback {
        note(&n);
    }
    Ok(mode)
}

/// Run-as menu reply. Empty is "you"; unknown leaves `service_user` alone.
pub(crate) fn run_as_reply(reply: &str) -> Step<ServiceUser> {
    match reply.trim() {
        "" | "1" | "you" | "me" => Step::Answer(ServiceUser::Unset, None),
        "2" | "service" | "svc" => Step::FollowUp,
        other => Step::Answer(
            ServiceUser::Unchanged,
            Some(format!(
                "unknown choice '{other}'; leaving service_user unchanged"
            )),
        ),
    }
}

/// Service account name reply. Empty leaves `service_user` alone.
pub(crate) fn service_name_reply(reply: &str) -> (ServiceUser, Option<String>) {
    match reply.trim() {
        "" => (
            ServiceUser::Unchanged,
            Some("empty name; leaving service_user unchanged".into()),
        ),
        name => (ServiceUser::Set(name.to_string()), None),
    }
}

fn ask_service_user(ctx: &Context, read: &mut LineReader) -> Result<ServiceUser> {
    let me_label = if ctx.me.is_empty() { "you" } else { &ctx.me };
    eprintln!("\nRun agents as:");
    eprintln!("  1) you ({me_label})            [default]");
    eprintln!("  2) a dedicated service account");
    if let Some(svc) = &ctx.service_user {
        eprintln!("     (currently service_user = {svc})");
    }
    let (answer, fallback) = match run_as_reply(&ask(read, "choice [1-2, default 1]: ")?) {
        Step::Answer(a, n) => (a, n),
        Step::FollowUp => service_name_reply(&ask(read, "service account name: ")?),
    };
    if let Some(n) = fallback {
        note(&n);
    }
    Ok(answer)
}

/// Workdir menu reply. Empty is `caller`; unknown falls back to `caller`.
pub(crate) fn workdir_reply(reply: &str) -> Step<String> {
    match reply.trim() {
        "" | "1" | "caller" => Step::Answer("caller".into(), None),
        "2" | "fixed" | "absolute" => Step::FollowUp,
        other => Step::Answer(
            "caller".into(),
            Some(format!("unknown choice '{other}'; using workdir = caller")),
        ),
    }
}

/// Fixed-directory reply. Empty falls back to `caller`.
pub(crate) fn workdir_path_reply(reply: &str) -> (String, Option<String>) {
    match reply.trim() {
        "" => (
            "caller".into(),
            Some("empty path; using workdir = caller".into()),
        ),
        path => (path.to_string(), None),
    }
}

fn ask_workdir(read: &mut LineReader) -> Result<String> {
    eprintln!("\nStart agents in:");
    eprintln!("  1) the directory you run the command from   [default]");
    eprintln!("  2) a fixed directory");
    let (workdir, fallback) = match workdir_reply(&ask(read, "choice [1-2, default 1]: ")?) {
        Step::Answer(w, n) => (w, n),
        Step::FollowUp => workdir_path_reply(&ask(read, "absolute path (or $HOME/…): ")?),
    };
    if let Some(n) = fallback {
        note(&n);
    }
    Ok(workdir)
}

/// Backend menu reply. Empty skips the vault; unknown is refused.
pub(crate) fn backend_reply(reply: &str) -> Result<BackendChoice> {
    let be = match reply.trim() {
        "" => return Ok(BackendChoice::Skipped),
        "1" | "bitwarden" | "bws" => Backend::Bitwarden,
        "2" | "onepassword" | "op" | "1password" => Backend::OnePassword,
        "3" | "pass" => Backend::Pass,
        "4" | "sops" => Backend::Sops,
        other => return Err(Error::Message(format!("setup: bad choice '{other}'"))),
    };
    Ok(BackendChoice::Use(be))
}

fn ask_backend(read: &mut LineReader) -> Result<BackendChoice> {
    eprintln!("\nChoose vault backend:");
    eprintln!("  1) bitwarden   (Bitwarden Secrets Manager)");
    eprintln!("  2) onepassword (1Password service account)");
    eprintln!("  3) pass");
    eprintln!("  4) sops");
    backend_reply(&ask(read, "backend [1-4]: ")?)
}

// ---------------------------------------------------------------------------
// Applying the answers
// ---------------------------------------------------------------------------

impl Answers {
    /// Machine defaults (`auth_mode`, `service_user`), then the Workdir on
    /// every Harness the Inventory loads. Vault wiring and Token capture are
    /// the caller's, after this.
    pub(crate) fn apply(&self, paths: &Paths) -> Result<()> {
        set_default(paths, "auth_mode", Some(self.auth_mode.as_str()))?;
        println!("auth_mode: {}", self.auth_mode.as_str());

        let service_user = match &self.service_user {
            ServiceUser::Unset => {
                set_default(paths, "service_user", None)?;
                println!("service_user: (unset — agents run as the invoking user)");
                None
            }
            ServiceUser::Set(name) => {
                set_default(paths, "service_user", Some(name))?;
                println!("service_user = {name}");
                note(
                    "NOTE: with service_user, `va run` is disabled unless allow_run = yes \
                     in defaults.conf.",
                );
                note(&format!(
                    "Token files written by setup will be chowned root:{name} (mode 0640) \
                     when run as root."
                ));
                Some(name.clone())
            }
            ServiceUser::Unchanged => Defaults::load(paths)?.service_user,
        };

        apply_workdir(paths, &self.workdir)?;
        if self.workdir == "caller" {
            if let Some(svc) = service_user.filter(|s| !s.is_empty()) {
                note(&workdir::setup_note(&svc, &CallerContext::from_env()));
            }
        }
        Ok(())
    }
}

/// Set `workdir` on every Harness the Inventory loads, through the Conf file
/// module. A conf that will not load is listed and left alone: reading a
/// missing conf yields an empty one, so editing it would replace a dangling
/// symlink with a one-line file.
fn apply_workdir(paths: &Paths, workdir: &str) -> Result<()> {
    let inventory = Inventory::load(paths)?;
    let mut set = 0;
    let mut left = Vec::new();
    for entry in inventory.harnesses() {
        if let Err(e) = &entry.loaded {
            left.push(format!("left {}.conf (unreadable: {e})", entry.name));
            continue;
        }
        let mut conf = ConfFile::read(&entry.conf)?;
        conf.set("workdir", workdir)?;
        conf.write(&entry.conf)?;
        set += 1;
    }
    if set == 0 && left.is_empty() {
        println!(
            "workdir = {workdir} (no harness confs yet — new harnesses should set this; \
             install auto-harness uses caller)"
        );
    } else {
        println!("workdir = {workdir} on {set} harness conf(s)");
    }
    for line in &left {
        println!("  {line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn context() -> Context {
        Context {
            tty: true,
            auth_mode: AuthMode::File,
            service_user: None,
            me: "jacob".into(),
            auto_backend: None,
        }
    }

    /// A [`LineReader`] answering with `lines`, in order. Running out is a
    /// test failure: the interview asked a question the script did not expect.
    fn scripted(lines: &[&str]) -> impl FnMut() -> Result<String> {
        let mut lines: VecDeque<String> = lines.iter().map(|l| format!("{l}\n")).collect();
        move || {
            Ok(lines
                .pop_front()
                .expect("interview asked one question too many"))
        }
    }

    fn never() -> impl FnMut() -> Result<String> {
        || panic!("the reader was called")
    }

    fn run(argv: &[&str], ctx: Context, lines: &[&str]) -> Result<Interview> {
        interview(
            &args(argv),
            Path::new("/cfg"),
            || Ok(ctx),
            &mut scripted(lines),
        )
    }

    // --- the command line ---------------------------------------------------

    #[test]
    fn a_bad_command_line_never_reads_context_or_calls_the_reader() {
        for argv in [
            &["frobnicate"][..],
            &["pass", "--set-token"],
            &["sops", "--set-token"],
            &["--wire-only"],
            &["bitwarden", "--wire-only", "--set-token"],
            &["plainfile"],
        ] {
            let err = interview(
                &args(argv),
                Path::new("/cfg"),
                || panic!("context was read for {argv:?}"),
                &mut never(),
            )
            .unwrap_err();
            assert!(!err.to_string().is_empty(), "{argv:?}");
        }
    }

    #[test]
    fn command_line_messages_are_todays() {
        let msg = |a: &[&str]| Command::parse(&args(a)).unwrap_err().to_string();
        assert!(msg(&["frobnicate"]).contains("unknown backend 'frobnicate'"));
        assert!(msg(&["pass", "--set-token"]).contains("pass has no manager token file"));
        assert!(msg(&["--wire-only"]).contains("name the backend"));
        assert!(msg(&["op", "--wire-only", "--set-token"]).contains("cannot be used with"));
    }

    #[test]
    fn command_line_accepts_aliases() {
        let cmd = Command::parse(&args(&["op", "--set-token"])).unwrap();
        assert_eq!(
            cmd,
            Command {
                set_token: true,
                wire_only: false,
                backend: Some(Backend::OnePassword),
            }
        );
    }

    #[test]
    fn wire_only_asks_nothing() {
        let got = interview(
            &args(&["bws", "--wire-only"]),
            Path::new("/cfg"),
            || panic!("context was read"),
            &mut never(),
        )
        .unwrap();
        assert_eq!(got, Interview::WireOnly(Backend::Bitwarden));
    }

    #[test]
    fn set_token_with_nothing_to_infer_fails_before_any_question() {
        let err = interview(
            &args(&["--set-token"]),
            Path::new("/cfg"),
            || Ok(context()),
            &mut never(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("name the backend"), "{err}");
    }

    // --- whole interviews ---------------------------------------------------

    #[test]
    fn an_interactive_setup_collects_every_answer() {
        let got = run(
            &[],
            context(),
            &["prompt", "2", "svc-agent", "fixed", "/srv/work", "op"],
        )
        .unwrap();
        assert_eq!(
            got,
            Interview::Setup {
                set_token: false,
                answers: Some(Answers {
                    auth_mode: AuthMode::Prompt,
                    service_user: ServiceUser::Set("svc-agent".into()),
                    workdir: "/srv/work".into(),
                }),
                backend: BackendChoice::Use(Backend::OnePassword),
            }
        );
    }

    #[test]
    fn empty_replies_take_every_default_and_skip_the_vault() {
        let got = run(&[], context(), &["", "", "", ""]).unwrap();
        assert_eq!(
            got,
            Interview::Setup {
                set_token: false,
                answers: Some(Answers {
                    auth_mode: AuthMode::File,
                    service_user: ServiceUser::Unset,
                    workdir: "caller".into(),
                }),
                backend: BackendChoice::Skipped,
            }
        );
    }

    #[test]
    fn a_named_or_inferred_backend_skips_the_menu() {
        for (argv, auto) in [(&["pass"][..], None), (&[][..], Some(Backend::Pass))] {
            let ctx = Context {
                auto_backend: auto,
                ..context()
            };
            let Interview::Setup { backend, .. } = run(argv, ctx, &["", "", ""]).unwrap() else {
                panic!("not a setup");
            };
            assert_eq!(backend, BackendChoice::Use(Backend::Pass));
        }
    }

    #[test]
    fn a_bad_backend_reply_fails_the_interview() {
        let err = run(&[], context(), &["", "", "", "frob"]).unwrap_err();
        assert_eq!(err.to_string(), "setup: bad choice 'frob'");
    }

    #[test]
    fn no_terminal_asks_nothing() {
        let ctx = Context {
            tty: false,
            auto_backend: Some(Backend::Bitwarden),
            ..context()
        };
        let got = interview(&[], Path::new("/cfg"), || Ok(ctx.clone()), &mut never()).unwrap();
        assert_eq!(
            got,
            Interview::Setup {
                set_token: false,
                answers: None,
                backend: BackendChoice::Use(Backend::Bitwarden),
            }
        );
        let ctx = Context {
            auto_backend: None,
            ..ctx
        };
        let got = interview(&[], Path::new("/cfg"), || Ok(ctx), &mut never()).unwrap();
        assert!(matches!(
            got,
            Interview::Setup {
                backend: BackendChoice::Undecided,
                ..
            }
        ));
    }

    // --- one menu at a time -------------------------------------------------

    #[test]
    fn auth_mode_menu() {
        for (reply, want) in [
            ("1", AuthMode::File),
            ("file", AuthMode::File),
            ("disk", AuthMode::File),
            ("2", AuthMode::Prompt),
            ("prompt", AuthMode::Prompt),
            ("p", AuthMode::Prompt),
            ("  file  ", AuthMode::File),
        ] {
            assert_eq!(auth_mode_reply(reply, AuthMode::File).0, want, "{reply}");
            assert_eq!(auth_mode_reply(reply, AuthMode::Prompt).0, want, "{reply}");
        }
        assert_eq!(
            auth_mode_reply("  ", AuthMode::Prompt),
            (AuthMode::Prompt, None)
        );
        assert_eq!(
            auth_mode_reply("x", AuthMode::File),
            (
                AuthMode::File,
                Some("unknown choice 'x'; keeping file".into())
            )
        );
    }

    #[test]
    fn run_as_menu() {
        for reply in ["", "1", "you", "me"] {
            assert_eq!(
                run_as_reply(reply),
                Step::Answer(ServiceUser::Unset, None),
                "{reply}"
            );
        }
        for reply in ["2", "service", "svc"] {
            assert_eq!(run_as_reply(reply), Step::FollowUp, "{reply}");
        }
        assert_eq!(
            run_as_reply("root"),
            Step::Answer(
                ServiceUser::Unchanged,
                Some("unknown choice 'root'; leaving service_user unchanged".into())
            )
        );
        assert_eq!(
            service_name_reply(" agent \n"),
            (ServiceUser::Set("agent".into()), None)
        );
        assert_eq!(
            service_name_reply(""),
            (
                ServiceUser::Unchanged,
                Some("empty name; leaving service_user unchanged".into())
            )
        );
    }

    #[test]
    fn workdir_menu() {
        for reply in ["", "1", "caller"] {
            assert_eq!(
                workdir_reply(reply),
                Step::Answer("caller".into(), None),
                "{reply}"
            );
        }
        for reply in ["2", "fixed", "absolute"] {
            assert_eq!(workdir_reply(reply), Step::FollowUp, "{reply}");
        }
        assert_eq!(
            workdir_reply("3"),
            Step::Answer(
                "caller".into(),
                Some("unknown choice '3'; using workdir = caller".into())
            )
        );
        assert_eq!(
            workdir_path_reply("$HOME/src\n"),
            ("$HOME/src".into(), None)
        );
        assert_eq!(
            workdir_path_reply(""),
            (
                "caller".into(),
                Some("empty path; using workdir = caller".into())
            )
        );
    }

    #[test]
    fn backend_menu() {
        for (replies, want) in [
            (["1", "bitwarden", "bws", "bws"], Backend::Bitwarden),
            (
                ["2", "onepassword", "op", "1password"],
                Backend::OnePassword,
            ),
            (["3", "pass", "pass", "pass"], Backend::Pass),
            (["4", "sops", "sops", "sops"], Backend::Sops),
        ] {
            for reply in replies {
                assert_eq!(
                    backend_reply(reply).unwrap(),
                    BackendChoice::Use(want),
                    "{reply}"
                );
            }
        }
        assert_eq!(backend_reply(" ").unwrap(), BackendChoice::Skipped);
        assert!(backend_reply("plainfile").is_err());
    }

    // --- applying -----------------------------------------------------------

    #[test]
    fn workdir_goes_only_to_harnesses_that_load() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        fs::create_dir_all(&paths.harness_dir).unwrap();
        fs::write(
            paths.harness_conf("claude"),
            "# shipped\nmanifest = empty.env\nworkdir  = /old\ncommand  = claude\n",
        )
        .unwrap();
        fs::write(
            paths.harness_conf("codex"),
            "manifest = empty.env\ncommand = codex\n",
        )
        .unwrap();
        symlink(tmp.path().join("gone.conf"), paths.harness_conf("dangling")).unwrap();
        fs::create_dir(paths.harness_conf("dir")).unwrap();
        fs::write(paths.harness_dir.join("notes.txt"), "workdir = untouched\n").unwrap();

        apply_workdir(&paths, "caller").unwrap();

        assert_eq!(
            fs::read_to_string(paths.harness_conf("claude")).unwrap(),
            "# shipped\nmanifest = empty.env\nworkdir  = caller\ncommand  = claude\n"
        );
        assert_eq!(
            fs::read_to_string(paths.harness_conf("codex")).unwrap(),
            "manifest = empty.env\ncommand = codex\nworkdir = caller\n"
        );
        let dangling = paths.harness_conf("dangling");
        assert!(dangling.is_symlink() && !dangling.exists());
        assert!(!tmp.path().join("gone.conf").exists());
        assert!(paths.harness_conf("dir").is_dir());
        assert_eq!(
            fs::read_to_string(paths.harness_dir.join("notes.txt")).unwrap(),
            "workdir = untouched\n"
        );
    }

    #[test]
    fn workdir_without_a_harness_directory_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        apply_workdir(&paths, "caller").unwrap();
        assert!(!paths.harness_dir.exists());
    }

    #[test]
    fn answers_apply_machine_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        fs::write(&paths.defaults_file, "service_user = old\nallow_run = no\n").unwrap();
        Answers {
            auth_mode: AuthMode::Prompt,
            service_user: ServiceUser::Unset,
            workdir: "caller".into(),
        }
        .apply(&paths)
        .unwrap();
        assert_eq!(
            fs::read_to_string(&paths.defaults_file).unwrap(),
            "allow_run = no\nauth_mode = prompt\n"
        );
    }
}
