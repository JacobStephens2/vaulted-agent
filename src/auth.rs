//! Load vault manager tokens from env, file, or TTY prompt (the Token source).

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::config::{self, AuthMode, Paths};
use crate::error::{Error, Result};
use crate::file_replace::{self, Perms};
use crate::privilege;
use crate::secret::ManagerToken;

/// Whether a vault token file can be read by this process.
///
/// `Path::is_file()` collapses `ENOENT` and `EACCES` into `false`, so a
/// permission-denied token file used to look identical to a missing one
/// (issue #51). These three states keep that distinction.
#[derive(Debug)]
pub(crate) enum TokenFileStatus {
    Present,
    Missing,
    Unreadable { source: io::Error },
}

/// Classify a token path without treating permission errors as absence.
pub(crate) fn token_file_status(path: &Path) -> TokenFileStatus {
    match fs::metadata(path) {
        Ok(m) if !m.is_file() => TokenFileStatus::Missing,
        Ok(_) => {
            // Stat can succeed while open fails (directory is traversable but
            // the file mode forbids this user). Confirm open, not just type.
            match fs::File::open(path) {
                Ok(_) => TokenFileStatus::Present,
                Err(e) if e.kind() == io::ErrorKind::NotFound => TokenFileStatus::Missing,
                Err(e) => TokenFileStatus::Unreadable { source: e },
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => TokenFileStatus::Missing,
        Err(e) => TokenFileStatus::Unreadable { source: e },
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TokenKind {
    Bws,
    Op,
}

impl TokenKind {
    pub fn env_var(self) -> &'static str {
        match self {
            Self::Bws => "BWS_ACCESS_TOKEN",
            Self::Op => "OP_SERVICE_ACCOUNT_TOKEN",
        }
    }

    pub fn file(self, paths: &Paths) -> &Path {
        match self {
            Self::Bws => &paths.bws_env_file,
            Self::Op => &paths.op_env_file,
        }
    }

    pub fn prompt_label(self) -> &'static str {
        match self {
            Self::Bws => {
                "Bitwarden Secrets Manager access token (Machine Accounts → Access Tokens; not your vault password)"
            }
            Self::Op => "1Password service-account token (OP_SERVICE_ACCOUNT_TOKEN)",
        }
    }

    /// The `setup` subcommand that configures this token's backend.
    pub fn backend_name(self) -> &'static str {
        match self {
            Self::Bws => "bitwarden",
            Self::Op => "onepassword",
        }
    }

    /// Vault console the operator gets the token from. Printed, never opened:
    /// setup runs under sudo on servers, where a browser is the wrong move.
    pub fn console_url(self) -> &'static str {
        match self {
            // Self-hosted and regional tenants have their own host; the path
            // after it is the same everywhere.
            Self::Bws => {
                "https://vault.bitwarden.com/#/sm (or your region's vault host) \
                          → Machine accounts → Access tokens"
            }
            Self::Op => {
                "https://my.1password.com/developer-tools/infrastructure-secrets/serviceaccount"
            }
        }
    }

    /// Catch a master-password / login-API-key paste before it reaches the
    /// vault. `None` means the shape is plausible — not that the token is valid.
    pub(crate) fn shape_problem(self, token: &str) -> Option<String> {
        if token.chars().any(char::is_whitespace) {
            return Some("contains whitespace — vault tokens do not".to_string());
        }
        match self {
            Self::Bws => {
                if token.starts_with("user.") || token.starts_with("organization.") {
                    return Some(
                        "that is a Bitwarden login API key client_id, not a Secrets Manager \
                         access token"
                            .to_string(),
                    );
                }
                if !token.starts_with("0.") {
                    return Some(
                        "Secrets Manager access tokens start with `0.` — this looks like a master \
                         password or a login API key"
                            .to_string(),
                    );
                }
                if !token.contains(':') {
                    return Some(
                        "missing the `:` separator — expected 0.<client-id>.<client-secret>:<key>"
                            .to_string(),
                    );
                }
                None
            }
            Self::Op => {
                if !token.starts_with("ops_") {
                    return Some(
                        "service-account tokens start with `ops_` — this looks like an account \
                         password or a session token"
                            .to_string(),
                    );
                }
                None
            }
        }
    }
}

fn read_token_file(path: &Path, key: &str) -> Result<Option<ManagerToken>> {
    match fs::metadata(path) {
        Ok(m) if !m.is_file() => return Ok(None),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        // EACCES / other failures: do not collapse into "missing".
        Err(e) => {
            return Err(Error::Io {
                path: path.to_path_buf(),
                source: e,
            })
        }
    }
    let text = fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    // Shared dotenv policy with validate/resolve (quotes stripped).
    Ok(crate::config::parse_dotenv_var(&text, key)?.map(ManagerToken::new))
}

/// Turn a token-file IO failure into a message that names the effective user
/// and, when relevant, points at a missing `service_user` hop.
fn token_file_unreadable(paths: &Paths, path: &Path, source: io::Error) -> Error {
    let who = privilege::current_user();
    let who = if who.is_empty() {
        "this process".to_string()
    } else {
        format!("`{who}`")
    };
    let mut msg = format!(
        "cannot read {} as {who} ({source})\n  \
         Token files are often root:<service_user> mode 0640 so only that account can read them.",
        path.display()
    );
    match config::load_service_user(paths) {
        None => msg.push_str(
            "\n  No service_user in defaults.conf — the launcher never re-execs as the account \
             that can read this file.\n  \
             Fix: set `service_user = <account>` in defaults.conf, or grant this user group read.",
        ),
        Some(svc) => msg.push_str(&format!(
            "\n  service_user={svc} is configured; if this process is not that account, the \
             privilege hop did not run (check sudoers / VAULTED_AGENT_NO_REEXEC)."
        )),
    }
    Error::Message(msg)
}

/// True when this process can actually run an interactive paste: stdin is a
/// terminal (that is where the no-echo read happens) *and* /dev/tty opens (that
/// is where the prompt is written). install.sh's `can_prompt_user`, in Rust.
///
/// Both halves matter. Under `cmd | vaulted-agent setup` stdin is a pipe, so a
/// "paste it now" prompt would read the pipe instead of the operator.
fn interactive_tty() -> bool {
    io::IsTerminal::is_terminal(&io::stdin()) && tty_usable()
}

/// True when /dev/tty can actually be opened (not merely present on the filesystem).
fn tty_usable() -> bool {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
}

fn prompt_token(kind: TokenKind) -> Result<ManagerToken> {
    // Prefer /dev/tty so prompts work when stdout is piped (bash parity).
    // Gate on open(), not Path::exists() — exists is true on every Unix even
    // without a controlling terminal (ticket #10 / story #48 guidance path).
    if !tty_usable() {
        return Err(Error::Message(format!(
            "auth_mode=prompt needs a terminal (or export {})\n  For agent→agent launches: auth-mode file + token file, or export {}",
            kind.env_var(),
            kind.env_var()
        )));
    }
    if let Ok(mut tty) = fs::OpenOptions::new().write(true).open("/dev/tty") {
        writeln!(
            tty,
            "{}\n(hidden, not written to disk): ",
            kind.prompt_label()
        )
        .map_err(|e| Error::Message(format!("tty write: {e}")))?;
        tty.flush().ok();
    }
    // No-echo read (bash `read -rs` parity). rpassword uses termios when available.
    let token = rpassword::read_password().map_err(|e| {
        Error::Message(format!(
            "could not read {} from terminal: {e}\n  export {} or write token file",
            kind.env_var(),
            kind.env_var()
        ))
    })?;
    let token = token.trim().to_string();
    if token.is_empty() {
        return Err(Error::Message(format!("empty {}", kind.env_var())));
    }
    Ok(ManagerToken::new(token))
}

// ---------------------------------------------------------------------------
// Token capture (issue #77)
//
// `setup`-only path that obtains a manager token, verifies it against the
// backend, then writes the token file. Deliberately not reachable from
// `TokenSource::load`: that runs on the launch path, which stays small and
// auditable and must never gain a credential-writing mode.
// ---------------------------------------------------------------------------

/// Token-file state as the capture decision sees it: comparable, no io::Error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenFile {
    /// Readable and carries a value for this key.
    Present,
    /// Absent, or readable but carrying no value for this key.
    Missing,
    /// Exists but cannot be read (invariant 6).
    Unreadable,
}

/// What `setup` should do about the manager token. Pure decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CaptureDecision {
    /// Ask on the terminal (no echo) and store what is pasted.
    Prompt,
    /// Read the token from stdin (`--set-token`).
    Stdin,
    /// A token is already available, or this mode stores nothing: do not
    /// capture, let the caller load the token the usual way.
    UseExisting,
    /// Capture cannot run here; the message says why.
    Fail(String),
}

/// Facts the capture decision is made from. All injectable; no IO in the plan.
#[derive(Debug, Clone)]
pub(crate) struct CaptureFacts {
    pub kind: TokenKind,
    pub file: TokenFile,
    /// The token's env var is exported and non-empty.
    pub env_token: bool,
    pub mode: AuthMode,
    /// A terminal is available for a no-echo paste.
    pub tty: bool,
    /// `--set-token` was passed to `setup`.
    pub set_token: bool,
    /// Token-file path, for message text only.
    pub token_path: String,
    /// Effective user, for the unreadable-file message.
    pub current_user: String,
}

impl CaptureFacts {
    /// Gather the facts from the running process. The only IO in capture
    /// planning; `plan_token_capture` itself stays pure.
    pub(crate) fn from_runtime(
        paths: &Paths,
        kind: TokenKind,
        mode: AuthMode,
        set_token: bool,
    ) -> Self {
        let path = kind.file(paths);
        let file = match token_file_status(path) {
            TokenFileStatus::Missing => TokenFile::Missing,
            TokenFileStatus::Unreadable { .. } => TokenFile::Unreadable,
            // A file that opens but holds no value for this key is nothing to
            // defer to — treat it as missing so setup captures instead of
            // handing the operator the launch-time prompt.
            TokenFileStatus::Present => match read_token_file(path, kind.env_var()) {
                Ok(Some(t)) if !t.expose().is_empty() => TokenFile::Present,
                Ok(_) => TokenFile::Missing,
                Err(_) => TokenFile::Unreadable,
            },
        };
        Self {
            kind,
            file,
            env_token: std::env::var(kind.env_var())
                .map(|v| !v.is_empty())
                .unwrap_or(false),
            mode,
            tty: interactive_tty(),
            set_token,
            token_path: path.display().to_string(),
            current_user: privilege::current_user(),
        }
    }
}

/// Pure planning: no IO, no prompts, no process spawn.
pub(crate) fn plan_token_capture(facts: &CaptureFacts) -> CaptureDecision {
    let key = facts.kind.env_var();

    // auth_mode=prompt stores nothing on disk, so there is nothing to capture.
    if facts.mode != AuthMode::File {
        if facts.set_token {
            return CaptureDecision::Fail(format!(
                "--set-token stores {key} in {}, but auth_mode=prompt\n  \
                 Store tokens on disk first: vaulted-agent auth-mode file",
                facts.token_path
            ));
        }
        return CaptureDecision::UseExisting;
    }

    // Invariant 6 / issue #51: an existing token file this process cannot read
    // is a permissions fault. Capturing over it would clobber a working
    // credential and hide the fault, so it is never an invitation to paste.
    if facts.file == TokenFile::Unreadable {
        let who = if facts.current_user.is_empty() {
            "this process".to_string()
        } else {
            format!("`{}`", facts.current_user)
        };
        return CaptureDecision::Fail(format!(
            "{} exists but cannot be read as {who}\n  \
             setup will not overwrite a token file it cannot read — that would clobber a working \
             credential and hide the permissions fault.\n  \
             Token files are often root:<service_user> mode 0640; fix ownership/mode, then re-run.",
            facts.token_path
        ));
    }

    // The rotation door. An explicit argument beats ambient env: without this,
    // rotating while an old token is still exported would store the stale value.
    if facts.set_token {
        // Reading stdin here would block on a terminal until the operator
        // found ^D, looking like a hang. Say what to do instead.
        if facts.tty {
            return CaptureDecision::Fail(format!(
                "--set-token reads the token from stdin, but stdin is a terminal\n  \
                 pipe it:  printf %s \"$TOKEN\" | vaulted-agent setup {backend} --set-token\n  \
                 or drop --set-token to paste it interactively",
                backend = facts.kind.backend_name(),
            ));
        }
        return CaptureDecision::Stdin;
    }

    if facts.env_token || facts.file == TokenFile::Present {
        return CaptureDecision::UseExisting;
    }

    if facts.tty {
        return CaptureDecision::Prompt;
    }

    CaptureDecision::Fail(format!(
        "no manager token yet and no terminal to paste one\n  \
         pipe it:   printf %s \"$TOKEN\" | vaulted-agent setup {backend} --set-token\n  \
         or export: {key}\n  \
         or paste each launch: vaulted-agent auth-mode prompt",
        backend = facts.kind.backend_name(),
    ))
}

/// Normalize a token arriving on stdin under `--set-token`.
///
/// Accepts the two shapes an operator actually pipes: the bare token, and the
/// `KEY=token` line copied straight out of a token file. Anything else is
/// rejected rather than stored, because a wrong value here is written to disk.
pub(crate) fn normalize_piped_token(kind: TokenKind, raw: &str) -> Result<String> {
    let key = kind.env_var();
    let trimmed = raw.trim();
    let body = trimmed.strip_prefix(&format!("{key}=")).unwrap_or(trimmed);
    let body = body.trim();
    if body.is_empty() {
        // Nobody pipes by accident: empty is an error here, not a skip.
        return Err(Error::Message(format!(
            "--set-token: empty {key} on stdin (nothing written)"
        )));
    }
    if body.contains('\n') || body.contains('\r') {
        return Err(Error::Message(format!(
            "--set-token: stdin holds more than one line; pipe only the {key} value"
        )));
    }
    if body.contains('=') {
        return Err(Error::Message(format!(
            "--set-token: stdin holds `=`; pipe the bare token or a single `{key}=…` line"
        )));
    }
    Ok(body.to_string())
}

/// Outcome of `capture_token`.
///
/// Three-way rather than `Option`: a declined prompt ("write it later") must
/// not be confused with "a token already exists", or the caller would fall
/// through and prompt the operator a second time.
pub(crate) enum Capture {
    /// Captured, verified against the backend, and written to the token file.
    Token(ManagerToken),
    /// No capture: the caller loads the token the usual way.
    UseExisting,
    /// Operator declined at the prompt; nothing was written.
    Skipped,
}

fn tty_write(line: &str) {
    if let Ok(mut tty) = fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = writeln!(tty, "{line}");
        let _ = tty.flush();
    }
}

fn store_captured(paths: &Paths, kind: TokenKind, token: &ManagerToken) -> Result<()> {
    let path = kind.file(paths).to_path_buf();
    let svc = config::load_service_user(paths);
    write_token_file(&path, kind.env_var(), token, svc.as_deref())?;
    println!("wrote {} (0640)", path.display());
    Ok(())
}

/// `setup`-only token capture. Never called from the launch path.
///
/// `verify` is the backend liveness check (`bws secret list` / `op whoami`);
/// an invalid token never lands on disk.
pub(crate) fn capture_token(
    paths: &Paths,
    kind: TokenKind,
    mode: AuthMode,
    set_token: bool,
    verify: &dyn Fn(&ManagerToken) -> Result<()>,
) -> Result<Capture> {
    let facts = CaptureFacts::from_runtime(paths, kind, mode, set_token);
    match plan_token_capture(&facts) {
        CaptureDecision::UseExisting => Ok(Capture::UseExisting),
        CaptureDecision::Fail(msg) => Err(Error::Message(msg)),
        CaptureDecision::Stdin => capture_from_stdin(paths, kind, verify),
        CaptureDecision::Prompt => capture_from_prompt(paths, kind, verify),
    }
}

/// Verify a candidate against the backend, then store it. Shared by both
/// capture doors so "an invalid token never lands on disk" has one home.
/// `Err` carries why the vault refused it; nothing is written in that case.
fn verify_and_store(
    paths: &Paths,
    kind: TokenKind,
    value: String,
    verify: &dyn Fn(&ManagerToken) -> Result<()>,
) -> Result<ManagerToken> {
    let token = ManagerToken::new(value);
    verify(&token)?;
    store_captured(paths, kind, &token)?;
    Ok(token)
}

fn capture_from_stdin(
    paths: &Paths,
    kind: TokenKind,
    verify: &dyn Fn(&ManagerToken) -> Result<()>,
) -> Result<Capture> {
    use std::io::Read as _;
    let mut raw = String::new();
    io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| Error::Message(format!("--set-token: reading stdin: {e}")))?;
    let value = normalize_piped_token(kind, &raw)?;
    // No shape check here. A pipe is deliberate and often a rotation, and the
    // live verify below is the authority on whether the token works — a
    // heuristic that has not caught up with a new token format must not be
    // what blocks it. Verify before write: no re-prompt, just a non-zero exit.
    let token = verify_and_store(paths, kind, value, verify).map_err(|e| {
        Error::Message(format!(
            "--set-token: {} rejected by the vault (nothing written)\n  {e}",
            kind.env_var()
        ))
    })?;
    Ok(Capture::Token(token))
}

fn capture_from_prompt(
    paths: &Paths,
    kind: TokenKind,
    verify: &dyn Fn(&ManagerToken) -> Result<()>,
) -> Result<Capture> {
    tty_write(&format!("\nGet it at: {}", kind.console_url()));
    // Two attempts: one paste, one correction.
    for attempt in 0..2 {
        tty_write(&format!(
            "{}\n(hidden; will be written to {}, empty to skip): ",
            kind.prompt_label(),
            kind.file(paths).display()
        ));
        let raw = rpassword::read_password().map_err(|e| {
            Error::Message(format!(
                "could not read {} from terminal: {e}\n  export {} or write the token file",
                kind.env_var(),
                kind.env_var()
            ))
        })?;
        let value = raw.trim().to_string();
        if value.is_empty() {
            // install.sh parity: an empty paste is a deliberate skip.
            println!(
                "no token provided; write {} later, or: vaulted-agent auth-mode prompt",
                kind.file(paths).display()
            );
            return Ok(Capture::Skipped);
        }
        // Shape first, so a master password or a login API key is named for
        // what it is instead of coming back as an opaque vault rejection.
        let problem = match kind.shape_problem(&value) {
            Some(problem) => problem,
            None => match verify_and_store(paths, kind, value, verify) {
                Ok(token) => return Ok(Capture::Token(token)),
                Err(e) => format!("the vault rejected it ({e})"),
            },
        };
        if attempt == 0 {
            eprintln!("vaulted-agent: {problem} — try again (nothing written).");
        } else {
            return Err(Error::Message(format!(
                "{}: {problem} (nothing written)",
                kind.env_var()
            )));
        }
    }
    unreachable!("prompt loop returns on every path")
}

// ---------------------------------------------------------------------------
// Token source (issue #124)
//
// How one invocation obtains a manager token, settled once from the
// environment, the `-p` flag and the configured auth mode. The decision is a
// pure function of those inputs; `TokenSource::from_env` is the only place that
// reads `VAULTED_AGENT_AUTH_MODE` / `VAULTED_AGENT_PROMPT_AUTH`.
// ---------------------------------------------------------------------------

/// Where `TokenSource::load` takes the token from. Pure output of `route`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenRoute {
    /// The manager-token env var is exported: it wins over everything.
    Env,
    /// Forced (`-p`, `VAULTED_AGENT_PROMPT_AUTH=1`) or auth mode `prompt`.
    Prompt,
    /// The token file, else a one-shot TTY prompt when the file is missing.
    File,
}

/// How this invocation obtains a Manager token. Built once per invocation at
/// the entry point and handed to every command that loads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenSource {
    mode: AuthMode,
    force_prompt: bool,
}

impl TokenSource {
    /// The pure precedence step. `env_mode` is `VAULTED_AGENT_AUTH_MODE`,
    /// `env_prompt` is `VAULTED_AGENT_PROMPT_AUTH`, `prompt_flag` is `-p` /
    /// `--prompt-auth`, and `configured` is the auth mode in `defaults.conf`.
    pub fn decide(
        env_mode: Option<&str>,
        env_prompt: Option<&str>,
        prompt_flag: bool,
        configured: AuthMode,
    ) -> Self {
        let mode = match env_mode {
            Some("prompt") => AuthMode::Prompt,
            Some("file") => AuthMode::File,
            _ => configured,
        };
        Self {
            mode,
            force_prompt: prompt_flag || env_prompt == Some("1"),
        }
    }

    /// Thin adapter: read the real environment and `defaults.conf`.
    pub fn from_env(paths: &Paths, prompt_flag: bool) -> Self {
        let env_mode = std::env::var("VAULTED_AGENT_AUTH_MODE").ok();
        let env_prompt = std::env::var("VAULTED_AGENT_PROMPT_AUTH").ok();
        Self::decide(
            env_mode.as_deref(),
            env_prompt.as_deref(),
            prompt_flag,
            config::load_auth_mode(paths),
        )
    }

    /// The same prompt forcing under an auth mode `setup` just had the
    /// operator choose.
    pub fn with_auth_mode(self, mode: AuthMode) -> Self {
        Self { mode, ..self }
    }

    /// Effective auth mode for this invocation (env override, else config).
    pub fn auth_mode(&self) -> AuthMode {
        self.mode
    }

    /// Pure: where the token comes from, given whether its env var is set.
    pub(crate) fn route(&self, env_token: bool) -> TokenRoute {
        if env_token {
            TokenRoute::Env
        } else if self.force_prompt || self.mode == AuthMode::Prompt {
            TokenRoute::Prompt
        } else {
            TokenRoute::File
        }
    }

    /// Load a manager token of `kind` along this invocation's route.
    pub fn load(&self, paths: &Paths, kind: TokenKind) -> Result<ManagerToken> {
        let key = kind.env_var();
        let env_token = std::env::var(key).unwrap_or_default();
        match self.route(!env_token.is_empty()) {
            TokenRoute::Env => Ok(ManagerToken::new(env_token)),
            TokenRoute::Prompt => prompt_token(kind),
            TokenRoute::File => load_from_file(paths, kind),
        }
    }
}

/// The Manager tokens one invocation has loaded, each kind at most once.
///
/// A failed load is kept too, as its message: an empty prompt or an
/// unreadable token file is reported again on every later use, never
/// re-prompted, so one run asks the operator once (invariant 6 still holds).
/// The tokens drop with the cache.
pub(crate) struct TokenCache<'a> {
    load: Box<dyn FnMut(TokenKind) -> Result<ManagerToken> + 'a>,
    bws: Option<std::result::Result<ManagerToken, String>>,
    op: Option<std::result::Result<ManagerToken, String>>,
}

impl<'a> TokenCache<'a> {
    /// Loads along `source`'s route on first use of each kind.
    pub(crate) fn new(paths: &'a Paths, source: TokenSource) -> Self {
        Self::with_loader(move |kind| source.load(paths, kind))
    }

    /// The loader seam, so tests can count loads.
    pub(crate) fn with_loader(load: impl FnMut(TokenKind) -> Result<ManagerToken> + 'a) -> Self {
        Self {
            load: Box::new(load),
            bws: None,
            op: None,
        }
    }

    /// The token of `kind`, loading it on first use. The first failure is
    /// returned as it was raised; later uses repeat its message.
    pub(crate) fn get(&mut self, kind: TokenKind) -> Result<&ManagerToken> {
        let slot = match kind {
            TokenKind::Bws => &mut self.bws,
            TokenKind::Op => &mut self.op,
        };
        if slot.is_none() {
            match (self.load)(kind) {
                Ok(token) => *slot = Some(Ok(token)),
                Err(e) => {
                    *slot = Some(Err(e.to_string()));
                    return Err(e);
                }
            }
        }
        match slot {
            Some(Ok(token)) => Ok(token),
            Some(Err(message)) => Err(Error::Message(message.clone())),
            None => unreachable!("filled above"),
        }
    }
}

/// The token file, else a one-shot TTY prompt when the file is missing.
fn load_from_file(paths: &Paths, kind: TokenKind) -> Result<ManagerToken> {
    let key = kind.env_var();
    let path = kind.file(paths);
    match read_token_file(path, key) {
        Ok(Some(t)) => return Ok(t),
        Ok(None) => {}
        // Unreadable is not missing: fail closed instead of prompting for a
        // paste of the vault service-account token (issue #51).
        Err(Error::Io { path, source }) => {
            return Err(token_file_unreadable(paths, &path, source));
        }
        Err(e) => return Err(e),
    }

    // One-shot prompt if TTY available (match bash behavior when file missing)
    if tty_usable() {
        eprintln!(
            "vaulted-agent: {} missing {}",
            kind.backend_name(),
            path.display()
        );
        return prompt_token(kind);
    }

    Err(Error::Message(format!(
        "backend needs {} (or export {} / auth-mode prompt)",
        path.display(),
        key
    )))
}

/// Write `KEY=token` with mode 0640 through File replace. When running as root
/// and `service_user` is set, the group is the service user's, so the service
/// account can read the file after sudo re-exec (stories #11, #40).
///
/// The token is staged in a 0600 temp file and renamed over the old one, so it
/// is never briefly world-readable nor truncated in place. An unchanged token
/// is not rewritten, but its mode and group are still repaired.
/// A group that cannot be set fails the write before the rename, leaving the
/// old token file in place.
pub fn write_token_file(
    path: &Path,
    key: &str,
    token: &ManagerToken,
    service_user: Option<&str>,
) -> Result<()> {
    let body = format!("{}={}\n", key, token.expose());
    // root:SERVICE_USER so mode 0640 is useful under a service-account install.
    let gid = service_user
        .filter(|u| !u.is_empty() && is_euid_root())
        .and_then(gid_for_user);
    file_replace::replace(path, body.as_bytes(), Perms::Exact { mode: 0o640, gid })
        .map_err(|e| Error::config_write(path, e))
}

fn is_euid_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
            } else {
                None
            }
        })
        .unwrap_or(1)
        == 0
}

fn gid_for_user(user: &str) -> Option<u32> {
    // Prefer primary group of the service account (`id -g user`).
    let out = std::process::Command::new("id")
        .args(["-g", user])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A host with nothing configured yet: file mode, no token anywhere, at a
    /// terminal. Each test overrides only the fact it is about.
    fn facts() -> CaptureFacts {
        CaptureFacts {
            kind: TokenKind::Bws,
            file: TokenFile::Missing,
            env_token: false,
            mode: AuthMode::File,
            tty: true,
            set_token: false,
            token_path: "/etc/vaulted-agent/bws.env".into(),
            current_user: "root".into(),
        }
    }

    #[test]
    fn capture_prompts_only_when_file_missing_no_env_and_mode_file() {
        assert_eq!(plan_token_capture(&facts()), CaptureDecision::Prompt);
    }

    #[test]
    fn capture_defers_to_existing_token_file() {
        assert_eq!(
            plan_token_capture(&CaptureFacts {
                file: TokenFile::Present,
                ..facts()
            }),
            CaptureDecision::UseExisting
        );
    }

    #[test]
    fn capture_defers_to_exported_token() {
        assert_eq!(
            plan_token_capture(&CaptureFacts {
                env_token: true,
                ..facts()
            }),
            CaptureDecision::UseExisting
        );
    }

    #[test]
    fn capture_never_fires_in_prompt_mode() {
        for file in [TokenFile::Missing, TokenFile::Present] {
            assert_eq!(
                plan_token_capture(&CaptureFacts {
                    mode: AuthMode::Prompt,
                    file,
                    ..facts()
                }),
                CaptureDecision::UseExisting
            );
        }
    }

    #[test]
    fn set_token_in_prompt_mode_is_a_contradiction() {
        match plan_token_capture(&CaptureFacts {
            mode: AuthMode::Prompt,
            tty: false,
            set_token: true,
            ..facts()
        }) {
            CaptureDecision::Fail(msg) => assert!(msg.contains("auth-mode file"), "{msg}"),
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn set_token_outranks_exported_token_and_existing_file() {
        // Rotation door: an explicit argument beats ambient env, so a rotation
        // never silently stores the stale exported value.
        assert_eq!(
            plan_token_capture(&CaptureFacts {
                file: TokenFile::Present,
                env_token: true,
                tty: false,
                set_token: true,
                ..facts()
            }),
            CaptureDecision::Stdin
        );
        assert_eq!(
            plan_token_capture(&CaptureFacts {
                env_token: true,
                tty: false,
                set_token: true,
                ..facts()
            }),
            CaptureDecision::Stdin
        );
    }

    #[test]
    fn set_token_at_a_terminal_says_to_pipe_instead_of_blocking() {
        // Reading stdin from a terminal waits for ^D and reads like a hang.
        match plan_token_capture(&CaptureFacts {
            set_token: true,
            ..facts()
        }) {
            CaptureDecision::Fail(msg) => {
                assert!(msg.contains("stdin is a terminal"), "{msg}");
                assert!(msg.contains("printf"), "{msg}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn unreadable_token_file_never_becomes_a_paste() {
        // Invariant 6 / issue #51: overwriting would clobber a working
        // credential and hide the permissions fault.
        for (env_token, tty, set_token) in [
            (false, true, false),
            (true, true, false),
            (false, false, true),
            (true, false, true),
        ] {
            match plan_token_capture(&CaptureFacts {
                file: TokenFile::Unreadable,
                env_token,
                tty,
                set_token,
                ..facts()
            }) {
                CaptureDecision::Fail(msg) => {
                    assert!(msg.contains("cannot be read"), "{msg}");
                    assert!(msg.contains("bws.env"), "{msg}");
                }
                other => panic!("expected Fail, got {other:?}"),
            }
        }
    }

    #[test]
    fn no_tty_and_no_token_names_set_token() {
        match plan_token_capture(&CaptureFacts {
            tty: false,
            ..facts()
        }) {
            CaptureDecision::Fail(msg) => {
                assert!(msg.contains("--set-token"), "{msg}");
                assert!(msg.contains("BWS_ACCESS_TOKEN"), "{msg}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    #[test]
    fn piped_token_strips_key_prefix_and_whitespace() {
        assert_eq!(
            normalize_piped_token(TokenKind::Bws, "BWS_ACCESS_TOKEN=0.a.b:c\n").unwrap(),
            "0.a.b:c"
        );
        assert_eq!(
            normalize_piped_token(TokenKind::Op, "  ops_abc\n").unwrap(),
            "ops_abc"
        );
        assert_eq!(
            normalize_piped_token(TokenKind::Op, "OP_SERVICE_ACCOUNT_TOKEN=ops_abc").unwrap(),
            "ops_abc"
        );
    }

    #[test]
    fn piped_token_rejects_empty_embedded_newlines_and_stray_equals() {
        for bad in ["", "   ", "\n"] {
            assert!(
                normalize_piped_token(TokenKind::Bws, bad).is_err(),
                "{bad:?}"
            );
        }
        assert!(normalize_piped_token(TokenKind::Bws, "0.a.b:c\nOTHER=x\n").is_err());
        assert!(normalize_piped_token(TokenKind::Bws, "FOO=0.a.b:c").is_err());
    }

    #[test]
    fn shape_check_catches_wrong_bitwarden_credential() {
        assert!(TokenKind::Bws.shape_problem("0.uuid.client:enc").is_none());
        // Login API key client id, not a Secrets Manager access token.
        assert!(TokenKind::Bws.shape_problem("user.1234").is_some());
        // Master password.
        assert!(TokenKind::Bws
            .shape_problem("correct horse battery")
            .is_some());
        assert!(TokenKind::Bws.shape_problem("hunter2").is_some());
        // Right prefix, missing the key separator.
        assert!(TokenKind::Bws.shape_problem("0.uuid.client").is_some());
    }

    #[test]
    fn shape_check_catches_wrong_onepassword_credential() {
        assert!(TokenKind::Op.shape_problem("ops_eyJhbGci").is_none());
        assert!(TokenKind::Op
            .shape_problem("my personal password")
            .is_some());
        assert!(TokenKind::Op.shape_problem("eyJhbGci").is_some());
    }

    #[test]
    fn env_token_wins_over_every_prompt_route() {
        for flag in [false, true] {
            for configured in [AuthMode::File, AuthMode::Prompt] {
                let ts = TokenSource::decide(Some("prompt"), Some("1"), flag, configured);
                assert_eq!(ts.route(true), TokenRoute::Env);
            }
        }
    }

    #[test]
    fn prompt_flag_forces_prompt_over_file_mode() {
        let ts = TokenSource::decide(None, None, true, AuthMode::File);
        assert_eq!(ts.route(false), TokenRoute::Prompt);
        assert_eq!(ts.auth_mode(), AuthMode::File);
    }

    #[test]
    fn prompt_env_forces_prompt_only_when_exactly_one() {
        assert_eq!(
            TokenSource::decide(None, Some("1"), false, AuthMode::File).route(false),
            TokenRoute::Prompt
        );
        for other in ["0", "", "yes", "true"] {
            assert_eq!(
                TokenSource::decide(None, Some(other), false, AuthMode::File).route(false),
                TokenRoute::File,
                "{other:?}"
            );
        }
    }

    #[test]
    fn configured_prompt_mode_prompts() {
        let ts = TokenSource::decide(None, None, false, AuthMode::Prompt);
        assert_eq!(ts.auth_mode(), AuthMode::Prompt);
        assert_eq!(ts.route(false), TokenRoute::Prompt);
    }

    #[test]
    fn file_mode_without_forcing_reads_the_file() {
        let ts = TokenSource::decide(None, None, false, AuthMode::File);
        assert_eq!(ts.auth_mode(), AuthMode::File);
        assert_eq!(ts.route(false), TokenRoute::File);
    }

    #[test]
    fn env_auth_mode_overrides_configured() {
        assert_eq!(
            TokenSource::decide(Some("prompt"), None, false, AuthMode::File).auth_mode(),
            AuthMode::Prompt
        );
        assert_eq!(
            TokenSource::decide(Some("file"), None, false, AuthMode::Prompt).auth_mode(),
            AuthMode::File
        );
        assert_eq!(
            TokenSource::decide(Some("file"), None, false, AuthMode::Prompt).route(false),
            TokenRoute::File
        );
    }

    #[test]
    fn unknown_env_auth_mode_falls_back_to_configured() {
        for configured in [AuthMode::File, AuthMode::Prompt] {
            for junk in ["", "disk", "PROMPT"] {
                assert_eq!(
                    TokenSource::decide(Some(junk), None, false, configured).auth_mode(),
                    configured,
                    "{junk:?}"
                );
            }
        }
    }

    #[test]
    fn forced_prompt_survives_setup_mode_choice() {
        let ts =
            TokenSource::decide(None, None, true, AuthMode::Prompt).with_auth_mode(AuthMode::File);
        assert_eq!(ts.auth_mode(), AuthMode::File);
        assert_eq!(ts.route(false), TokenRoute::Prompt);
    }

    #[test]
    fn token_file_status_missing_is_not_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.env");
        assert!(matches!(token_file_status(&path), TokenFileStatus::Missing));
    }

    #[test]
    fn token_file_status_present_when_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.env");
        fs::write(&path, "OP_SERVICE_ACCOUNT_TOKEN=x\n").unwrap();
        assert!(matches!(token_file_status(&path), TokenFileStatus::Present));
    }

    #[test]
    fn token_file_status_unreadable_when_mode_forbids() {
        // Skip when the suite runs as root: chmod 000 does not stop root.
        if is_euid_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.env");
        fs::write(&path, "OP_SERVICE_ACCOUNT_TOKEN=x\n").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&path, perms).unwrap();
        match token_file_status(&path) {
            TokenFileStatus::Unreadable { source } => {
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected Unreadable, got {other:?}"),
        }
        // Restore so tempfile cleanup can remove the file.
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).unwrap();
    }

    #[test]
    fn read_token_file_errors_on_permission_denied() {
        if is_euid_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.env");
        fs::write(&path, "OP_SERVICE_ACCOUNT_TOKEN=x\n").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&path, perms).unwrap();
        let err = read_token_file(&path, "OP_SERVICE_ACCOUNT_TOKEN").unwrap_err();
        match err {
            Error::Io { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("expected Io, got {other}"),
        }
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).unwrap();
    }

    #[test]
    fn read_token_file_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.env");
        assert!(matches!(
            read_token_file(&path, "OP_SERVICE_ACCOUNT_TOKEN"),
            Ok(None)
        ));
    }

    #[test]
    fn a_token_cache_loads_each_kind_once() {
        let loads = std::cell::RefCell::new(Vec::new());
        let mut cache = TokenCache::with_loader(|kind| {
            loads.borrow_mut().push(kind.env_var());
            Ok(ManagerToken::new(format!("t-{}", kind.env_var())))
        });
        for _ in 0..3 {
            assert_eq!(
                cache.get(TokenKind::Bws).unwrap().expose(),
                "t-BWS_ACCESS_TOKEN"
            );
        }
        cache.get(TokenKind::Op).unwrap();
        cache.get(TokenKind::Op).unwrap();
        drop(cache);
        assert_eq!(
            *loads.borrow(),
            vec!["BWS_ACCESS_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN"]
        );
    }

    #[test]
    fn a_failed_load_is_cached_and_repeated_never_retried() {
        let loads = std::cell::Cell::new(0);
        let mut cache = TokenCache::with_loader(|_| {
            loads.set(loads.get() + 1);
            Err(Error::Message("empty token".into()))
        });
        for _ in 0..3 {
            assert_eq!(
                cache.get(TokenKind::Bws).unwrap_err().to_string(),
                "empty token"
            );
        }
        assert_eq!(loads.get(), 1, "a failed load must not re-prompt");
    }
}
