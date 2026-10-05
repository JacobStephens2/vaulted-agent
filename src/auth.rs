//! Load vault manager tokens from env, file, or TTY prompt (the Token source).

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::config::{AuthMode, Backend, Paths};
use crate::defaults::Defaults;
use crate::error::{Error, Result};
use crate::secret::ManagerToken;
use crate::token_file::{self, Probe, Reader, State};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// The Backend this token unlocks.
    pub fn backend(self) -> Backend {
        match self {
            Self::Bws => Backend::Bitwarden,
            Self::Op => Backend::OnePassword,
        }
    }

    /// The `setup` subcommand that configures this token's backend.
    pub fn backend_name(self) -> &'static str {
        self.backend().as_str()
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

/// True when this process can actually run an interactive paste: stdin is a
/// terminal (that is where the no-echo read happens) *and* /dev/tty opens (that
/// is where the prompt is written). install.sh's `can_prompt_user`, in Rust.
///
/// Both halves matter. Under `cmd | vaulted-agent setup` stdin is a pipe, so a
/// "paste it now" prompt would read the pipe instead of the operator.
///
/// The one "can a human answer a prompt" predicate: Token capture, the Setup
/// interview, `auth-mode` and `edit-manifest` all ask it.
pub(crate) fn interactive_tty() -> bool {
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

/// Where Token capture takes the Manager token from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Door {
    /// `--set-token`: the token is piped on stdin.
    Stdin,
    /// A no-echo paste on the terminal.
    Prompt,
    /// The manager-token env var is exported and non-empty.
    Env,
    /// The token file is readable and carries a value for this key.
    File,
}

/// What `setup` should do about the manager token. Pure decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CaptureDecision {
    /// Obtain the token through `door`, verify it, then store it when `store`.
    Obtain { door: Door, store: bool },
    /// Capture cannot run here; the message says why.
    Fail(String),
}

/// Facts the capture decision is made from. All injectable; no IO in the plan.
#[derive(Debug, Clone)]
pub(crate) struct CaptureFacts {
    pub kind: TokenKind,
    pub file: State,
    /// What is wrong with an unreadable or malformed token file: the IO error
    /// or the faulty line. Message text only.
    pub file_fault: String,
    /// The token's env var is exported and non-empty.
    pub env_token: bool,
    pub mode: AuthMode,
    /// `-p` / `VAULTED_AGENT_PROMPT_AUTH=1`: paste rather than read the file.
    pub force_prompt: bool,
    /// A terminal is available for a no-echo paste.
    pub tty: bool,
    /// `--set-token` was passed to `setup`.
    pub set_token: bool,
    /// Token-file path, for message text only.
    pub token_path: String,
    /// Who reads the token file, for the unreadable-file message.
    pub reader: Reader,
}

impl CaptureFacts {
    /// Gather the facts from the running process and the token file's
    /// `probe`. The only IO in capture planning; `plan_token_capture` itself
    /// stays pure.
    pub(crate) fn from_runtime(
        paths: &Paths,
        kind: TokenKind,
        source: TokenSource,
        set_token: bool,
        probe: &Probe,
    ) -> Self {
        let doors = DoorFacts::from_probe(kind, probe);
        let file_fault = match probe {
            Probe::Malformed(fault) => fault.to_string(),
            Probe::Unreadable(source) => source.to_string(),
            _ => String::new(),
        };
        Self {
            kind,
            file: doors.file,
            file_fault,
            env_token: doors.env_token,
            mode: source.auth_mode(),
            force_prompt: source.forces_prompt(),
            tty: interactive_tty(),
            set_token,
            token_path: kind.file(paths).display().to_string(),
            reader: Reader::from_runtime(paths),
        }
    }
}

/// The two token doors that exist before `setup` runs, for one kind: what
/// [`CaptureFacts`] reads, and all that setup's no-backend auto-pick reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DoorFacts {
    /// The token's env var is exported and non-empty.
    pub env_token: bool,
    pub file: State,
}

impl DoorFacts {
    pub(crate) fn from_runtime(paths: &Paths, kind: TokenKind) -> Self {
        Self::from_probe(kind, &token_file::probe(kind.file(paths), kind.env_var()))
    }

    /// The doors given the token file's probe. A file that holds no value for
    /// this key is not a door: it projects to missing, so setup asks for one.
    fn from_probe(kind: TokenKind, probe: &Probe) -> Self {
        Self {
            env_token: std::env::var(kind.env_var())
                .map(|v| !v.is_empty())
                .unwrap_or(false),
            file: probe.state(),
        }
    }

    /// True when this kind has a token door. An unreadable or malformed token
    /// file counts: setup then picks its Backend and Token capture fails with
    /// that file's message, instead of setup quietly choosing another vault.
    pub(crate) fn has_door(self) -> bool {
        self.env_token || self.file != State::Missing
    }
}

/// The token kind `setup` with no backend named sets up: the first with a
/// door, Bitwarden before 1Password. `None` when neither has one. Pure.
pub(crate) fn auto_pick(bws: DoorFacts, op: DoorFacts) -> Option<TokenKind> {
    [(TokenKind::Bws, bws), (TokenKind::Op, op)]
        .into_iter()
        .find(|(_, doors)| doors.has_door())
        .map(|(kind, _)| kind)
}

/// Pure planning: no IO, no prompts, no process spawn.
///
/// Precedence follows Token source routing, so `setup` keeps today's order:
/// an explicit pipe beats ambient env, env beats `-p`, `-p` beats the file.
/// The unit tests are named after the rows, first match wins:
///
/// | row | `auth_mode = file`                         | `auth_mode = prompt` (never stores) |
/// |-----|--------------------------------------------|-------------------------------------|
/// | 1   | token file unreadable: fail                | `--set-token`: fail                 |
/// | 1b  | malformed, no `--set-token`: fail          |                                     |
/// | 2   | `--set-token`: Stdin (fail at a terminal)  | env token: Env                      |
/// | 3   | env token: Env                             | terminal: Prompt                    |
/// | 4   | `-p` at a terminal: Prompt                 | otherwise fail                      |
/// | 5   | token file present: File                   |                                     |
/// | 6   | terminal: Prompt                           |                                     |
/// | 7   | otherwise fail                             |                                     |
pub(crate) fn plan_token_capture(facts: &CaptureFacts) -> CaptureDecision {
    let key = facts.kind.env_var();
    let backend = facts.kind.backend_name();

    // auth_mode=prompt stores nothing on disk and never reads the token file.
    if facts.mode != AuthMode::File {
        let obtain = |door| CaptureDecision::Obtain { door, store: false };
        if facts.set_token {
            return CaptureDecision::Fail(format!(
                "--set-token stores {key} in {}, but auth_mode=prompt\n  \
                 Store tokens on disk first: vaulted-agent auth-mode file",
                facts.token_path
            ));
        }
        if facts.env_token {
            return obtain(Door::Env);
        }
        if facts.tty {
            return obtain(Door::Prompt);
        }
        return CaptureDecision::Fail(format!(
            "no manager token to verify and no terminal to paste one (auth_mode=prompt)\n  \
             export: {key}\n  \
             or store it on disk: vaulted-agent auth-mode file, then\n  \
             printf %s \"$TOKEN\" | vaulted-agent setup {backend} --set-token"
        ));
    }
    let obtain = |door| CaptureDecision::Obtain { door, store: true };

    // Invariant 6 / issue #51: an existing token file this process cannot read
    // is a permissions fault. Capturing over it would clobber a working
    // credential and hide the fault, so it is never an invitation to paste.
    if facts.file == State::Unreadable {
        return CaptureDecision::Fail(format!(
            "{}\n  \
             setup will not overwrite a token file it cannot read — that would clobber a working \
             credential and hide the permissions fault.",
            token_file::explain_unreadable(&facts.token_path, &facts.file_fault, &facts.reader)
        ));
    }
    // A malformed file is a fault too, but no working credential: only the
    // explicit rotation door below may replace it, once its token verifies.
    if facts.file == State::Malformed && !facts.set_token {
        return CaptureDecision::Fail(token_file::explain_malformed(
            &facts.token_path,
            &facts.file_fault,
            facts.kind,
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
                 or drop --set-token to paste it interactively"
            ));
        }
        return obtain(Door::Stdin);
    }

    if facts.env_token {
        return obtain(Door::Env);
    }
    if facts.force_prompt && facts.tty {
        return obtain(Door::Prompt);
    }
    if facts.file == State::Present {
        return obtain(Door::File);
    }
    if facts.tty {
        return obtain(Door::Prompt);
    }

    CaptureDecision::Fail(format!(
        "no manager token yet and no terminal to paste one\n  \
         pipe it:   printf %s \"$TOKEN\" | vaulted-agent setup {backend} --set-token\n  \
         or export: {key}\n  \
         or paste each launch: vaulted-agent auth-mode prompt"
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

/// Outcome of `capture_token`. `V` is what the Backend's verify produced.
pub(crate) enum Capture<V> {
    /// Verified against the backend, and stored when the auth mode is `file`.
    Token(ManagerToken, V),
    /// Operator declined at the prompt; nothing was verified or written.
    Skipped,
}

fn tty_write(line: &str) {
    if let Ok(mut tty) = fs::OpenOptions::new().write(true).open("/dev/tty") {
        let _ = writeln!(tty, "{line}");
        let _ = tty.flush();
    }
}

/// The only Manager-token write outside `token_file::write` itself.
fn store_captured(paths: &Paths, kind: TokenKind, token: &ManagerToken) -> Result<()> {
    let path = kind.file(paths).to_path_buf();
    let svc = Defaults::load(paths)?.service_user;
    token_file::write(&path, kind.env_var(), token, svc.as_deref())?;
    println!("wrote {} (0640)", path.display());
    Ok(())
}

/// `setup`-only token capture. Never called from the launch path.
///
/// Owns every way `setup` obtains a token (pasted, piped, exported, already
/// on disk). Each door ends the same way: `verify` (`bws secret list` /
/// `op whoami`) against the backend, then the token file is written when
/// `source`'s auth mode is `file`. An invalid token never lands on disk.
pub(crate) fn capture_token<V>(
    paths: &Paths,
    kind: TokenKind,
    source: TokenSource,
    set_token: bool,
    verify: &dyn Fn(&ManagerToken) -> Result<V>,
) -> Result<Capture<V>> {
    let probe = token_file::probe(kind.file(paths), kind.env_var());
    let facts = CaptureFacts::from_runtime(paths, kind, source, set_token, &probe);
    let (door, store) = match plan_token_capture(&facts) {
        CaptureDecision::Fail(msg) => return Err(Error::Message(msg)),
        CaptureDecision::Obtain { door, store } => (door, store),
    };
    let captured = match door {
        Door::Stdin => capture_from_stdin(kind, verify)?,
        Door::Prompt => capture_from_prompt(paths, kind, store, verify)?,
        Door::Env => capture_from_env(kind, verify)?,
        Door::File => {
            let Probe::Token(token) = probe else {
                unreachable!("the plan opens the file door only when the probe holds a token")
            };
            capture_from_file(paths, kind, token, verify)?
        }
    };
    if let Capture::Token(token, _) = &captured {
        if store {
            store_captured(paths, kind, token)?;
        } else {
            println!("auth_mode=prompt — token not written to disk (good).");
            println!(
                "  To store it: vaulted-agent auth-mode file, then re-run setup {}.",
                kind.backend_name()
            );
        }
    }
    Ok(captured)
}

/// Verify a token that has no operator at a paste to correct it: a rejection
/// is final, and `rejected` says where the token came from.
fn verify_once<V>(
    token: ManagerToken,
    verify: &dyn Fn(&ManagerToken) -> Result<V>,
    rejected: impl FnOnce(Error) -> String,
) -> Result<Capture<V>> {
    match verify(&token) {
        Ok(verified) => Ok(Capture::Token(token, verified)),
        Err(e) => Err(Error::Message(rejected(e))),
    }
}

fn capture_from_stdin<V>(
    kind: TokenKind,
    verify: &dyn Fn(&ManagerToken) -> Result<V>,
) -> Result<Capture<V>> {
    use std::io::Read as _;
    let mut raw = String::new();
    io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| Error::Message(format!("--set-token: reading stdin: {e}")))?;
    let token = ManagerToken::new(normalize_piped_token(kind, &raw)?);
    // No shape check here. A pipe is deliberate and often a rotation, and the
    // live verify is the authority on whether the token works — a heuristic
    // that has not caught up with a new token format must not be what blocks
    // it. No re-prompt, just a non-zero exit.
    verify_once(token, verify, |e| {
        format!(
            "--set-token: {} rejected by the vault (nothing written)\n  {e}",
            kind.env_var()
        )
    })
}

/// The exported env var. Nobody is at a paste to correct it, so a rejection
/// fails right away.
fn capture_from_env<V>(
    kind: TokenKind,
    verify: &dyn Fn(&ManagerToken) -> Result<V>,
) -> Result<Capture<V>> {
    let key = kind.env_var();
    let token = ManagerToken::new(std::env::var(key).unwrap_or_default());
    verify_once(token, verify, |e| {
        format!(
            "exported {key} rejected by the vault (nothing written)\n  \
             unset it, or export a working token, then re-run setup {}\n  {e}",
            kind.backend_name()
        )
    })
}

/// The token already on disk, as the probe read it. A rejected one is never
/// overwritten here: rotating it is the operator's explicit `--set-token`.
fn capture_from_file<V>(
    paths: &Paths,
    kind: TokenKind,
    token: ManagerToken,
    verify: &dyn Fn(&ManagerToken) -> Result<V>,
) -> Result<Capture<V>> {
    verify_once(token, verify, |e| {
        format!(
            "{} in {} rejected by the vault (nothing written; the file is unchanged)\n  \
             rotate it:  printf %s \"$TOKEN\" | vaulted-agent setup {} --set-token\n  {e}",
            kind.env_var(),
            kind.file(paths).display(),
            kind.backend_name()
        )
    })
}

fn capture_from_prompt<V>(
    paths: &Paths,
    kind: TokenKind,
    store: bool,
    verify: &dyn Fn(&ManagerToken) -> Result<V>,
) -> Result<Capture<V>> {
    let path = kind.file(paths);
    let fate = if store {
        format!("will be written to {}", path.display())
    } else {
        "not written to disk".to_string()
    };
    tty_write(&format!("\nGet it at: {}", kind.console_url()));
    // Two attempts: one paste, one correction.
    for attempt in 0..2 {
        tty_write(&format!(
            "{}\n(hidden; {fate}, empty to skip): ",
            kind.prompt_label()
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
            if store {
                println!(
                    "no token provided; write {} later, or: vaulted-agent auth-mode prompt",
                    path.display()
                );
            } else {
                println!("no token provided; nothing verified.");
            }
            return Ok(Capture::Skipped);
        }
        // Shape first, so a master password or a login API key is named for
        // what it is instead of coming back as an opaque vault rejection.
        let problem = match kind.shape_problem(&value) {
            Some(problem) => problem,
            None => {
                let token = ManagerToken::new(value);
                match verify(&token) {
                    Ok(verified) => return Ok(Capture::Token(token, verified)),
                    Err(e) => format!("the vault rejected it ({e})"),
                }
            }
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

    /// Thin adapter: read the real environment and Machine defaults. Fails
    /// when `defaults.conf` does not load.
    pub fn from_env(paths: &Paths, prompt_flag: bool) -> Result<Self> {
        let configured = Defaults::load(paths)?.auth_mode;
        let env_mode = std::env::var("VAULTED_AGENT_AUTH_MODE").ok();
        let env_prompt = std::env::var("VAULTED_AGENT_PROMPT_AUTH").ok();
        Ok(Self::decide(
            env_mode.as_deref(),
            env_prompt.as_deref(),
            prompt_flag,
            configured,
        ))
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

    /// `-p` / `VAULTED_AGENT_PROMPT_AUTH=1` asked for a paste this invocation.
    pub(crate) fn forces_prompt(&self) -> bool {
        self.force_prompt
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
    match token_file::probe(path, key) {
        Probe::Token(t) => return Ok(t),
        // An empty value never authenticates: it is no token, as missing is.
        Probe::NoValue | Probe::Missing => {}
        // Unreadable or malformed is not missing: fail closed instead of
        // prompting for a paste of the vault service-account token
        // (invariant 6, issues #51 and #160).
        Probe::Unreadable(source) => {
            return Err(Error::Message(token_file::explain_unreadable(
                path.display(),
                source,
                &Reader::from_runtime(paths),
            )));
        }
        Probe::Malformed(fault) => {
            return Err(Error::Message(token_file::explain_malformed(
                path.display(),
                fault,
                kind,
            )));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A host with nothing configured yet: file mode, no token anywhere, at a
    /// terminal. Each test overrides only the fact it is about.
    fn facts() -> CaptureFacts {
        CaptureFacts {
            kind: TokenKind::Bws,
            file: State::Missing,
            env_token: false,
            mode: AuthMode::File,
            force_prompt: false,
            tty: true,
            set_token: false,
            file_fault: String::new(),
            token_path: "/etc/vaulted-agent/bws.env".into(),
            reader: Reader {
                user: "root".into(),
                service_user: Ok(None),
            },
        }
    }

    fn stored(door: Door) -> CaptureDecision {
        CaptureDecision::Obtain { door, store: true }
    }

    fn unstored(door: Door) -> CaptureDecision {
        CaptureDecision::Obtain { door, store: false }
    }

    fn fail_message(decision: CaptureDecision) -> String {
        match decision {
            CaptureDecision::Fail(msg) => msg,
            other => panic!("expected Fail, got {other:?}"),
        }
    }

    // --- auth_mode = file ------------------------------------------------

    #[test]
    fn file_mode_row_1_unreadable_token_file_fails_whatever_else_is_available() {
        // Invariant 6 / issue #51: overwriting would clobber a working
        // credential and hide the permissions fault.
        for (env_token, tty, set_token, force_prompt) in [
            (false, true, false, false),
            (true, true, false, false),
            (false, false, true, false),
            (true, false, true, false),
            (false, true, false, true),
        ] {
            let msg = fail_message(plan_token_capture(&CaptureFacts {
                file: State::Unreadable,
                file_fault: "Permission denied (os error 13)".into(),
                env_token,
                tty,
                set_token,
                force_prompt,
                ..facts()
            }));
            assert!(msg.contains("cannot be read"), "{msg}");
            assert!(msg.contains("bws.env"), "{msg}");
            assert!(msg.contains("Permission denied"), "{msg}");
            assert!(msg.contains("will not overwrite"), "{msg}");
        }
    }

    fn malformed() -> CaptureFacts {
        CaptureFacts {
            file: State::Malformed,
            file_fault: "line 1: expected KEY=value".into(),
            ..facts()
        }
    }

    #[test]
    fn file_mode_row_1b_malformed_token_file_fails_unless_set_token() {
        // A fault, not an absence: pasting over it would hide it, and it is
        // not unreadable, so the fix is a rewrite, not a chmod.
        for (env_token, tty, force_prompt) in [
            (false, true, false),
            (true, true, false),
            (false, false, false),
            (false, true, true),
        ] {
            let msg = fail_message(plan_token_capture(&CaptureFacts {
                env_token,
                tty,
                force_prompt,
                ..malformed()
            }));
            assert!(msg.contains("bws.env is malformed"), "{msg}");
            assert!(msg.contains("line 1: expected KEY=value"), "{msg}");
            assert!(msg.contains("--set-token"), "{msg}");
            assert!(!msg.contains("cannot be read"), "{msg}");
        }
    }

    #[test]
    fn file_mode_row_2_set_token_may_replace_a_malformed_token_file() {
        for env_token in [false, true] {
            assert_eq!(
                plan_token_capture(&CaptureFacts {
                    env_token,
                    tty: false,
                    set_token: true,
                    ..malformed()
                }),
                stored(Door::Stdin)
            );
        }
    }

    #[test]
    fn file_mode_row_2_set_token_reads_stdin_over_env_file_and_force_prompt() {
        // Rotation door: an explicit argument beats ambient env, so a rotation
        // never silently stores the stale exported value.
        for (file, env_token, force_prompt) in [
            (State::Missing, false, false),
            (State::Present, true, false),
            (State::Missing, true, false),
            (State::Present, false, true),
        ] {
            assert_eq!(
                plan_token_capture(&CaptureFacts {
                    file,
                    env_token,
                    force_prompt,
                    tty: false,
                    set_token: true,
                    ..facts()
                }),
                stored(Door::Stdin)
            );
        }
    }

    #[test]
    fn file_mode_row_2_set_token_at_a_terminal_says_to_pipe_instead_of_blocking() {
        // Reading stdin from a terminal waits for ^D and reads like a hang.
        let msg = fail_message(plan_token_capture(&CaptureFacts {
            set_token: true,
            ..facts()
        }));
        assert!(msg.contains("stdin is a terminal"), "{msg}");
        assert!(msg.contains("printf"), "{msg}");
    }

    #[test]
    fn file_mode_row_3_exported_token_beats_force_prompt_and_the_file() {
        for (file, force_prompt, tty) in [
            (State::Missing, false, true),
            (State::Present, false, false),
            (State::Present, true, true),
        ] {
            assert_eq!(
                plan_token_capture(&CaptureFacts {
                    env_token: true,
                    file,
                    force_prompt,
                    tty,
                    ..facts()
                }),
                stored(Door::Env)
            );
        }
    }

    #[test]
    fn file_mode_row_4_force_prompt_at_a_terminal_beats_the_file() {
        assert_eq!(
            plan_token_capture(&CaptureFacts {
                force_prompt: true,
                file: State::Present,
                ..facts()
            }),
            stored(Door::Prompt)
        );
    }

    #[test]
    fn file_mode_row_5_token_file_is_a_door_and_is_stored_again() {
        // Stored again so File replace repairs mode and group; identical bytes
        // are never rewritten.
        for tty in [true, false] {
            assert_eq!(
                plan_token_capture(&CaptureFacts {
                    file: State::Present,
                    tty,
                    ..facts()
                }),
                stored(Door::File)
            );
        }
        // -p with no terminal cannot paste, so the file still answers.
        assert_eq!(
            plan_token_capture(&CaptureFacts {
                file: State::Present,
                force_prompt: true,
                tty: false,
                ..facts()
            }),
            stored(Door::File)
        );
    }

    #[test]
    fn file_mode_row_6_terminal_with_nothing_else_prompts() {
        assert_eq!(plan_token_capture(&facts()), stored(Door::Prompt));
    }

    #[test]
    fn file_mode_row_7_no_token_and_no_terminal_names_set_token() {
        for force_prompt in [false, true] {
            let msg = fail_message(plan_token_capture(&CaptureFacts {
                tty: false,
                force_prompt,
                ..facts()
            }));
            assert!(msg.contains("no manager token yet"), "{msg}");
            assert!(msg.contains("--set-token"), "{msg}");
            assert!(msg.contains("BWS_ACCESS_TOKEN"), "{msg}");
        }
    }

    // --- setup's no-backend auto-pick --------------------------------------

    const NO_DOOR: DoorFacts = DoorFacts {
        env_token: false,
        file: State::Missing,
    };

    fn doors(env_token: bool, file: State) -> DoorFacts {
        DoorFacts { env_token, file }
    }

    #[test]
    fn auto_pick_row_1_no_door_on_either_kind_picks_nothing() {
        // An empty exported var or a token file without the key reads as
        // env_token=false / Missing in `DoorFacts::from_runtime`.
        assert_eq!(auto_pick(NO_DOOR, NO_DOOR), None);
    }

    #[test]
    fn auto_pick_row_2_each_door_alone_picks_its_kind() {
        for door in [
            doors(true, State::Missing),
            doors(false, State::Present),
            doors(false, State::Unreadable),
            doors(false, State::Malformed),
        ] {
            assert_eq!(auto_pick(door, NO_DOOR), Some(TokenKind::Bws), "{door:?}");
            assert_eq!(auto_pick(NO_DOOR, door), Some(TokenKind::Op), "{door:?}");
        }
    }

    #[test]
    fn auto_pick_row_3_bitwarden_wins_over_onepassword() {
        let op = doors(true, State::Present);
        for bws in [
            doors(true, State::Missing),
            doors(false, State::Present),
            doors(false, State::Unreadable),
            doors(false, State::Malformed),
        ] {
            assert_eq!(auto_pick(bws, op), Some(TokenKind::Bws), "{bws:?}");
        }
    }

    #[test]
    fn a_token_file_without_the_key_is_not_a_door() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        fs::write(&paths.bws_env_file, "OTHER=x\n").unwrap();
        let facts = DoorFacts::from_runtime(&paths, TokenKind::Bws);
        assert_eq!(facts.file, State::Missing);
    }

    // --- auth_mode = prompt ----------------------------------------------

    fn prompt_mode() -> CaptureFacts {
        CaptureFacts {
            mode: AuthMode::Prompt,
            ..facts()
        }
    }

    #[test]
    fn prompt_mode_row_1_set_token_is_a_contradiction() {
        for (env_token, file) in [
            (false, State::Missing),
            (true, State::Present),
            (false, State::Unreadable),
            (false, State::Malformed),
        ] {
            let msg = fail_message(plan_token_capture(&CaptureFacts {
                tty: false,
                set_token: true,
                env_token,
                file,
                ..prompt_mode()
            }));
            assert!(msg.contains("auth-mode file"), "{msg}");
        }
    }

    #[test]
    fn prompt_mode_row_2_exported_token_is_verified_but_not_stored() {
        for tty in [true, false] {
            assert_eq!(
                plan_token_capture(&CaptureFacts {
                    env_token: true,
                    tty,
                    ..prompt_mode()
                }),
                unstored(Door::Env)
            );
        }
    }

    #[test]
    fn prompt_mode_row_3_terminal_pastes_and_never_reads_the_token_file() {
        for file in [
            State::Missing,
            State::Present,
            State::Unreadable,
            State::Malformed,
        ] {
            for force_prompt in [false, true] {
                assert_eq!(
                    plan_token_capture(&CaptureFacts {
                        file,
                        force_prompt,
                        ..prompt_mode()
                    }),
                    unstored(Door::Prompt)
                );
            }
        }
    }

    #[test]
    fn prompt_mode_row_4_no_token_and_no_terminal_says_export_or_auth_mode_file() {
        for file in [
            State::Missing,
            State::Present,
            State::Unreadable,
            State::Malformed,
        ] {
            let msg = fail_message(plan_token_capture(&CaptureFacts {
                file,
                tty: false,
                ..prompt_mode()
            }));
            assert!(msg.contains("export: BWS_ACCESS_TOKEN"), "{msg}");
            assert!(msg.contains("auth-mode file"), "{msg}");
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
