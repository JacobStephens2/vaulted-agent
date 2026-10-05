//! Load vault manager tokens from env, file, or TTY prompt (the Token source).

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::config::{AuthMode, Paths};
use crate::defaults::Defaults;
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
    match Defaults::load(paths).map(|d| d.service_user) {
        Err(e) => msg.push_str(&format!("\n  defaults.conf did not load: {e}")),
        Ok(None) => msg.push_str(
            "\n  No service_user in defaults.conf — the launcher never re-execs as the account \
             that can read this file.\n  \
             Fix: set `service_user = <account>` in defaults.conf, or grant this user group read.",
        ),
        Ok(Some(svc)) => msg.push_str(&format!(
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
    pub file: TokenFile,
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
    /// Effective user, for the unreadable-file message.
    pub current_user: String,
}

impl CaptureFacts {
    /// Gather the facts from the running process. The only IO in capture
    /// planning; `plan_token_capture` itself stays pure.
    pub(crate) fn from_runtime(
        paths: &Paths,
        kind: TokenKind,
        source: TokenSource,
        set_token: bool,
    ) -> Self {
        let path = kind.file(paths);
        let file = match token_file_status(path) {
            TokenFileStatus::Missing => TokenFile::Missing,
            TokenFileStatus::Unreadable { .. } => TokenFile::Unreadable,
            // A file that opens but holds no value for this key is not a
            // door: treat it as missing so setup asks for a token instead.
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
            mode: source.auth_mode(),
            force_prompt: source.forces_prompt(),
            tty: interactive_tty(),
            set_token,
            token_path: path.display().to_string(),
            current_user: privilege::current_user(),
        }
    }
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
    if facts.file == TokenFile::Present {
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

/// The only Manager-token write outside `write_token_file` itself.
fn store_captured(paths: &Paths, kind: TokenKind, token: &ManagerToken) -> Result<()> {
    let path = kind.file(paths).to_path_buf();
    let svc = Defaults::load(paths)?.service_user;
    write_token_file(&path, kind.env_var(), token, svc.as_deref())?;
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
    let facts = CaptureFacts::from_runtime(paths, kind, source, set_token);
    let (door, store) = match plan_token_capture(&facts) {
        CaptureDecision::Fail(msg) => return Err(Error::Message(msg)),
        CaptureDecision::Obtain { door, store } => (door, store),
    };
    let captured = match door {
        Door::Stdin => capture_from_stdin(kind, verify)?,
        Door::Prompt => capture_from_prompt(paths, kind, store, verify)?,
        Door::Env => capture_from_env(kind, verify)?,
        Door::File => capture_from_file(paths, kind, verify)?,
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

/// The token already on disk. A rejected one is never overwritten here:
/// rotating it is the operator's explicit `--set-token`.
fn capture_from_file<V>(
    paths: &Paths,
    kind: TokenKind,
    verify: &dyn Fn(&ManagerToken) -> Result<V>,
) -> Result<Capture<V>> {
    let key = kind.env_var();
    let path = kind.file(paths);
    let token = match read_token_file(path, key) {
        Ok(Some(token)) => token,
        Ok(None) => {
            return Err(Error::Message(format!(
                "{} no longer holds {key}",
                path.display()
            )))
        }
        Err(Error::Io { path, source }) => return Err(token_file_unreadable(paths, &path, source)),
        Err(e) => return Err(e),
    };
    verify_once(token, verify, |e| {
        format!(
            "{key} in {} rejected by the vault (nothing written; the file is unchanged)\n  \
             rotate it:  printf %s \"$TOKEN\" | vaulted-agent setup {} --set-token\n  {e}",
            path.display(),
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

/// The group a Manager-token file written now should carry, as a gid. Pure:
/// `gid_of` resolves an account's primary group (`None` for unknown).
///
/// Only root changes a file's group. The Service user wins, so the service
/// account can read the file after the sudo re-exec (stories #11, #40); an
/// unknown Service user means no change, never a fallback to the invoking
/// account. With no Service user the launch account is the invoking account,
/// so `SUDO_USER`'s group is used when it names a real, non-root account
/// (issue #150), the same choice the installer has always made.
pub(crate) fn token_file_gid(
    service_user: Option<&str>,
    sudo_user: Option<&str>,
    euid_root: bool,
    gid_of: impl Fn(&str) -> Option<u32>,
) -> Option<u32> {
    if !euid_root {
        return None;
    }
    match service_user.map(str::trim).filter(|u| !u.is_empty()) {
        Some(svc) => gid_of(svc),
        None => sudo_user
            .map(str::trim)
            .filter(|u| !u.is_empty() && *u != "root")
            .and_then(gid_of),
    }
}

/// Write `KEY=token` with mode 0640 through File replace, group chosen by
/// [`token_file_gid`] from `service_user`, `SUDO_USER` and the effective uid.
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
    let sudo_user = std::env::var("SUDO_USER").ok();
    let gid = token_file_gid(
        service_user,
        sudo_user.as_deref(),
        is_euid_root(),
        gid_for_user,
    );
    file_replace::replace(path, body.as_bytes(), Perms::Exact { mode: 0o640, gid })
        .map_err(|e| Error::config_write(path, e))
}

pub(crate) fn is_euid_root() -> bool {
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
    // Primary group of the account (`id -g user`); None when it is unknown.
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
            force_prompt: false,
            tty: true,
            set_token: false,
            token_path: "/etc/vaulted-agent/bws.env".into(),
            current_user: "root".into(),
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
                file: TokenFile::Unreadable,
                env_token,
                tty,
                set_token,
                force_prompt,
                ..facts()
            }));
            assert!(msg.contains("cannot be read"), "{msg}");
            assert!(msg.contains("bws.env"), "{msg}");
        }
    }

    #[test]
    fn file_mode_row_2_set_token_reads_stdin_over_env_file_and_force_prompt() {
        // Rotation door: an explicit argument beats ambient env, so a rotation
        // never silently stores the stale exported value.
        for (file, env_token, force_prompt) in [
            (TokenFile::Missing, false, false),
            (TokenFile::Present, true, false),
            (TokenFile::Missing, true, false),
            (TokenFile::Present, false, true),
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
            (TokenFile::Missing, false, true),
            (TokenFile::Present, false, false),
            (TokenFile::Present, true, true),
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
                file: TokenFile::Present,
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
                    file: TokenFile::Present,
                    tty,
                    ..facts()
                }),
                stored(Door::File)
            );
        }
        // -p with no terminal cannot paste, so the file still answers.
        assert_eq!(
            plan_token_capture(&CaptureFacts {
                file: TokenFile::Present,
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
            (false, TokenFile::Missing),
            (true, TokenFile::Present),
            (false, TokenFile::Unreadable),
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
            TokenFile::Missing,
            TokenFile::Present,
            TokenFile::Unreadable,
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
            TokenFile::Missing,
            TokenFile::Present,
            TokenFile::Unreadable,
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
    fn token_file_status_missing_is_not_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("op.env");
        assert!(matches!(token_file_status(&path), TokenFileStatus::Missing));
    }

    /// Accounts the group tests know: everyone else is unknown.
    fn known_gid(user: &str) -> Option<u32> {
        match user {
            "root" => Some(0),
            "svc" => Some(900),
            "jacob" => Some(1000),
            _ => None,
        }
    }

    #[test]
    fn token_file_group_is_the_service_users_over_sudo_user() {
        assert_eq!(
            token_file_gid(Some("svc"), Some("jacob"), true, known_gid),
            Some(900)
        );
        // An unknown Service user still wins: no fallback to the invoker.
        assert_eq!(
            token_file_gid(Some("ghost"), Some("jacob"), true, known_gid),
            None
        );
    }

    #[test]
    fn token_file_group_is_sudo_users_under_root_with_no_service_user() {
        assert_eq!(
            token_file_gid(None, Some("jacob"), true, known_gid),
            Some(1000)
        );
        assert_eq!(
            token_file_gid(Some("  "), Some("jacob"), true, known_gid),
            Some(1000),
            "a blank Service user is no Service user"
        );
    }

    #[test]
    fn token_file_group_unchanged_for_sudo_user_root_or_unknown() {
        assert_eq!(token_file_gid(None, Some("root"), true, known_gid), None);
        assert_eq!(token_file_gid(None, Some("ghost"), true, known_gid), None);
        assert_eq!(token_file_gid(None, Some(""), true, known_gid), None);
        assert_eq!(token_file_gid(None, None, true, known_gid), None);
    }

    #[test]
    fn token_file_group_unchanged_when_not_root() {
        assert_eq!(token_file_gid(None, Some("jacob"), false, known_gid), None);
        assert_eq!(
            token_file_gid(Some("svc"), Some("jacob"), false, known_gid),
            None
        );
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
