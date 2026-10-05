//! `refresh`: bring a Refs file up to date with what the vault holds now.
//!
//! `setup bitwarden` writes its Refs file through here too ([`setup_refs`]),
//! handing in the listing Token capture already fetched.
//!
//! What a run finds in the lines already in the file is a [`RefreshReport`]:
//! data, built before anything is decided, printed by one renderer. The Refs
//! module owns the file's grammar and its writes, which this module,
//! `edit-manifest` and the launch share; this module owns the policy about what to report and
//! what to change.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::auth::{TokenKind, TokenSource};
use crate::backend;
use crate::bitwarden::BwListing;
use crate::config::{Backend, Paths};
use crate::error::{Error, Result};
use crate::inventory::{AliasUse, Inventory};
use crate::onepassword::{self, OpField, OpItem, OpListing};
use crate::refs::{self, Mapping, RefEdit, RefFate, RefsStyle, ScannedRef, WriteMode};
use crate::setup_interview::{ask, LineReader};
use crate::vault_wiring;

pub fn cmd_refresh(paths: &Paths, args: &[String], token_source: TokenSource) -> Result<()> {
    let mut man_path: Option<String> = None;
    let mut take_all = false;
    let mut mode: Option<WriteMode> = None;
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
            "--merge" => mode = Some(WriteMode::Merge),
            "--replace" | "--rewrite" => mode = Some(WriteMode::Replace),
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

    let step = RefreshStep::new(be, exclude)?;
    refresh_refs(
        paths,
        Origin::Refresh,
        ListingSource::Fetch(token_source),
        step,
        RunOptions {
            man_path,
            take_all,
            mode,
            prune,
            interactive: io::IsTerminal::is_terminal(&io::stdin()),
        },
        &mut read_stdin_line,
    )
}

/// The production [`LineReader`] for `refresh`: one line from stdin, not the
/// controlling terminal, so a piped or redirected run reads what it was given.
fn read_stdin_line() -> Result<String> {
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| Error::Message(format!("stdin read: {e}")))?;
    Ok(line)
}

/// `setup bitwarden`'s write: every secret in `listing`, merged into the
/// Backend's Refs file when it exists, through the same flow as `refresh`.
///
/// The listing is the one Token capture fetched to prove the token live, so
/// the vault is asked once, and the manager token is already gone. An empty
/// listing is setup's to explain before calling here.
///
/// Non-interactive: it takes every secret and never opens the fix gate
/// (ADR-0003), so there is no question it could reach.
pub(crate) fn setup_refs(paths: &Paths, listing: BwListing) -> Result<()> {
    refresh_refs(
        paths,
        Origin::Setup,
        ListingSource::Given(listing),
        RefreshStep::Bitwarden,
        RunOptions {
            man_path: None,
            take_all: true,
            mode: None,
            prune: false,
            interactive: false,
        },
        &mut || unreachable!("setup bitwarden asks nothing"),
    )
}

/// The verb writing the Refs file. One value rather than loose flags because
/// it settles three things together — the header verb, the verb the
/// writability remedy names, and whether the fix gate may ever open — and a
/// setup run that prunes must not be expressible (ADR-0003).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    Refresh,
    Setup,
}

impl Origin {
    /// The command line, after the launcher, that re-runs this write.
    fn command(self) -> &'static str {
        match self {
            Origin::Refresh => "refresh",
            Origin::Setup => "setup bitwarden",
        }
    }

    /// The writer named in the Refs file header.
    fn header(self) -> &'static str {
        match self {
            Origin::Refresh => "vaulted-agent refresh",
            Origin::Setup => "vaulted-agent setup",
        }
    }
}

/// What the command line asked of one run. `setup` asks for every secret,
/// with the write mode settled by the file's presence, and never prunes.
struct RunOptions {
    /// An explicit Refs file; `None` is Vault wiring's choice.
    man_path: Option<String>,
    take_all: bool,
    /// `--merge` / `--replace`; `None` settles on whether the file exists.
    mode: Option<WriteMode>,
    prune: bool,
    /// Whether a human can answer, settled once by the entry point. The
    /// selection and the fix confirmation are asked only then.
    interactive: bool,
}

/// Where the flow's listing comes from.
enum ListingSource {
    /// Load the manager token and ask the vault (`refresh`).
    Fetch(TokenSource),
    /// Already fetched by Token capture (`setup bitwarden`).
    Given(BwListing),
}

/// Backend for a bare `refresh` (see [`Inventory::refresh_backend`]). An
/// unreadable harness directory gives no signal, so the Bitwarden fallback.
fn refresh_backend(paths: &Paths) -> Backend {
    Inventory::load(paths)
        .map(|inv| inv.refresh_backend())
        .unwrap_or(Backend::Bitwarden)
}

/// The Refs file for a bare `refresh` (story #13): Vault wiring's choice.
pub(crate) fn default_refs_file(paths: &Paths, be: Backend) -> Result<PathBuf> {
    // Only Bitwarden and 1Password have Refs files `refresh` writes;
    // `RefreshStep::new` refuses the rest before anything asks.
    vault_wiring::refs_file(paths, &Inventory::load(paths)?, be)
        .map_err(|e| match e {
            Error::SeveralManifests { .. } => Error::Message(format!(
                "{e}; pass one explicitly: vaulted-agent refresh <file>"
            )),
            e => e,
        })?
        .ok_or_else(|| Error::Message(format!("refresh: {be} has no Refs file")))
}

/// The part of `refresh` that differs per Backend: the listing, the selection
/// menu, turning the selection into mappings, and the facts the lines already
/// in the file are judged against. Everything else is `refresh_refs`, once.
///
/// An enum rather than a trait: there are exactly two Backends with Refs
/// files, and the CLI tests already drive both through fake `bws` / `op`.
enum RefreshStep {
    Bitwarden,
    /// Exclusion patterns: this run's, then (once the target is known) the
    /// ones the file records.
    OnePassword {
        exclusions: Vec<String>,
    },
}

impl RefreshStep {
    /// The step for `be`, or the refusal for a Backend or flag that has no
    /// business here.
    fn new(be: Backend, exclude: Vec<String>) -> Result<RefreshStep> {
        match be {
            Backend::Bitwarden if !exclude.is_empty() => Err(Error::Message(
                "refresh: --exclude applies to the onepassword backend only".into(),
            )),
            Backend::Bitwarden => Ok(RefreshStep::Bitwarden),
            Backend::OnePassword => Ok(RefreshStep::OnePassword {
                exclusions: exclude,
            }),
            other => Err(Error::Message(format!(
                "refresh does not apply to backend '{}'. It builds refs files, which only \
                 bitwarden and onepassword use; {} manifests are edited directly.",
                other.as_str(),
                other.as_str()
            ))),
        }
    }

    fn backend(&self) -> Backend {
        match self {
            RefreshStep::Bitwarden => Backend::Bitwarden,
            RefreshStep::OnePassword { .. } => Backend::OnePassword,
        }
    }

    fn style(&self) -> RefsStyle<'_> {
        match self {
            RefreshStep::Bitwarden => RefsStyle::Bitwarden,
            RefreshStep::OnePassword { exclusions } => RefsStyle::OnePassword { exclusions },
        }
    }

    /// Whether a renamed ref can be repaired in place. An `op://` line records
    /// no source id, so a renamed item is indistinguishable from a deleted one
    /// (ADR-0005).
    fn repairs(&self) -> bool {
        matches!(self, RefreshStep::Bitwarden)
    }

    fn exclusions(&self) -> Option<&[String]> {
        match self {
            RefreshStep::Bitwarden => None,
            RefreshStep::OnePassword { exclusions } => Some(exclusions),
        }
    }

    /// Put the patterns `path` already records ahead of this run's. Read here
    /// rather than inside the writer so the filtering stays visible: what was
    /// skipped is reported, never silently dropped.
    fn read_recorded_exclusions(&mut self, path: &Path) {
        let RefreshStep::OnePassword { exclusions } = self else {
            return;
        };
        let mut recorded = if path.is_file() {
            refs::read_exclusions(&fs::read_to_string(path).unwrap_or_default())
        } else {
            Vec::new()
        };
        for p in exclusions.drain(..) {
            if !recorded.contains(&p) {
                recorded.push(p);
            }
        }
        *exclusions = recorded;
    }

    /// List, let the operator choose, and turn the choice into mappings. The
    /// manager token, when one is needed, is loaded and dropped in here, so it
    /// is gone before the flow writes anything. `select` is `None` when the run
    /// takes everything without asking.
    fn gather(
        &self,
        paths: &Paths,
        listing: ListingSource,
        path: &Path,
        select: Option<&mut LineReader>,
    ) -> Result<Gathered> {
        match (self, listing) {
            (RefreshStep::Bitwarden, listing) => gather_bitwarden(paths, listing, select),
            (RefreshStep::OnePassword { exclusions }, ListingSource::Fetch(token_source)) => {
                gather_onepassword(paths, token_source, path, select, exclusions)
            }
            // Only `setup bitwarden` hands a listing in, and it is a `bws` one.
            (RefreshStep::OnePassword { .. }, ListingSource::Given(_)) => Err(Error::Message(
                "refresh: a Bitwarden listing cannot refresh a 1Password Refs file".into(),
            )),
        }
    }

    /// The line after the reports, saying what the write did.
    fn print_summary(
        &self,
        path: &Path,
        mode: WriteMode,
        mappings: usize,
        written: refs::RefsWrite,
    ) {
        // 1Password's item warnings and skip reports precede this line; a
        // blank line sets it apart from them.
        let lead = match self {
            RefreshStep::Bitwarden => "",
            RefreshStep::OnePassword { .. } => "\n",
        };
        match (mode, self) {
            (WriteMode::Replace, RefreshStep::Bitwarden) => {
                println!("Wrote refs file (replace): {}", path.display());
            }
            (WriteMode::Replace, RefreshStep::OnePassword { .. }) => {
                println!(
                    "{lead}Wrote refs file (replace, {mappings} mapping(s)): {}",
                    path.display()
                );
            }
            (WriteMode::Merge, _) => {
                if written.recovered > 0 {
                    println!(
                        "Split {} mapping(s) that were glued onto one line (va 0.3.0 refresh): {}",
                        written.recovered,
                        path.display()
                    );
                }
                if written.added == 0 {
                    if written.recovered == 0 {
                        println!("{lead}No new mappings to add: {}", path.display());
                    }
                } else {
                    println!(
                        "{lead}Updated refs file (+{} mapping(s)): {}",
                        written.added,
                        path.display()
                    );
                }
            }
        }
    }
}

/// What a Backend's step hands back to the flow.
struct Gathered {
    mappings: Vec<Mapping>,
    fetched: Fetched,
    /// Why there is nothing to write, when that is a refusal rather than a
    /// merge with nothing new (1Password only).
    refusal: Option<Error>,
}

/// What the lines already in the file are judged against.
enum Fetched {
    /// The `bws` listing.
    Bitwarden(BwListing),
    /// The item listing plus the fields of the items this run expanded, and
    /// nothing more (ADR-0005).
    OnePassword(OpListing),
}

impl Fetched {
    fn scan(&self, text: &str) -> Vec<ScannedRef> {
        match self {
            Fetched::Bitwarden(listing) => refs::scan_bitwarden_refs(text, listing),
            Fetched::OnePassword(listing) => refs::scan_op_refs(text, listing),
        }
    }
}

/// One write of a Refs file, whichever Backend `step` lists from and whichever
/// verb (`origin`) asked for it. Its questions, the selection and the fix
/// confirmation, are answered through `read`, and only when the run is
/// interactive.
fn refresh_refs(
    paths: &Paths,
    origin: Origin,
    listing: ListingSource,
    mut step: RefreshStep,
    opts: RunOptions,
    read: &mut LineReader,
) -> Result<()> {
    let RunOptions {
        man_path,
        take_all,
        mode,
        prune,
        interactive,
    } = opts;
    let path = match man_path {
        Some(man) => paths.resolve_manifest(&man),
        None => default_refs_file(paths, step.backend())?,
    };
    let mode = WriteMode::settle(mode, &path);

    // Best effort and before the probe: on a host without the directory the
    // probe would otherwise report a false "cannot write". A root-owned
    // directory still fails the probe, with its friendly message.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok();
    }
    // Checked before any vault work, not at the write. Expanding every
    // 1Password item costs a round trip apiece (~a minute on a 65-item vault);
    // discovering the file is root-owned only at the write meant paying all of
    // that to learn something knowable at the start.
    ensure_manifest_writable(&path, origin)?;
    step.read_recorded_exclusions(&path);

    // The manager token is loaded and dropped inside this step: nothing after
    // it can reach the vault, and nothing after it holds the token at the write.
    // Non-interactive without --all: all for replace, or merge all new.
    let select = (interactive && !take_all).then_some(&mut *read);
    let gathered = step.gather(paths, listing, &path, select)?;

    // After the listing, because it is what makes a verdict possible; before
    // the write, so a pruned line is gone by the time merge decides what to
    // append.
    if path.is_file() {
        let text = fs::read_to_string(&path).map_err(|e| Error::Io {
            path: path.clone(),
            source: e,
        })?;
        let scan = gathered.fetched.scan(&text);
        // An Inventory that cannot be read means no alias warnings, never a
        // failed refresh: the warnings are advice about files refresh does not
        // own.
        let inventory = Inventory::load(paths).ok();
        let report = RefreshReport::new(
            &scan,
            step.exclusions(),
            step.repairs(),
            mode,
            inventory.as_ref(),
        );
        // Exit status is unaffected by anything the report holds — `refresh`
        // is not a gate, `secrets validate` is (invariant 5), and it already
        // fails on a dangling ref.
        report.render(&path);
        let gate = Gate {
            origin,
            mode,
            prune,
            interactive,
        };
        apply_ref_edits(&path, &report.edits, gate, read)?;
    }
    if let Some(refusal) = gathered.refusal {
        return Err(refusal);
    }

    let written = refs::write_refs(
        &path,
        &gathered.mappings,
        mode,
        step.style(),
        origin.header(),
    )?;
    step.print_summary(&path, mode, gathered.mappings.len(), written);
    Ok(())
}

/// Bitwarden: pick from the secrets the token can see.
fn gather_bitwarden(
    paths: &Paths,
    listing: ListingSource,
    select: Option<&mut LineReader>,
) -> Result<Gathered> {
    let listing = match listing {
        ListingSource::Fetch(token_source) => {
            let token = token_source.load(paths, TokenKind::Bws)?;
            let listing = backend::bws_listing(&token)?;
            drop(token);
            listing
        }
        ListingSource::Given(listing) => listing,
    };
    if listing.is_empty() {
        return Err(Error::Message(
            "No secrets visible to this token yet.".into(),
        ));
    }

    let indices = match select {
        None => None, // all
        Some(read) => {
            println!("Secrets:");
            for (i, s) in listing.secrets().iter().enumerate() {
                println!("  {:2}) {}  {}  {}", i + 1, s.id, s.key, s.project);
            }
            ask_selection(read, "Secrets to include [all]: ", listing.len())?
        }
    };

    Ok(Gathered {
        mappings: Mapping::bitwarden_selection(&listing, indices.as_deref()),
        fetched: Fetched::Bitwarden(listing),
        refusal: None,
    })
}

/// What one `refresh` run found in the lines already in a Refs file, and the
/// edits it would make about them.
///
/// Each scanned line sits under exactly one fate group — or, for a mapping that
/// resolves but matches a recorded exclusion, under `excluded` — and a line
/// that resolves and is not excluded is in none. Built before anything is
/// decided, and rendered on every run whether or not the file changes.
///
/// Reporting happens on every run; changing the file never does on its own.
/// Removals and repairs ride the one `--prune` / confirmation gate, because
/// they are the same intent — fix this manifest — and a run that repairs one
/// line while leaving another broken would be harder to reason about than
/// either alone.
#[derive(Debug)]
struct RefreshReport<'a> {
    renamed: Vec<&'a ScannedRef>,
    dangling: Vec<&'a ScannedRef>,
    ambiguous: Vec<&'a ScannedRef>,
    unchecked: Vec<&'a ScannedRef>,
    unjudged: Vec<&'a ScannedRef>,
    /// Mappings that resolve but whose variable name a recorded exclusion now
    /// covers. Listed, never removed: an exclusion says what `refresh` may
    /// **add**, and prune removes only what does not resolve (ADR-0005).
    excluded: Vec<&'a ScannedRef>,
    /// Whether this run promises to repair a rename in place: the Backend can
    /// (only a source recording licenses a repair, ADR-0004), and the run is
    /// not `--replace`, which regenerates from the listing instead.
    repair_promised: bool,
    /// Harness aliases reading a renamed mapping that this run will not
    /// repair, so the variable goes under `--replace`.
    renamed_aliases: Vec<AliasUse<'a>>,
    /// Harness aliases reading a dangling mapping, which pruning removes.
    dangling_aliases: Vec<AliasUse<'a>>,
    /// Everything the scan says the file needs, repairs first.
    edits: Vec<(String, RefEdit)>,
}

impl<'a> RefreshReport<'a> {
    /// `exclusions` is given only by a Backend that records them; `can_repair`
    /// says whether the Backend can repair a rename at all. `inventory` is
    /// `None` when it could not be read, and then nothing warns about aliases.
    fn new(
        scan: &'a [ScannedRef],
        exclusions: Option<&[String]>,
        can_repair: bool,
        mode: WriteMode,
        inventory: Option<&'a Inventory>,
    ) -> RefreshReport<'a> {
        let mut report = RefreshReport {
            renamed: Vec::new(),
            dangling: Vec::new(),
            ambiguous: Vec::new(),
            unchecked: Vec::new(),
            unjudged: Vec::new(),
            excluded: Vec::new(),
            // `--replace` regenerates from the listing instead of repairing, so
            // the report must not promise a repair it will not perform.
            repair_promised: can_repair && mode != WriteMode::Replace,
            renamed_aliases: Vec::new(),
            dangling_aliases: Vec::new(),
            edits: Vec::new(),
        };
        for r in scan {
            let group = match r.fate {
                RefFate::Renamed => &mut report.renamed,
                RefFate::Dangling => &mut report.dangling,
                RefFate::Ambiguous => &mut report.ambiguous,
                RefFate::Unchecked => &mut report.unchecked,
                RefFate::Unjudged => &mut report.unjudged,
                // Only lines shown to resolve. Every other fate already has a
                // group of its own, and each says something this one would
                // contradict — a dangling line is about to go, and an unchecked
                // or unjudged line was never shown to resolve at all.
                RefFate::Resolvable => match exclusions {
                    Some(patterns) if refs::is_excluded(patterns, &r.var) => &mut report.excluded,
                    _ => continue,
                },
            };
            group.push(r);
        }
        // A repair keeps the variable name, so an `alias =` reading it keeps
        // working — that is why it keeps the name. `--replace` gives no such
        // promise: it remaps the secret under its new key and the old variable
        // goes. That is the one piece of cleanup refresh cannot do itself
        // (ADR-0003), so it has to be said out loud.
        if !report.repair_promised {
            report.renamed_aliases = vanishing_aliases(inventory, &report.renamed);
        }
        report.dangling_aliases = vanishing_aliases(inventory, &report.dangling);
        report.edits = plan_ref_edits(&report.renamed, &report.dangling);
        report
    }

    /// What the scan found, said before anything is decided about it.
    fn render(&self, path: &Path) {
        if !self.renamed.is_empty() {
            // Named as a rename because the recorded UUID proves it is one. The
            // old guess — "one went dangling, one appeared" — was rejected in
            // #80, and a wrong label is worse than none.
            println!(
                "Renamed secrets in {} ({} mapping(s) whose key changed in the vault):",
                path.display(),
                self.renamed.len()
            );
            for r in &self.renamed {
                println!("    {}", r.line);
                match (
                    self.repair_promised,
                    r.repaired_line(),
                    r.renamed_to.as_deref(),
                ) {
                    (true, Some(new), _) => println!("      -> {new}"),
                    (false, _, Some(key)) => println!("      now named {key} in the vault"),
                    _ => {}
                }
            }
            print_alias_warnings(
                &self.renamed_aliases,
                "a mapping whose secret was renamed in the vault. --replace remaps it \
                 under the new key, so the alias will fail that launch closed",
            );
        }
        if !self.dangling.is_empty() {
            print_ref_group(
                &format!(
                    "Dangling refs in {} ({} matching nothing this token can see):",
                    path.display(),
                    self.dangling.len()
                ),
                &self.dangling,
                None,
            );
            print_alias_warnings(
                &self.dangling_aliases,
                "a dangling mapping. Pruning it leaves the alias to fail that launch closed",
            );
        }
        if !self.ambiguous.is_empty() {
            // Not dangling, so never pruned: the secrets exist. Not repaired
            // either: which one was meant is the operator's call, and only a
            // recorded identity licenses a repair (ADR-0004).
            println!(
                "Ambiguous refs in {} ({} matching more than one secret — the launch \
                 fails closed rather than pick one):",
                path.display(),
                self.ambiguous.len()
            );
            for r in &self.ambiguous {
                println!("    {}", r.line);
                for s in &r.candidates {
                    println!("      matches uuid:{}  {}{}", s.id, s.key, s.project_note());
                }
            }
            println!(
                "  Qualify each with project:PROJECT/KEY, or pin one secret with uuid:UUID: \
                 vaulted-agent edit-manifest"
            );
            println!();
        }
        if !self.unchecked.is_empty() {
            // Said out loud rather than passed over, because silence here would
            // read as "these are fine". They are simply unexamined: the item is
            // there, and what it costs to look inside is the reason refresh asks
            // which items to expand (ADR-0005).
            print_ref_group(
                &format!(
                    "Refs this run did not check ({} — into items whose fields it did not read):",
                    self.unchecked.len()
                ),
                &self.unchecked,
                Some(
                    "Items you did not select, or that could not be read this run. \
                     `--all` expands every item.",
                ),
            );
            println!();
        }
        if !self.unjudged.is_empty() {
            // Reported separately and never pruned: prune removes what does not
            // resolve, and these have not been shown not to.
            print_ref_group(
                &format!(
                    "Refs refresh cannot judge ({} — shape is `vaulted-agent secrets validate`'s job):",
                    self.unjudged.len()
                ),
                &self.unjudged,
                None,
            );
            println!();
        }
        if !self.excluded.is_empty() {
            // Naming the file and the fix keeps the operator from having to
            // guess why a pattern did not make an existing variable go away.
            print_ref_group(
                &format!(
                    "Mapped but excluded in {} ({} matching a recorded exclusion — kept, because \
                     they still resolve):",
                    path.display(),
                    self.excluded.len()
                ),
                &self.excluded,
                Some("Remove one by hand if you meant it to go: vaulted-agent edit-manifest"),
            );
            println!();
        }
    }
}

/// One heading, the lines under it verbatim, and an optional closing note.
///
/// Every group the report prints has this shape, and they are read together —
/// an operator comparing "dangling" against "cannot judge" is comparing two
/// lists of file lines. Printing them through one function is what keeps them
/// looking like one report.
fn print_ref_group(heading: &str, refs: &[&ScannedRef], note: Option<&str>) {
    println!("{heading}");
    for r in refs {
        println!("    {}", r.line);
    }
    if let Some(n) = note {
        println!("  {n}");
    }
}

/// One warning per alias. `consequence` differs because the two ways a variable
/// can vanish — pruned, or regenerated away by `--replace` — need different
/// advice.
fn print_alias_warnings(aliases: &[AliasUse], consequence: &str) {
    for a in aliases {
        println!(
            "  ! harness {}: alias = {} = {} reads {consequence} \
             — edit the harness too.",
            a.harness, a.target, a.source
        );
    }
}

/// Harness aliases that name a variable about to disappear.
///
/// A warning, never a block: refresh changes the manifest, and the `alias =`
/// line naming it is in a harness file refresh does not own.
fn vanishing_aliases<'a>(
    inventory: Option<&'a Inventory>,
    vanishing: &[&ScannedRef],
) -> Vec<AliasUse<'a>> {
    let Some(inventory) = inventory else {
        return Vec::new();
    };
    if vanishing.is_empty() {
        return Vec::new();
    }
    let vars: Vec<&str> = vanishing.iter().map(|r| r.var.as_str()).collect();
    inventory.aliases_reading(&vars)
}

/// Everything a scan says this manifest needs, as one ordered edit list.
///
/// Repairs come first so a rename is fixed before anything is dropped, and both
/// kinds travel together: one list means one write, so a run cannot leave the
/// file half-corrected.
fn plan_ref_edits(renamed: &[&ScannedRef], dangling: &[&ScannedRef]) -> Vec<(String, RefEdit)> {
    let mut edits: Vec<(String, RefEdit)> = Vec::new();
    for r in renamed {
        if let Some(new) = r.repaired_line() {
            edits.push((r.line.clone(), RefEdit::Rewrite(new)));
        }
    }
    for r in dangling {
        edits.push((r.line.clone(), RefEdit::Remove));
    }
    edits
}

/// A planned or applied edit list in the operator's terms — a removal and a
/// repair are not the same act, and a prompt that blurs them is asking for a
/// wrong `y`.
fn describe_ref_edits(edits: &[(String, RefEdit)]) -> String {
    let repairs = edits
        .iter()
        .filter(|(_, e)| matches!(e, RefEdit::Rewrite(_)))
        .count();
    let removals = edits.len() - repairs;
    match (removals, repairs) {
        (0, n) => format!("Repair {n} renamed mapping(s)"),
        (n, 0) => format!("Remove {n} dangling mapping(s)"),
        (n, m) => format!("Remove {n} dangling and repair {m} renamed mapping(s)"),
    }
}

/// What `refresh` should do about the changes its scan wants to make.
///
/// Named for the change in general, not for pruning: the `--prune` flag now
/// gates repairs as well as removals (ADR-0004), and `CONTEXT.md` keeps
/// **prune** meaning removal alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefFixChoice {
    /// Nothing to change, so nothing to decide.
    NothingPending,
    /// `--replace` is about to regenerate the file, which prunes by
    /// construction. `--replace --prune` lands here: a harmless no-op rather
    /// than an error.
    ReplaceRegenerates,
    /// `--prune`: make the changes.
    Apply,
    /// A TTY is present: ask, defaulting to no.
    Ask,
    /// Non-interactive without `--prune`: report and change nothing.
    Report,
    /// `setup`: report, change nothing, and point at `refresh --prune`.
    LeaveToRefresh,
}

/// The decision, kept out of the I/O so it can be stated as a table.
///
/// For `setup` the answer is never — fixing a manifest is maintenance, and
/// `refresh` is the maintenance verb (ADR-0003) — whatever the TTY state.
fn ref_fix_choice(
    origin: Origin,
    pending: usize,
    prune_flag: bool,
    mode_is_replace: bool,
    interactive: bool,
) -> RefFixChoice {
    if pending == 0 {
        return RefFixChoice::NothingPending;
    }
    if origin == Origin::Setup {
        return RefFixChoice::LeaveToRefresh;
    }
    if mode_is_replace {
        return RefFixChoice::ReplaceRegenerates;
    }
    if prune_flag {
        return RefFixChoice::Apply;
    }
    if interactive {
        RefFixChoice::Ask
    } else {
        RefFixChoice::Report
    }
}

/// The selection question both Backends ask once their listing is printed.
/// A blank reply or a failed read means all (`None`); anything else is an
/// index list, and one that does not parse fails the run.
fn ask_selection(read: &mut LineReader, text: &str, n: usize) -> Result<Option<Vec<usize>>> {
    match ask(read, text) {
        Ok(line) if !line.trim().is_empty() => Ok(Some(refs::parse_index_list(line.trim(), n)?)),
        _ => Ok(None),
    }
}

/// The fix confirmation: only `y` / `yes`, in any case, applies. A blank,
/// failed or other reply is no.
fn ask_fix(read: &mut LineReader, what: &str) -> bool {
    ask(read, &format!("{what}? [y/N]: "))
        .is_ok_and(|line| matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// What the fix gate is decided from, besides the edits themselves.
struct Gate {
    origin: Origin,
    mode: WriteMode,
    prune: bool,
    interactive: bool,
}

impl Gate {
    /// [`ref_fix_choice`] for `pending` planned edits.
    fn choice(&self, pending: usize) -> RefFixChoice {
        ref_fix_choice(
            self.origin,
            pending,
            self.prune,
            self.mode == WriteMode::Replace,
            self.interactive,
        )
    }
}

/// Decide what to do about a report's planned edits, then do it.
///
/// Shared by both backends: the gate (`--prune`, an interactive yes, or report
/// and leave) and the surgical write are the same act whatever made a line
/// dangling. Only the classification differs.
fn apply_ref_edits(
    path: &Path,
    edits: &[(String, RefEdit)],
    gate: Gate,
    read: &mut LineReader,
) -> Result<()> {
    if edits.is_empty() {
        return Ok(());
    }
    let what = describe_ref_edits(edits);

    let apply = match gate.choice(edits.len()) {
        RefFixChoice::NothingPending => return Ok(()),
        RefFixChoice::ReplaceRegenerates => {
            println!("  --replace rewrites the file, so these go with it.\n");
            return Ok(());
        }
        RefFixChoice::Report => {
            println!("  Left in place. Re-run with --prune to apply.\n");
            return Ok(());
        }
        RefFixChoice::LeaveToRefresh => {
            println!("  Left in place. To apply: vaulted-agent refresh --prune\n");
            return Ok(());
        }
        RefFixChoice::Apply => true,
        RefFixChoice::Ask => ask_fix(read, &what),
    };
    if !apply {
        println!("  Left in place.\n");
        return Ok(());
    }

    let applied = refs::edit_refs_lines(path, edits)?;
    // Verbatim, because scrollback is the recovery path — refresh writes no
    // backup file into the root-owned manifest directory.
    println!("{}:", describe_ref_edits(&applied));
    for (line, edit) in &applied {
        match edit {
            RefEdit::Remove => println!("  - {line}"),
            RefEdit::Rewrite(new) => {
                println!("  - {line}");
                println!("  + {new}");
            }
        }
    }
    println!();
    Ok(())
}

/// Fail now if the refs file cannot be written later.
///
/// Manifests live in a root-owned directory, so `refresh` or `setup` run as the
/// operator or as the service user cannot write one. Nothing about that is
/// visible from the menu, and the expensive part sits between the two points.
fn ensure_manifest_writable(path: &Path, origin: Origin) -> Result<()> {
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
         sudo {exe} {}",
        path.display(),
        crate::privilege::current_user(),
        origin.command(),
    )))
}

/// 1Password: pick items from the vault, then turn each picked item's fields
/// into `VAR=op://VAULT/ITEM/FIELD` lines.
///
/// Selection is at ITEM level, not field level, for two reasons: an item is the
/// unit a person recognises, and `op item list` returns every item in one call
/// while fields cost one `op item get` per item. Expanding all items up front
/// would mean a per-item round trip before the menu could even be printed
/// (~50s on a 60-item vault). Only the chosen items are expanded.
fn gather_onepassword(
    paths: &Paths,
    token_source: TokenSource,
    path: &Path,
    select: Option<&mut LineReader>,
    exclusions: &[String],
) -> Result<Gathered> {
    let token = token_source.load(paths, TokenKind::Op)?;
    // What the run learned, for judging the mappings already in the file. Only
    // the items expanded below gain fields: `refresh` judges what it fetched
    // and nothing more (ADR-0005).
    let mut listing = backend::op_list_items(&token, None)?;
    if listing.is_empty() {
        return Err(Error::Message(
            "No 1Password items visible to this token yet.".into(),
        ));
    }

    let chosen = match select {
        None => None,
        Some(read) => {
            println!("Items visible to this token:");
            for (i, it) in listing.items().iter().enumerate() {
                println!("  {:2}) {}  ({})", i + 1, it.title, it.vault);
            }
            println!();
            ask_selection(
                read,
                "Items to include (e.g. 1,4,7 or 1-5,9 - blank for all): ",
                listing.len(),
            )?
        }
    };
    let indices = chosen.unwrap_or_else(|| (0..listing.len()).collect());

    // Fields are fetched only for the items actually chosen, one round trip
    // apiece, and each item's notes print as it lands: a minute-long run must
    // keep showing progress.
    let mut fold = OpFold::default();
    for i in indices {
        let item = listing.items()[i].clone();
        let fields = backend::op_item_json(&token, &item.id, Some(item.vault.as_str()))
            .and_then(|json| listing.expand(&item.id, &json));
        for note in fold.add(&item, fields, exclusions) {
            note.print(&item.title);
        }
    }
    drop(token);

    fold.print_left_out();
    let refusal = fold.refusal().map(|r| r.into_error(path));
    Ok(Gathered {
        mappings: fold.mappings,
        fetched: Fetched::OnePassword(listing),
        refusal,
    })
}

/// What the 1Password items a run expanded become, folded one item at a time.
/// No vault calls: each item arrives with its fields already fetched, or the
/// error that fetching them hit.
#[derive(Debug, Default)]
struct OpFold {
    mappings: Vec<Mapping>,
    /// Variable names a recorded or given exclusion kept out.
    excluded: Vec<String>,
    /// One item title per field that cannot be written as a reference.
    unrepresentable: Vec<String>,
    /// Titles of the items whose fields could not be read.
    unreadable: Vec<String>,
}

/// Something one item contributed that the operator sees as it happens.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ItemNote {
    /// Reading the item failed; the error, as it reads.
    Unreadable(String),
    /// The item has no field a reference could name.
    NoFields,
    /// A field, by label, whose section or label `op` cannot parse.
    Unrepresentable(String),
}

impl ItemNote {
    fn print(&self, title: &str) {
        match self {
            ItemNote::Unreadable(e) => eprintln!("  warn: {title}: {e}"),
            ItemNote::NoFields => println!("  {title}: no referenceable fields, skipped"),
            ItemNote::Unrepresentable(label) => eprintln!(
                "  warn: {title}: field '{label}' has characters op cannot parse, skipped"
            ),
        }
    }
}

/// Why a 1Password run has nothing to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpRefusal {
    /// Nothing selected has a field a reference could name.
    NothingReferenceable,
    /// Everything referenceable matched an exclusion: this many fields.
    AllExcluded(usize),
}

impl OpRefusal {
    fn into_error(self, path: &Path) -> Error {
        Error::Message(match self {
            OpRefusal::NothingReferenceable => "Nothing selected has a referenceable field.".into(),
            // Distinguishable from "the vault gave us nothing", because the
            // operator's own patterns caused this and the fix is to relax one.
            OpRefusal::AllExcluded(n) => format!(
                "Every referenceable field on what you selected matched an exclusion \
                 ({n} field(s)). Loosen a pattern in {} to map any of them.",
                path.display()
            ),
        })
    }
}

impl OpFold {
    /// Fold in one item. A per-item failure (transient 502 from the vault API,
    /// an item the token cannot read) must not discard the whole run — reading
    /// 60 items takes ~a minute, and refresh defaults to merge, so the next run
    /// picks up whatever was missed. Skips are reported, never silent.
    fn add(
        &mut self,
        item: &OpItem,
        fields: Result<Vec<OpField>>,
        exclusions: &[String],
    ) -> Vec<ItemNote> {
        let fields = match fields {
            Ok(fields) => fields,
            Err(e) => {
                self.unreadable.push(item.title.clone());
                return vec![ItemNote::Unreadable(e.to_string())];
            }
        };
        if fields.is_empty() {
            return vec![ItemNote::NoFields];
        }
        let mapped = onepassword::item_mappings(item, fields);
        let mut notes = Vec::new();
        for f in mapped.skipped {
            self.unrepresentable.push(item.title.clone());
            notes.push(ItemNote::Unrepresentable(f.label));
        }
        for m in mapped.mappings {
            if refs::is_excluded(exclusions, &m.var) {
                self.excluded.push(m.var);
                continue;
            }
            self.mappings
                .push(Mapping::onepassword(&m.var, &m.reference));
        }
        notes
    }

    /// Why there is nothing to write, if there is nothing.
    fn refusal(&self) -> Option<OpRefusal> {
        if !self.mappings.is_empty() {
            return None;
        }
        Some(if self.excluded.is_empty() {
            OpRefusal::NothingReferenceable
        } else {
            OpRefusal::AllExcluded(self.excluded.len())
        })
    }

    /// What was left out, and why, once every item is in.
    fn print_left_out(&self) {
        if !self.excluded.is_empty() {
            println!(
                "\n{} field(s) matched an exclusion and were left out: {}",
                self.excluded.len(),
                self.excluded.join(", ")
            );
        }

        if !self.unrepresentable.is_empty() {
            let mut names = self.unrepresentable.clone();
            names.sort();
            names.dedup();
            println!(
                "\n{} field(s) on {} item(s) cannot be written as a reference and were \
                 left out: {}\n\
                 Rename the section or field in the vault to use letters, digits, \
                 spaces, '.', '_' or '-' if you need them.",
                self.unrepresentable.len(),
                names.len(),
                names.join(", ")
            );
        }

        if !self.unreadable.is_empty() {
            println!(
                "\n{} item(s) could not be read and were left out: {}\n\
                 Re-run refresh to pick them up (merge only adds what is missing).",
                self.unreadable.len(),
                self.unreadable.join(", ")
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitwarden::BwSecret;

    const U1: &str = "00000000-0000-0000-0000-000000000001";

    /// `NEW_KEY` (U1, once `OLD_KEY`), `OPENAI_API_KEY`, and `DUP` twice.
    fn bw_listing() -> BwListing {
        BwListing::new(vec![
            BwSecret::new(U1, "NEW_KEY", "tools"),
            BwSecret::new(
                "00000000-0000-0000-0000-000000000002",
                "OPENAI_API_KEY",
                "tools",
            ),
            BwSecret::new("00000000-0000-0000-0000-000000000003", "DUP", "tools"),
            BwSecret::new("00000000-0000-0000-0000-000000000004", "DUP", "tools"),
        ])
    }

    /// `db.example.com` expanded with one `password` field; `github token`
    /// listed but never expanded.
    fn op_listing() -> OpListing {
        let mut l = OpListing::from_json(
            r#"[
              {"id":"id-host","title":"db.example.com","vault":{"id":"v","name":"Orchestrator"}},
              {"id":"id-other","title":"github token","vault":{"id":"v","name":"Orchestrator"}}
            ]"#,
        )
        .unwrap();
        l.expand(
            "id-host",
            r#"{"fields":[{"id":"f1","label":"password","type":"CONCEALED","value":"a"}]}"#,
        )
        .unwrap();
        l
    }

    /// A config directory whose one Harness aliases `vars`.
    fn aliasing(vars: &[&str]) -> (tempfile::TempDir, Inventory) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        fs::create_dir_all(&paths.harness_dir).unwrap();
        let mut conf = String::from("manifest = a.env\ncommand = kimi\n");
        for v in vars {
            conf.push_str(&format!("alias = TARGET_{v} = {v}\n"));
        }
        fs::write(paths.harness_dir.join("kimi.conf"), conf).unwrap();
        let inv = Inventory::load(&paths).unwrap();
        (tmp, inv)
    }

    fn vars(group: &[&ScannedRef]) -> Vec<String> {
        group.iter().map(|r| r.var.clone()).collect()
    }

    fn alias_sources(aliases: &[AliasUse]) -> Vec<String> {
        aliases.iter().map(|a| a.source.to_string()).collect()
    }

    const BW_TEXT: &str = "GONE=name:GONE\n\
                           KEEP=name:OPENAI_API_KEY\n\
                           OLD=name:OLD_KEY # uuid:00000000-0000-0000-0000-000000000001\n\
                           BOTH=name:DUP\n\
                           JUNK=not-a-reference\n";

    #[test]
    fn a_renamed_ref_under_replace_promises_no_repair_and_warns_its_alias() {
        let scan = refs::scan_bitwarden_refs(BW_TEXT, &bw_listing());
        let (_tmp, inv) = aliasing(&["OLD"]);
        let report = RefreshReport::new(&scan, None, true, WriteMode::Replace, Some(&inv));
        assert!(!report.repair_promised);
        assert_eq!(vars(&report.renamed), ["OLD"]);
        assert_eq!(alias_sources(&report.renamed_aliases), ["OLD"]);
    }

    #[test]
    fn a_renamed_ref_under_merge_is_repaired_and_its_alias_keeps_working() {
        let scan = refs::scan_bitwarden_refs(BW_TEXT, &bw_listing());
        let (_tmp, inv) = aliasing(&["OLD"]);
        let report = RefreshReport::new(&scan, None, true, WriteMode::Merge, Some(&inv));
        assert!(report.repair_promised);
        // The repair keeps the variable name, so nothing to warn about.
        assert!(report.renamed_aliases.is_empty());
        assert!(report.edits.contains(&(
            format!("OLD=name:OLD_KEY # uuid:{U1}"),
            RefEdit::Rewrite(format!("OLD=name:NEW_KEY # uuid:{U1}"))
        )));
    }

    #[test]
    fn a_backend_that_cannot_repair_promises_no_repair_even_on_merge() {
        let scan = refs::scan_bitwarden_refs(BW_TEXT, &bw_listing());
        let report = RefreshReport::new(&scan, None, false, WriteMode::Merge, None);
        assert!(!report.repair_promised);
    }

    #[test]
    fn a_dangling_ref_read_by_an_alias_gets_a_warning() {
        let scan = refs::scan_bitwarden_refs(BW_TEXT, &bw_listing());
        let (_tmp, inv) = aliasing(&["GONE", "KEEP"]);
        let report = RefreshReport::new(&scan, None, true, WriteMode::Merge, Some(&inv));
        assert_eq!(vars(&report.dangling), ["GONE"]);
        // Only the vanishing variable: KEEP resolves.
        assert_eq!(alias_sources(&report.dangling_aliases), ["GONE"]);
    }

    #[test]
    fn an_unreadable_inventory_means_no_alias_warnings() {
        let scan = refs::scan_bitwarden_refs(BW_TEXT, &bw_listing());
        let report = RefreshReport::new(&scan, None, true, WriteMode::Replace, None);
        assert!(report.renamed_aliases.is_empty());
        assert!(report.dangling_aliases.is_empty());
    }

    #[test]
    fn every_line_lands_in_exactly_one_group() {
        let scan = refs::scan_bitwarden_refs(BW_TEXT, &bw_listing());
        let report = RefreshReport::new(&scan, None, true, WriteMode::Merge, None);
        assert_eq!(vars(&report.dangling), ["GONE"]);
        assert_eq!(vars(&report.renamed), ["OLD"]);
        assert_eq!(vars(&report.ambiguous), ["BOTH"]);
        assert_eq!(vars(&report.unjudged), ["JUNK"]);
        assert!(report.unchecked.is_empty());
        // KEEP resolves, and Bitwarden records no exclusions: in no group.
        assert!(report.excluded.is_empty());
    }

    #[test]
    fn repairs_come_before_removals() {
        let scan = refs::scan_bitwarden_refs(BW_TEXT, &bw_listing());
        let report = RefreshReport::new(&scan, None, true, WriteMode::Merge, None);
        let kinds: Vec<&RefEdit> = report.edits.iter().map(|(_, e)| e).collect();
        assert!(matches!(kinds[..], [RefEdit::Rewrite(_), RefEdit::Remove]));
        assert_eq!(report.edits[1].0, "GONE=name:GONE");
    }

    #[test]
    fn ambiguous_and_unchecked_lines_are_never_planned_edits() {
        let scan = refs::scan_bitwarden_refs("BOTH=name:DUP\nJUNK=x\n", &bw_listing());
        let report = RefreshReport::new(&scan, None, true, WriteMode::Merge, None);
        assert_eq!(vars(&report.ambiguous), ["BOTH"]);
        assert_eq!(vars(&report.unjudged), ["JUNK"]);
        assert!(report.edits.is_empty());

        let scan = refs::scan_op_refs(
            "GH=op://Orchestrator/github token/credential\n",
            &op_listing(),
        );
        let report = RefreshReport::new(&scan, Some(&[]), false, WriteMode::Merge, None);
        assert_eq!(vars(&report.unchecked), ["GH"]);
        assert!(report.edits.is_empty());
    }

    #[test]
    fn a_resolvable_mapping_matched_by_an_exclusion_is_listed_and_kept() {
        let text = "DB_EXAMPLE_COM_PASSWORD=op://Orchestrator/db.example.com/password\n\
                    GONE=op://Orchestrator/vanished/password\n";
        let scan = refs::scan_op_refs(text, &op_listing());
        let patterns = vec!["*_PASSWORD".to_string(), "GONE".to_string()];
        let report = RefreshReport::new(&scan, Some(&patterns), false, WriteMode::Merge, None);
        assert_eq!(vars(&report.excluded), ["DB_EXAMPLE_COM_PASSWORD"]);
        // GONE matches a pattern too, but it is dangling: one line, one group.
        assert_eq!(vars(&report.dangling), ["GONE"]);
        assert_eq!(
            report.edits,
            [(
                "GONE=op://Orchestrator/vanished/password".to_string(),
                RefEdit::Remove
            )]
        );
    }

    #[test]
    fn exclusions_are_judged_only_when_the_backend_records_them() {
        let scan = refs::scan_bitwarden_refs("KEEP=name:OPENAI_API_KEY\n", &bw_listing());
        let report = RefreshReport::new(&scan, None, true, WriteMode::Merge, None);
        assert!(report.excluded.is_empty());
    }

    #[test]
    fn a_quoted_dangling_ref_is_pruned_as_one_physical_line() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bws.refs");
        let before = "KEEP=name:OPENAI_API_KEY\nA=\"name:GONE\"\nB=2\n";
        fs::write(&p, before).unwrap();
        let scan = refs::scan_bitwarden_refs(before, &bw_listing());
        let report = RefreshReport::new(&scan, None, true, WriteMode::Merge, None);
        assert_eq!(report.edits.len(), 1, "{:?}", report.edits);
        refs::edit_refs_lines(&p, &report.edits).unwrap();
        assert_eq!(
            fs::read_to_string(&p).unwrap(),
            "KEEP=name:OPENAI_API_KEY\nB=2\n"
        );
    }

    #[test]
    fn edits_are_described_in_the_operators_terms() {
        let remove = ("A".to_string(), RefEdit::Remove);
        let repair = ("B".to_string(), RefEdit::Rewrite("C".into()));
        assert_eq!(
            describe_ref_edits(std::slice::from_ref(&remove)),
            "Remove 1 dangling mapping(s)"
        );
        assert_eq!(
            describe_ref_edits(std::slice::from_ref(&repair)),
            "Repair 1 renamed mapping(s)"
        );
        assert_eq!(
            describe_ref_edits(&[repair, remove]),
            "Remove 1 dangling and repair 1 renamed mapping(s)"
        );
    }

    #[test]
    fn prune_decision_table() {
        use Origin::Refresh;
        // --prune removes; a TTY asks; neither reports and changes nothing.
        assert_eq!(
            ref_fix_choice(Refresh, 2, true, false, false),
            RefFixChoice::Apply
        );
        assert_eq!(
            ref_fix_choice(Refresh, 2, false, false, true),
            RefFixChoice::Ask
        );
        assert_eq!(
            ref_fix_choice(Refresh, 2, false, false, false),
            RefFixChoice::Report
        );
        // Nothing dangling is nothing to decide.
        assert_eq!(
            ref_fix_choice(Refresh, 0, true, false, true),
            RefFixChoice::NothingPending
        );
        // --replace already prunes by construction, so --replace --prune is a
        // harmless no-op rather than an error.
        assert_eq!(
            ref_fix_choice(Refresh, 3, true, true, true),
            RefFixChoice::ReplaceRegenerates
        );
    }

    #[test]
    fn setup_never_fixes_whatever_the_tty_or_flags() {
        // Fixing a manifest is maintenance, and `refresh` is the maintenance
        // verb (ADR-0003): setup reports and points there, never applies.
        for prune in [false, true] {
            for replace in [false, true] {
                for interactive in [false, true] {
                    assert_eq!(
                        ref_fix_choice(Origin::Setup, 2, prune, replace, interactive),
                        RefFixChoice::LeaveToRefresh
                    );
                }
            }
        }
        assert_eq!(
            ref_fix_choice(Origin::Setup, 0, false, false, true),
            RefFixChoice::NothingPending
        );
    }

    #[test]
    fn the_fallback_refs_file_follows_the_backend() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        assert_eq!(
            default_refs_file(&paths, Backend::Bitwarden).unwrap(),
            paths.manifest_dir.join("openai.env.refs")
        );
        assert_eq!(
            default_refs_file(&paths, Backend::OnePassword).unwrap(),
            paths.manifest_dir.join("onepassword.refs")
        );
    }

    // ---- the questions, through the line-reading seam ----

    /// A [`LineReader`] answering with `lines`, in order. Running out is a
    /// test failure: the run asked a question the script did not expect.
    fn scripted(lines: &[&str]) -> impl FnMut() -> Result<String> {
        let mut lines: std::collections::VecDeque<String> =
            lines.iter().map(|l| format!("{l}\n")).collect();
        move || {
            Ok(lines
                .pop_front()
                .expect("refresh asked one question too many"))
        }
    }

    fn never() -> impl FnMut() -> Result<String> {
        || panic!("the reader was called")
    }

    fn failing() -> impl FnMut() -> Result<String> {
        || Err(Error::Message("stdin read: gone".into()))
    }

    /// `ALPHA`, `BETA`, `GAMMA`: one secret each.
    fn abc_listing() -> BwListing {
        BwListing::new(vec![
            BwSecret::new("00000000-0000-0000-0000-00000000000a", "ALPHA", "tools"),
            BwSecret::new("00000000-0000-0000-0000-00000000000b", "BETA", "tools"),
            BwSecret::new("00000000-0000-0000-0000-00000000000c", "GAMMA", "tools"),
        ])
    }

    /// Everything [`abc_listing`] holds, plus one mapping to nothing.
    const ABC_AND_GONE: &str = "ALPHA=name:ALPHA\n\
                                BETA=name:BETA\n\
                                GAMMA=name:GAMMA\n\
                                GONE=name:GONE\n";

    /// One `refresh` of a Bitwarden Refs file holding `existing` (absent when
    /// `None`), listing [`abc_listing`]. Returns the file afterwards.
    fn refresh_with(
        existing: Option<&str>,
        take_all: bool,
        interactive: bool,
        read: &mut LineReader,
    ) -> Result<String> {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_config_dir(tmp.path());
        let file = paths.manifest_dir.join("t.refs");
        if let Some(text) = existing {
            fs::create_dir_all(&paths.manifest_dir).unwrap();
            fs::write(&file, text).unwrap();
        }
        refresh_refs(
            &paths,
            Origin::Refresh,
            ListingSource::Given(abc_listing()),
            RefreshStep::Bitwarden,
            RunOptions {
                man_path: Some(file.display().to_string()),
                take_all,
                mode: None,
                prune: false,
                interactive,
            },
            read,
        )?;
        Ok(fs::read_to_string(&file).unwrap())
    }

    /// The variables the file maps, in order.
    fn mapped(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|l| !l.starts_with('#') && l.contains('='))
            .filter_map(|l| l.split_once('=').map(|(var, _)| var))
            .collect()
    }

    #[test]
    fn an_interactive_selection_writes_exactly_what_was_picked() {
        let text = refresh_with(None, false, true, &mut scripted(&["1,3"])).unwrap();
        assert_eq!(mapped(&text), ["ALPHA", "GAMMA"]);
    }

    #[test]
    fn an_interactive_blank_selection_writes_everything() {
        let text = refresh_with(None, false, true, &mut scripted(&[""])).unwrap();
        assert_eq!(mapped(&text), ["ALPHA", "BETA", "GAMMA"]);
    }

    #[test]
    fn a_bad_selection_fails_the_run() {
        assert!(refresh_with(None, false, true, &mut scripted(&["9"])).is_err());
    }

    #[test]
    fn an_interactive_yes_removes_the_dangling_line() {
        for yes in ["y", "YES", " Yes "] {
            let text = refresh_with(Some(ABC_AND_GONE), true, true, &mut scripted(&[yes])).unwrap();
            assert_eq!(mapped(&text), ["ALPHA", "BETA", "GAMMA"], "reply {yes:?}");
        }
    }

    #[test]
    fn anything_but_yes_leaves_the_dangling_line() {
        for reply in ["", "n", "no", "yep"] {
            let text =
                refresh_with(Some(ABC_AND_GONE), true, true, &mut scripted(&[reply])).unwrap();
            assert_eq!(text, ABC_AND_GONE, "reply {reply:?}");
        }
        let text = refresh_with(Some(ABC_AND_GONE), true, true, &mut failing()).unwrap();
        assert_eq!(text, ABC_AND_GONE, "failed read");
    }

    #[test]
    fn the_selection_then_the_confirmation_share_one_reader() {
        let text =
            refresh_with(Some(ABC_AND_GONE), false, true, &mut scripted(&["2", "y"])).unwrap();
        assert_eq!(mapped(&text), ["ALPHA", "BETA", "GAMMA"]);
    }

    #[test]
    fn a_non_interactive_run_never_asks_and_changes_nothing() {
        let text = refresh_with(Some(ABC_AND_GONE), false, false, &mut never()).unwrap();
        assert_eq!(text, ABC_AND_GONE);
    }

    #[test]
    fn the_selection_question_reads_blank_or_failure_as_all() {
        let select = |read: &mut LineReader| ask_selection(read, "? ", 5);
        assert_eq!(select(&mut scripted(&[""])).unwrap(), None);
        assert_eq!(select(&mut scripted(&["   "])).unwrap(), None);
        assert_eq!(select(&mut failing()).unwrap(), None);
        assert_eq!(
            select(&mut scripted(&["all"])).unwrap(),
            Some(vec![0, 1, 2, 3, 4])
        );
        assert_eq!(
            select(&mut scripted(&["1-3,5"])).unwrap(),
            Some(vec![0, 1, 2, 4])
        );
        assert_eq!(
            select(&mut scripted(&["4-2"])).unwrap(),
            Some(vec![1, 2, 3])
        );
        assert!(select(&mut scripted(&["6"])).is_err());
        assert!(select(&mut scripted(&["x"])).is_err());
    }

    // ---- the 1Password item fold ----

    fn item(title: &str) -> OpItem {
        OpItem {
            id: format!("id-{title}"),
            title: title.to_string(),
            vault: "V".to_string(),
            vault_id: "v".to_string(),
        }
    }

    fn field(label: &str) -> OpField {
        OpField {
            section: None,
            label: label.to_string(),
        }
    }

    #[test]
    fn the_fold_maps_fields_and_keeps_out_what_an_exclusion_names() {
        let mut fold = OpFold::default();
        let notes = fold.add(
            &item("stripe"),
            Ok(vec![field("api key"), field("username")]),
            &["*_USERNAME".to_string()],
        );
        assert!(notes.is_empty());
        assert_eq!(
            fold.mappings,
            [Mapping::onepassword(
                "STRIPE_API_KEY",
                "op://V/stripe/api key"
            )]
        );
        assert_eq!(fold.excluded, ["STRIPE_USERNAME"]);
        assert_eq!(fold.refusal(), None);
    }

    #[test]
    fn the_fold_reports_unrepresentable_fields_and_unreadable_items() {
        let mut fold = OpFold::default();
        let notes = fold.add(
            &item("svc"),
            Ok(vec![field("token"), field("bad/label")]),
            &[],
        );
        assert_eq!(notes, [ItemNote::Unrepresentable("bad/label".into())]);
        assert_eq!(fold.unrepresentable, ["svc"]);

        let notes = fold.add(
            &item("flaky"),
            Err(Error::Message("502 from the vault".into())),
            &[],
        );
        assert_eq!(notes, [ItemNote::Unreadable("502 from the vault".into())]);
        assert_eq!(fold.unreadable, ["flaky"]);

        assert_eq!(
            fold.add(&item("empty"), Ok(vec![]), &[]),
            [ItemNote::NoFields]
        );
        assert_eq!(fold.mappings.len(), 1);
    }

    #[test]
    fn the_refusal_tells_nothing_referenceable_from_everything_excluded() {
        let mut fold = OpFold::default();
        fold.add(&item("empty"), Ok(vec![]), &[]);
        assert_eq!(fold.refusal(), Some(OpRefusal::NothingReferenceable));

        let mut fold = OpFold::default();
        fold.add(
            &item("stripe"),
            Ok(vec![field("api key"), field("username")]),
            &["STRIPE_*".to_string()],
        );
        assert_eq!(fold.refusal(), Some(OpRefusal::AllExcluded(2)));
    }
}
