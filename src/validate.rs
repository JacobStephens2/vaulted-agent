//! Manifest validation: the Manifest check, and the placeholder and
//! Bitwarden reference-form rules it applies.

use std::path::Path;

use crate::bitwarden::BwRef;
use crate::config::Backend;
use crate::error::{Error, Result};
use crate::onepassword;

pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// Placeholder check for operator-supplied *references* (not secret values).
/// Kept narrow so legitimate pass paths like `example.com/token` are accepted.
pub fn is_placeholder_ref(r: &str) -> bool {
    let low = r.to_ascii_lowercase();
    if low.is_empty() {
        return true;
    }
    if low.contains("00000000-0000-0000-0000-000000000000") || low.contains("replace_with") {
        return true;
    }
    low.starts_with("change_me")
        || low.starts_with("changeme")
        || low.starts_with("your_")
        || low.starts_with("placeholder")
        || low == "todo"
        || low.starts_with("todo_")
        || low == "xxx"
        || low.starts_with("xxx_")
        || low == "example"
        || low == "replace"
}

/// Strong signals only — applied to decrypted secret *values* (sops/plainfile).
/// A password containing the substring "REPLACE" must not fail closed.
pub fn is_placeholder_secret_value(val: &str) -> bool {
    let low = val.to_ascii_lowercase();
    if low.is_empty() {
        return false;
    }
    low.contains("replace_with")
        || low.contains("change_me")
        || low.contains("00000000-0000-0000-0000-000000000000")
        || low == "changeme"
        || low == "placeholder"
        || low == "todo"
        || low == "xxx"
}

pub fn validate_var_name(var: &str) -> bool {
    let mut chars = var.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Why a Bitwarden reference will not resolve, or `None` when it is well-formed.
fn bitwarden_ref_problem(var: &str, r: &str) -> Option<String> {
    if is_placeholder_ref(r) {
        return Some(format!("{var} still has placeholder ref {r}"));
    }
    // None of the four Bitwarden reference forms contain `=`. A second
    // `VAR=name:KEY` glued onto this one is the bash 0.3.0 refresh merge
    // (command substitution strips the trailing newline). Fail closed with
    // the recovered lines rather than sending the blob to the vault.
    if r.contains('=') {
        let glued = format!("{var}={r}");
        if let Some(parts) = crate::refs::split_glued_bitwarden_line(&glued) {
            let listed = parts
                .iter()
                .map(|p| format!("  {p}"))
                .collect::<Vec<_>>()
                .join("\n");
            return Some(format!(
                "{var} looks like several mappings glued onto one line \
                 (va 0.3.0 refresh merge dropped the newlines). \
                 Split each onto its own line:\n{listed}\n\
                 Or run: vaulted-agent refresh"
            ));
        }
        return Some(format!(
            "{var} bad bitwarden ref {r} (a reference cannot contain '=')"
        ));
    }
    // The shared parse decides what is well-formed, so anything this accepts
    // the launch and `refresh` read the same way (issue #120). What follows is
    // only the wording for each way of being malformed.
    if BwRef::parse(r).is_some() {
        return None;
    }
    Some(if r.starts_with("uuid:") {
        format!("{var} uuid: value is not a UUID: {r}")
    } else if r.starts_with("name:") {
        format!("{var} empty name: ref")
    } else if r.starts_with("project:") {
        format!("{var} want project:PROJECT/SECRET (got {r})")
    } else {
        format!(
            "{var} bad bitwarden ref {r} (use UUID, uuid:UUID, name:KEY, or project:PROJECT/KEY)"
        )
    })
}

/// The reference `backend` reads from a Manifest entry's value.
///
/// A Bitwarden refs line may record the secret it was generated from as a
/// trailing `# uuid:…` (ADR-0004). Stripping it here — once, at the one seam
/// every reader already goes through — is the whole cost of the format change
/// on the launch path (story #44): `resolve_bitwarden` never learns the
/// recording exists.
///
/// Bitwarden only. A plainfile or sops manifest holds secret *values*, where a
/// `#` is material and dropping the tail would truncate it.
fn reference_for(backend: Option<Backend>, value: &str) -> &str {
    match backend {
        Some(Backend::Bitwarden) => crate::refs::reference_of(value),
        _ => value,
    }
}

/// The rule `backend` applies to a non-empty reference, as a message without
/// its line prefix.
fn backend_problem(backend: Backend, var: &str, r: &str) -> Option<String> {
    match backend {
        Backend::Bitwarden => bitwarden_ref_problem(var, r),
        Backend::OnePassword | Backend::Pass => {
            is_placeholder_ref(r).then(|| format!("{var} still has placeholder ref {r}"))
        }
        Backend::Plainfile | Backend::Sops => {
            is_placeholder_secret_value(r).then(|| format!("{var} looks like a placeholder value"))
        }
    }
}

/// One thing wrong with a Manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// 1-based physical line the problem is reported on.
    pub line: usize,
    /// The full message, `line N: …` prefix included.
    pub message: String,
    /// Whether the launch refuses the Manifest over it. Advisory problems
    /// (a duplicate variable, `op://` text op cannot read) never block.
    pub blocks: bool,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// What the Manifest check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Checked {
    /// Every Manifest entry as `(variable, reference)`, in file order, with the
    /// Bitwarden source recording stripped when Bitwarden reads the Manifest.
    pub entries: Vec<(String, String)>,
    /// Every problem, in line order.
    pub problems: Vec<Problem>,
}

impl Checked {
    /// The launch gate's projection: the first blocking problem, else the
    /// entries.
    pub fn gate(self) -> std::result::Result<Vec<(String, String)>, Problem> {
        match self.problems.into_iter().find(|p| p.blocks) {
            Some(p) => Err(p),
            None => Ok(self.entries),
        }
    }
}

/// The Manifest check: every problem in `text` as `backends` would read it.
///
/// The one judge of a Manifest. The launch gate (through
/// [`validate_manifest_file`]) fails on the first blocking problem; the editor
/// shows them all, so the operator fixes everything in one pass and never
/// hears "no problems" about a file the launch refuses.
///
/// Each Backend's rules run, and a problem two Backends find is reported once.
/// With no Backends — a Manifest nothing on the machine reads — only the rules
/// every Backend shares run, plus the `op://` advisories.
///
/// The blocking set is the launch policy and stays exactly what the gate has
/// always failed on: parser faults, an empty value, each Backend's placeholder
/// rule and the Bitwarden reference forms.
///
/// The `op://` advisories earn their place for 1Password. A reference `op
/// inject` cannot read does not fail alone: the scanner stops at the offending
/// character, the reference comes out truncated, and the whole injection
/// aborts. One typo therefore costs every other variable in the file, so it is
/// worth catching while the editor is still open. Comments are included: inject
/// reads them. No other Backend feeds the file to `op inject`.
pub fn check_manifest(text: &str, backends: &[Backend]) -> Checked {
    let mut problems: Vec<Problem> = Vec::new();
    let mut push = |line: usize, msg: String, blocks: bool| {
        let message = format!("line {line}: {msg}");
        if !problems.iter().any(|p| p.message == message) {
            problems.push(Problem {
                line,
                message,
                blocks,
            });
        }
    };

    // Structural faults (bad names, unbalanced quotes, a value that runs off
    // the end) and the entries below come from the same parser resolve uses,
    // so every reader agrees about what each mapping is.
    let parsed = crate::manifest_entry::parse(text);
    for fault in &parsed.faults {
        // The parser's message already carries its `line N:` prefix.
        let msg = fault
            .message
            .strip_prefix(&format!("line {}: ", fault.line))
            .unwrap_or(&fault.message)
            .to_string();
        push(fault.line, msg, true);
    }

    let op_advisories = backends.is_empty() || backends.contains(&Backend::OnePassword);
    if op_advisories {
        for n in comment_lines_with_op_refs(text) {
            push(
                n,
                "comment contains a secret reference (op://…). \
                 `op inject` resolves references in comments too, and one that fails \
                 aborts the whole manifest"
                    .to_string(),
                false,
            );
        }
    }

    // `None` stands for "no Backend known": the shared rules still run.
    let readers: Vec<Option<Backend>> = if backends.is_empty() {
        vec![None]
    } else {
        backends.iter().copied().map(Some).collect()
    };
    let entries_backend = backends
        .contains(&Backend::Bitwarden)
        .then_some(Backend::Bitwarden);

    let mut seen: Vec<&str> = Vec::new();
    let mut entries = Vec::with_capacity(parsed.entries.len());
    for entry in &parsed.entries {
        let (n, var, value) = (entry.first_line, entry.var.as_str(), entry.value.as_str());
        for &backend in &readers {
            let r = reference_for(backend, value);
            if r.is_empty() {
                push(n, format!("empty reference for {var}"), true);
            } else if let Some(msg) = backend.and_then(|b| backend_problem(b, var, r)) {
                push(n, msg, true);
            }
        }
        if seen.contains(&var) {
            push(n, format!("{var} is set more than once"), false);
        } else {
            seen.push(var);
        }
        if op_advisories && value.starts_with("op://") && !onepassword::is_readable(value) {
            push(
                n,
                format!(
                    "{var} has a reference op cannot parse ({value}) \u{2014} \
                     one such reference aborts the whole manifest, not just this line"
                ),
                false,
            );
        }
        entries.push((
            var.to_string(),
            reference_for(entries_backend, value).to_string(),
        ));
    }

    // Line order for the editor. Stable, so problems on one line keep the
    // order the rules above found them in.
    problems.sort_by_key(|p| p.line);
    Checked { entries, problems }
}

/// 1-based line numbers of `#` comments that contain an `op://` token.
///
/// `op inject` resolves references in comments too; one failed lookup aborts
/// the whole file. Shared by doctor and the Manifest check so the two agree.
pub fn comment_lines_with_op_refs(text: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.trim_start();
        if !line.starts_with('#') {
            continue;
        }
        // Same rough scanner as op: a whitespace-delimited token that claims
        // to be a reference is enough to fail inject if it does not resolve.
        for tok in line.split_whitespace() {
            if tok.starts_with("op://") {
                lines.push(n + 1);
                break;
            }
        }
    }
    lines
}

/// The launch's pre-flight gate: read `path` and run the Manifest check for
/// `backend`, failing on the first blocking problem.
pub fn validate_manifest_file(path: &Path, backend: Backend) -> Result<Vec<(String, String)>> {
    let text = std::fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    check_manifest(&text, &[backend])
        .gate()
        .map_err(|p| Error::Message(format!("{}: {p}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The editor's projection: every message.
    fn messages(text: &str, backends: &[Backend]) -> Vec<String> {
        check_manifest(text, backends)
            .problems
            .into_iter()
            .map(|p| p.message)
            .collect()
    }

    /// The gate's projection, as the error text it fails with (no path).
    fn gate(text: &str, backend: Backend) -> std::result::Result<Vec<(String, String)>, String> {
        check_manifest(text, &[backend])
            .gate()
            .map_err(|p| p.message)
    }

    #[test]
    fn comment_lines_with_op_refs_finds_only_references() {
        let text = "\
# prose about 1Password, no reference\n\
# see op://Vault/item/field\n\
GOOD=op://Vault/item/field\n\
# TODO: clean this up\n";
        assert_eq!(comment_lines_with_op_refs(text), vec![2]);
    }

    #[test]
    fn check_flags_comment_refs() {
        let text = "# note op://Vault/x/y\nA=op://Vault/item/field\n";
        let p = messages(text, &[]);
        assert!(
            p.iter()
                .any(|s| s.contains("comment") && s.contains("line 1")),
            "{p:?}"
        );
    }

    #[test]
    fn rejects_placeholder() {
        assert!(bitwarden_ref_problem("X", "REPLACE_WITH_BITWARDEN_SECRET_UUID").is_some());
    }

    #[test]
    fn accepts_name_ref() {
        assert!(bitwarden_ref_problem("OPENAI_API_KEY", "name:openai-api-key").is_none());
    }

    #[test]
    fn validate_accepts_exactly_what_the_shared_parse_accepts() {
        for r in [
            "6a1c0e94-1111-2222-3333-444444444444",
            "uuid:6a1c0e94-1111-2222-3333-444444444444",
            "uuid:not-a-uuid",
            "name:KEY",
            "name:a/b",
            "name:",
            "project:P/a/b",
            "project:P",
            "project:/KEY",
            "project:P/",
            "REPLACE_WITH_BITWARDEN_SECRET_UUID",
            "00000000-0000-0000-0000-000000000000",
            "name:A=name:B",
            "junk",
        ] {
            assert_eq!(
                bitwarden_ref_problem("X", r).is_none(),
                BwRef::parse(r).is_some(),
                "{r}"
            );
        }
    }

    #[test]
    fn accepts_uuid() {
        assert!(bitwarden_ref_problem("X", "6a1c0e94-1111-2222-3333-444444444444").is_none());
    }

    #[test]
    fn pass_path_example_com_is_not_placeholder() {
        assert!(!is_placeholder_ref("example.com/token"));
        assert!(gate("API=example.com/token\n", Backend::Pass).is_ok());
    }

    #[test]
    fn unknown_backend_is_a_type_error_not_a_match_arm() {
        // Compiles only because Backend is exhaustive — this documents the intent.
        let _ = Backend::Plainfile;
    }

    #[test]
    fn secret_value_with_replace_substring_is_ok() {
        assert!(!is_placeholder_secret_value("please-REPLACE-this-password"));
        assert!(is_placeholder_secret_value("REPLACE_WITH_SECRET"));
    }

    #[test]
    fn validate_shares_quote_stripping_with_resolve() {
        let pairs = gate("QUOTED=\"hello world\"\n", Backend::Plainfile).unwrap();
        assert_eq!(pairs, vec![("QUOTED".into(), "hello world".into())]);
    }

    #[test]
    fn validate_multiline_does_not_split_continuation() {
        let pairs = gate("PEM=\"line1\nline2\"\n", Backend::Plainfile).unwrap();
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].1, "line1\nline2");
    }

    // ---- annotated bitwarden refs (issue #82, ADR-0004) ----

    #[test]
    fn an_annotated_bitwarden_ref_reaches_resolve_as_the_bare_reference() {
        // The launch path is deliberately small (story #44): stripping the
        // recording happens once, here, and `resolve_bitwarden` never learns
        // the format changed.
        let u = "11111111-1111-1111-1111-111111111111";
        let text = format!("ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:{u}\n");
        let pairs = gate(&text, Backend::Bitwarden).unwrap();
        assert_eq!(
            pairs,
            vec![(
                "ASSEMBLY_AI_API_KEY".to_string(),
                "name:ASSEMBLY_AI_API_KEY".to_string()
            )]
        );
    }

    #[test]
    fn a_stale_recording_does_not_fail_the_pre_flight_gate() {
        // The line resolves, so validate must not block it (invariant 5). A
        // disagreement between the recording and the key is `refresh`'s signal
        // to report a rename, not a misconfiguration.
        let text = "A=name:A_KEY # uuid:11111111-1111-1111-1111-111111111111\n";
        assert!(gate(text, Backend::Bitwarden).is_ok());
    }

    #[test]
    fn a_hash_inside_a_secret_value_is_still_part_of_the_value() {
        // The recording is a Bitwarden-refs concept. Stripping comments from
        // dotenv secret material would silently truncate passwords.
        let pairs = gate("PW=s3cret # not-a-comment\n", Backend::Plainfile).unwrap();
        assert_eq!(pairs[0].1, "s3cret # not-a-comment");
    }

    #[test]
    fn an_annotation_cannot_smuggle_a_placeholder_past_the_gate() {
        // Invariant 4: the reference itself is what must be real.
        let text = "A=name: # uuid:11111111-1111-1111-1111-111111111111\n";
        assert!(gate(text, Backend::Bitwarden).is_err());
    }

    #[test]
    fn a_glued_0_3_0_refresh_line_fails_closed_with_the_recovered_mappings() {
        // The launch used to send the whole blob to the vault and report
        // `no secret matched 'name:META_AI_API_KEYFIREWORKS_API_KEY=name:…'`.
        // Shape is validate's job (CONTEXT.md: malformed ref).
        let text = "META_AI_API_KEY=name:META_AI_API_KEYFIREWORKS_API_KEY=name:FIREWORKS_API_KEYELEVENLABS_API_KEY=name:ELEVENLABS_API_KEY\n";
        let err = gate(text, Backend::Bitwarden).unwrap_err().to_string();
        assert!(err.contains("glued onto one line"), "{err}");
        assert!(
            err.contains("META_AI_API_KEY=name:META_AI_API_KEY"),
            "{err}"
        );
        assert!(
            err.contains("FIREWORKS_API_KEY=name:FIREWORKS_API_KEY"),
            "{err}"
        );
        assert!(
            err.contains("ELEVENLABS_API_KEY=name:ELEVENLABS_API_KEY"),
            "{err}"
        );
        assert!(err.contains("vaulted-agent refresh"), "{err}");
    }

    // ---- manifest entries (issue #112) ----

    #[test]
    fn check_accepts_a_bare_multiline_json_value() {
        // Parses and launches, so the editor must not call it broken.
        let text = "A=1\nSA={\n  \"type\": \"service_account\",\n  \"tok\": \"ab==\"\n}\n\nB=2\n";
        assert!(crate::config::parse_dotenv_pairs(text).is_ok());
        assert_eq!(messages(text, &[]), Vec::<String>::new());
    }

    #[test]
    fn check_accepts_base64_continuation_lines() {
        // Padding on a continuation line once read as an assignment to the
        // text before it, and so as a bad variable name.
        let text = "K=-----BEGIN KEY-----\nMIIB+gA/x==\nMIIB+gA/x==\n-----END KEY-----\n";
        assert_eq!(messages(text, &[]), Vec::<String>::new());
    }

    #[test]
    fn check_accepts_a_double_quoted_multiline_value() {
        let text = "PEM=\"line1\nA=b\nline3\"\nA=1\n";
        assert_eq!(messages(text, &[]), Vec::<String>::new());
    }

    #[test]
    fn check_reports_a_quoted_unparseable_op_ref() {
        let p = messages("A=\"op://Vault/bad|item/field\"\n", &[]);
        assert!(
            p.iter()
                .any(|s| s.starts_with("line 1: A has a reference op cannot parse")),
            "{p:?}"
        );
    }

    #[test]
    fn check_lists_every_structural_fault() {
        let p = messages("A=1\n\nMY-VAR=x\nB=2\n\noops\nA=3\n", &[]);
        assert_eq!(
            p,
            vec![
                "line 3: bad variable name MY-VAR".to_string(),
                "line 6: expected KEY=value".to_string(),
                "line 7: A is set more than once".to_string(),
            ]
        );
    }

    // ---- one Manifest check for the gate and the editor (issue #138) ----

    #[test]
    fn what_the_editor_once_called_clean_the_check_reports_as_the_gate_does() {
        // Each of these launched-refused but edited-clean before issue #138.
        for (text, want) in [
            ("X=\n", "line 1: empty reference for X"),
            (
                "X=REPLACE_WITH_UUID\n",
                "line 1: X still has placeholder ref REPLACE_WITH_UUID",
            ),
            ("X=name:\n", "line 1: X empty name: ref"),
            (
                "X=uuid:nope\n",
                "line 1: X uuid: value is not a UUID: uuid:nope",
            ),
        ] {
            let checked = check_manifest(text, &[Backend::Bitwarden]);
            let blocking: Vec<&Problem> = checked.problems.iter().filter(|p| p.blocks).collect();
            assert_eq!(blocking.len(), 1, "{text:?}: {:?}", checked.problems);
            assert_eq!(blocking[0].message, want, "{text:?}");
            assert_eq!(blocking[0].line, 1);
            assert_eq!(gate(text, Backend::Bitwarden), Err(want.to_string()));
        }
    }

    #[test]
    fn the_gate_names_the_line_of_the_first_blocking_problem() {
        let err = gate("A=name:A\n# note\nB=name:B\nC=name:\n", Backend::Bitwarden).unwrap_err();
        assert_eq!(err, "line 4: C empty name: ref");
    }

    #[test]
    fn the_file_gate_prefixes_the_path_to_the_lined_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.env.tpl");
        std::fs::write(&path, "A=name:A\n\nX=\n").unwrap();
        let err = validate_manifest_file(&path, Backend::Bitwarden)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            format!("{}: line 3: empty reference for X", path.display())
        );
    }

    #[test]
    fn advisory_problems_never_block_the_launch() {
        let text = "# see op://V/i/f\nA=op://V/db-admin (rw)/pass\nA=op://V/i/f\n";
        let checked = check_manifest(text, &[Backend::OnePassword]);
        assert_eq!(checked.problems.len(), 3, "{:?}", checked.problems);
        assert!(checked.problems.iter().all(|p| !p.blocks));
        assert_eq!(checked.gate().unwrap().len(), 2);
    }

    #[test]
    fn op_advisories_run_only_for_onepassword_or_no_backend() {
        let text = "# see op://V/i/f\nA=op://V/db-admin (rw)/pass\n";
        assert_eq!(messages(text, &[]).len(), 2);
        assert_eq!(messages(text, &[Backend::OnePassword]).len(), 2);
        assert_eq!(messages(text, &[Backend::Plainfile]), Vec::<String>::new());
        assert_eq!(
            messages(text, &[Backend::Plainfile, Backend::OnePassword]).len(),
            2
        );
    }

    #[test]
    fn a_duplicate_is_advisory_on_every_backend() {
        let checked = check_manifest("A=1\nA=2\n", &[Backend::Plainfile]);
        assert_eq!(
            checked.problems,
            vec![Problem {
                line: 2,
                message: "line 2: A is set more than once".into(),
                blocks: false,
            }]
        );
    }

    #[test]
    fn without_a_backend_only_the_shared_blocking_rules_run() {
        // Which placeholder rule applies depends on the Backend, so none does.
        assert_eq!(messages("X=REPLACE_WITH_UUID\n", &[]), Vec::<String>::new());
        let checked = check_manifest("X=\n", &[]);
        assert_eq!(checked.problems.len(), 1);
        assert!(checked.problems[0].blocks);
        assert_eq!(checked.problems[0].message, "line 1: empty reference for X");
    }

    #[test]
    fn each_backend_s_rules_run_and_a_shared_finding_is_reported_once() {
        let text = "X=REPLACE_WITH_SECRET\nY=\n";
        let p = messages(text, &[Backend::OnePassword, Backend::Pass, Backend::Sops]);
        assert_eq!(
            p,
            vec![
                "line 1: X still has placeholder ref REPLACE_WITH_SECRET".to_string(),
                "line 1: X looks like a placeholder value".to_string(),
                "line 2: empty reference for Y".to_string(),
            ]
        );
    }

    #[test]
    fn parser_faults_block_and_keep_their_message() {
        let checked = check_manifest("A=1\n\nMY-VAR=x\n", &[Backend::Plainfile]);
        assert_eq!(
            checked.problems,
            vec![Problem {
                line: 3,
                message: "line 3: bad variable name MY-VAR".into(),
                blocks: true,
            }]
        );
    }

    #[test]
    fn entries_strip_the_recording_only_when_bitwarden_reads_the_manifest() {
        let u = "11111111-1111-1111-1111-111111111111";
        let text = format!("A=name:A_KEY # uuid:{u}\n");
        assert_eq!(
            check_manifest(&text, &[Backend::Bitwarden]).entries,
            vec![("A".to_string(), "name:A_KEY".to_string())]
        );
        assert_eq!(
            check_manifest(&text, &[]).entries,
            vec![("A".to_string(), format!("name:A_KEY # uuid:{u}"))]
        );
    }
}
