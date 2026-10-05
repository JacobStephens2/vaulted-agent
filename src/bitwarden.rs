//! The **Bitwarden listing**: the secrets one manager token can see, as one
//! `bws secret list` returns them, and the one place a Bitwarden reference is
//! parsed and looked up against them.
//!
//! It also owns the rest of the Bitwarden refs-line grammar: why a reference
//! is malformed ([`BwRefFault`]), the trailing annotation that carries a
//! **Source recording**, the generated `name:` line, key → variable naming and
//! 0.3.0 glued-line recovery. The Refs file module only scans, judges and
//! writes; 1Password keeps its own grammar in `onepassword`.
//!
//! The launch, `refresh`'s scan, the Refs file writer and the offline shape
//! check all ask this module, so they give the same answer by construction.
//! Four private matchers used to disagree: `refresh` called a `name:` that
//! matched two secrets healthy while the launch failed on it, and merge split
//! `project:P/a/b` on the wrong `/` and appended a duplicate (issue #120).
//!
//! Pure and in-process: the listing is built from JSON text, and the `bws`
//! process calls stay in `backend`.

use crate::error::{Error, Result};
use crate::validate::{is_placeholder_ref, is_uuid, validate_var_name};

/// One secret as `bws secret list` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BwSecret {
    pub id: String,
    pub key: String,
    /// The project's name, empty when the secret is in none.
    pub project: String,
}

impl BwSecret {
    pub fn new(id: &str, key: &str, project: &str) -> BwSecret {
        BwSecret {
            id: id.to_string(),
            key: key.to_string(),
            project: project.to_string(),
        }
    }

    /// `  (project: P)`, or nothing for a secret in no project: the suffix a
    /// listing line names the project with.
    pub fn project_note(&self) -> String {
        if self.project.is_empty() {
            String::new()
        } else {
            format!("  (project: {})", self.project)
        }
    }
}

/// A well-formed Bitwarden reference: one of the four forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BwRef<'a> {
    /// `UUID` or `uuid:UUID`.
    Id(&'a str),
    /// `name:KEY`.
    Name(&'a str),
    /// `project:PROJECT/KEY`, split on the first `/`: a generated key may
    /// contain `/`, while the project is the prefix.
    Project { project: &'a str, key: &'a str },
}

impl<'a> BwRef<'a> {
    /// Parse a reference (annotation already removed): one of the four forms,
    /// or the fault that says why it is none. A placeholder is a fault:
    /// invariant 4 keeps those loud, and nothing should look one up.
    pub fn parse(reference: &'a str) -> std::result::Result<BwRef<'a>, BwRefFault> {
        let fault = |make: fn(String) -> BwRefFault| Err(make(reference.to_string()));
        if is_placeholder_ref(reference) {
            return fault(BwRefFault::Placeholder);
        }
        // No form contains `=`; one that does is a glued 0.3.0 line.
        if reference.contains('=') {
            return fault(BwRefFault::ContainsEquals);
        }
        if let Some(rest) = reference.strip_prefix("uuid:") {
            return if is_uuid(rest) {
                Ok(BwRef::Id(rest))
            } else {
                fault(BwRefFault::NotAUuid)
            };
        }
        if let Some(key) = reference.strip_prefix("name:") {
            return if key.is_empty() {
                Err(BwRefFault::EmptyName)
            } else {
                Ok(BwRef::Name(key))
            };
        }
        if let Some(rest) = reference.strip_prefix("project:") {
            return match rest.split_once('/') {
                Some((project, key)) if !project.is_empty() && !key.is_empty() => {
                    Ok(BwRef::Project { project, key })
                }
                _ => fault(BwRefFault::BadProject),
            };
        }
        if is_uuid(reference) {
            Ok(BwRef::Id(reference))
        } else {
            fault(BwRefFault::UnknownForm)
        }
    }

    /// True when this reference selects `secret`: the same id, the same key
    /// for `name:`, the same project and key for `project:`.
    pub fn selects(&self, secret: &BwSecret) -> bool {
        match *self {
            BwRef::Id(id) => secret.id == id,
            BwRef::Name(key) => secret.key == key,
            BwRef::Project { project, key } => secret.project == project && secret.key == key,
        }
    }
}

/// Why a Bitwarden reference is malformed. Each variant carries the
/// reference it was found in (except `EmptyName`, whose reference is always
/// `name:`), and its `Display` is the one wording every caller prints: the
/// Manifest check as `<VAR> <fault>`, the launch's lookup and `secrets get`
/// bare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BwRefFault {
    /// A placeholder, never looked up (invariant 4).
    Placeholder(String),
    /// Contains `=`, which no form does: often a glued 0.3.0 line
    /// ([`split_glued_bitwarden_line`]).
    ContainsEquals(String),
    /// `uuid:` followed by something that is not a UUID.
    NotAUuid(String),
    /// `name:` with no key.
    EmptyName,
    /// `project:` without both a project and a key.
    BadProject(String),
    /// None of the four forms.
    UnknownForm(String),
}

impl std::fmt::Display for BwRefFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BwRefFault::Placeholder(r) => write!(f, "still has placeholder ref {r}"),
            BwRefFault::ContainsEquals(r) => {
                write!(f, "bad bitwarden ref {r} (a reference cannot contain '=')")
            }
            BwRefFault::NotAUuid(r) => write!(f, "uuid: value is not a UUID: {r}"),
            BwRefFault::EmptyName => f.write_str("empty name: ref"),
            BwRefFault::BadProject(r) => write!(f, "want project:PROJECT/SECRET (got {r})"),
            BwRefFault::UnknownForm(r) => write!(
                f,
                "bad bitwarden ref {r} (use UUID, uuid:UUID, name:KEY, or project:PROJECT/KEY)"
            ),
        }
    }
}

/// What a reference finds in the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// Exactly one secret: what a launch injects.
    Found(&'a BwSecret),
    /// Nothing: a **dangling ref**.
    Absent,
    /// More than one, in listing order: an **ambiguous ref**. Listing order
    /// is not a contract `bws` makes, so picking one could inject the wrong
    /// credential.
    Ambiguous(Vec<&'a BwSecret>),
    /// Not one of the four forms, or a placeholder: why, as the fault.
    NotARef(BwRefFault),
}

/// The secrets one manager token can see.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BwListing {
    secrets: Vec<BwSecret>,
}

impl BwListing {
    pub fn new(secrets: Vec<BwSecret>) -> BwListing {
        BwListing { secrets }
    }

    /// Parse `bws secret list --output json`. Rows without an id are skipped.
    pub fn from_json(list_json: &str) -> Result<BwListing> {
        let v: serde_json::Value = serde_json::from_str(list_json)
            .map_err(|e| Error::Message(format!("bws secret list JSON: {e}")))?;
        let arr = match &v {
            serde_json::Value::Array(a) => a.clone(),
            serde_json::Value::Object(o) => o
                .get("data")
                .or_else(|| o.get("secrets"))
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let mut secrets = Vec::new();
        for s in arr {
            let id = s.get("id").and_then(|x| x.as_str()).unwrap_or("");
            if id.is_empty() {
                continue;
            }
            let key = s
                .get("key")
                .or_else(|| s.get("name"))
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let project = match s.get("project") {
                Some(serde_json::Value::Object(p)) => {
                    p.get("name").and_then(|x| x.as_str()).unwrap_or("")
                }
                Some(serde_json::Value::String(s)) => s.as_str(),
                _ => "",
            };
            secrets.push(BwSecret::new(id, key, project));
        }
        Ok(BwListing { secrets })
    }

    /// Every listed secret, in listing order.
    pub fn secrets(&self) -> &[BwSecret] {
        &self.secrets
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// The listed secret with this id.
    pub fn by_id(&self, id: &str) -> Option<&BwSecret> {
        self.secrets.iter().find(|s| s.id == id)
    }

    /// Look a reference (annotation already removed) up against the listing.
    pub fn lookup(&self, reference: &str) -> Lookup<'_> {
        let r = match BwRef::parse(reference) {
            Ok(r) => r,
            Err(fault) => return Lookup::NotARef(fault),
        };
        let mut hits: Vec<&BwSecret> = self.secrets.iter().filter(|s| r.selects(s)).collect();
        match hits.len() {
            0 => Lookup::Absent,
            1 => Lookup::Found(hits.remove(0)),
            _ => Lookup::Ambiguous(hits),
        }
    }
}

/// The variable a generated line names a secret key with.
pub fn key_to_var(key: &str) -> String {
    let mut s: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    let needs_prefix = !matches!(s.chars().next(), Some(c) if c.is_ascii_alphabetic() || c == '_');
    if needs_prefix {
        s = format!("SECRET_{s}");
    }
    s
}

/// Split a Bitwarden refs value into its reference and trailing annotation.
///
/// Generated lines record which secret they came from, so a vault-side rename
/// stays detectable after the key it was named for is gone (ADR-0004):
///
/// ```text
/// ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY # uuid:ea6db86f-…
/// ```
///
/// The split needs whitespace before the `#`. No Bitwarden reference form
/// contains whitespace, so ` #` unambiguously ends one — while a bare `#` may
/// sit inside a secret key, and treating that as a comment would send a
/// truncated reference to the vault.
///
/// Bitwarden refs only. A dotenv manifest holds secret *values*, where a `#`
/// is ordinary material.
pub fn split_annotation(value: &str) -> (&str, Option<&str>) {
    let mut prev_ws = false;
    for (i, c) in value.char_indices() {
        if c == '#' && prev_ws {
            return (value[..i].trim_end(), Some(value[i + 1..].trim()));
        }
        prev_ws = c.is_whitespace();
    }
    (value, None)
}

/// The reference a Bitwarden refs value carries, annotation removed.
pub fn reference_of(value: &str) -> &str {
    split_annotation(value).0
}

/// The source UUID a Bitwarden refs value records, if it records one.
///
/// A placeholder records nothing: invariant 4 keeps placeholders loud, and a
/// zero UUID must never be the evidence that turns a line into a rename.
pub fn recorded_uuid(value: &str) -> Option<&str> {
    split_annotation(value)
        .1?
        .split_whitespace()
        .find_map(|t| t.strip_prefix("uuid:"))
        .filter(|u| is_recordable(u))
}

/// Is this id worth recording on a line?
///
/// A placeholder is not: invariant 4 keeps placeholders loud, and a zero UUID
/// must never be the evidence that turns a line into a rename.
fn is_recordable(id: &str) -> bool {
    is_uuid(id) && !is_placeholder_ref(id)
}

/// A `name:` mapping line, carrying its source recording when there is one.
///
/// The single place the annotated form is spelled out — generation and repair
/// must not be able to disagree about it.
pub fn name_line(var: &str, key: &str, id: &str) -> String {
    if is_recordable(id) {
        format!("{var}=name:{key} # uuid:{id}")
    } else {
        format!("{var}=name:{key}")
    }
}

/// Recover the one-mapping-per-line form of a 0.3.0 glued Bitwarden refs line.
///
/// `va refresh` on the bash launcher captured each `VAR=name:KEY\n` with
/// `$(…)`, which strips the trailing newline, then concatenated. When the SM
/// secret key was already env-shaped, VAR equals KEY and the file held:
///
/// ```text
/// META_AI_API_KEY=name:META_AI_API_KEYFIREWORKS_API_KEY=name:FIREWORKS_API_KEY
/// ```
///
/// KEY and the next VAR share the `[A-Z0-9_]` charset, so there is no
/// delimiter between them. The writer always emitted `VAR=name:VAR` in this
/// case, and that identity is what makes the split unambiguous.
///
/// Returns `None` when the line is a single mapping (or not this shape).
pub fn split_glued_bitwarden_line(line: &str) -> Option<Vec<String>> {
    let mut rest = line.trim();
    if rest.is_empty() || rest.starts_with('#') {
        return None;
    }
    let mut parts = Vec::new();
    while !rest.is_empty() {
        let (var, after_eq) = rest.split_once('=')?;
        if !validate_var_name(var) {
            return None;
        }
        let after_form = after_eq.strip_prefix("name:")?;
        if !after_form.starts_with(var) {
            return None;
        }
        let after_key = &after_form[var.len()..];
        if !after_key.is_empty() && !starts_with_name_assignment(after_key) {
            return None;
        }
        parts.push(format!("{var}=name:{var}"));
        rest = after_key;
    }
    (parts.len() >= 2).then_some(parts)
}

fn starts_with_name_assignment(s: &str) -> bool {
    let Some((var, after_eq)) = s.split_once('=') else {
        return false;
    };
    validate_var_name(var) && after_eq.starts_with("name:")
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "11111111-1111-1111-1111-111111111111";
    const B: &str = "22222222-2222-2222-2222-222222222222";
    const C: &str = "33333333-3333-3333-3333-333333333333";
    const D: &str = "44444444-4444-4444-4444-444444444444";
    const E: &str = "55555555-5555-5555-5555-555555555555";
    const F: &str = "66666666-6666-6666-6666-666666666666";
    const G: &str = "77777777-7777-7777-7777-777777777777";

    /// A duplicated key, a key containing `/`, the same key in two projects,
    /// and a secret whose key is a placeholder.
    fn listing() -> BwListing {
        BwListing::from_json(&format!(
            r#"[
              {{"id":"{A}","key":"UNIQUE","project":{{"name":"tools"}}}},
              {{"id":"{B}","key":"DUP","project":{{"name":"tools"}}}},
              {{"id":"{C}","key":"DUP","project":{{"name":"tools"}}}},
              {{"id":"{D}","key":"a/b","project":{{"name":"P"}}}},
              {{"id":"{E}","key":"SHARED","project":{{"name":"P"}}}},
              {{"id":"{F}","key":"SHARED","project":{{"name":"Q"}}}},
              {{"id":"{G}","key":"REPLACE_WITH_KEY","project":{{"name":"P"}}}}
            ]"#
        ))
        .unwrap()
    }

    fn found_id(r: &str) -> Option<String> {
        match listing().lookup(r) {
            Lookup::Found(s) => Some(s.id.clone()),
            _ => None,
        }
    }

    fn ambiguous_ids(r: &str) -> Vec<String> {
        match listing().lookup(r) {
            Lookup::Ambiguous(c) => c.iter().map(|s| s.id.clone()).collect(),
            other => panic!("{r}: {other:?}"),
        }
    }

    #[test]
    fn the_listing_reads_bws_json_in_every_shape_it_comes_in() {
        let l = BwListing::from_json(
            r#"[{"id":"a","key":"k1","project":{"name":"p"}},
                {"id":"b","name":"k2","project":"q"},
                {"id":"c","key":"k3"},
                {"key":"no-id"}]"#,
        )
        .unwrap();
        assert_eq!(
            l.secrets(),
            [
                BwSecret::new("a", "k1", "p"),
                BwSecret::new("b", "k2", "q"),
                BwSecret::new("c", "k3", ""),
            ]
        );
        let wrapped = BwListing::from_json(r#"{"data":[{"id":"a","key":"k"}]}"#).unwrap();
        assert_eq!(wrapped.len(), 1);
        assert!(BwListing::from_json("not json").is_err());
    }

    #[test]
    fn uuid_forms_find_by_id() {
        assert_eq!(found_id(A).as_deref(), Some(A));
        assert_eq!(found_id(&format!("uuid:{A}")).as_deref(), Some(A));
        let gone = "99999999-9999-9999-9999-999999999999";
        assert_eq!(listing().lookup(gone), Lookup::Absent);
        assert_eq!(listing().lookup(&format!("uuid:{gone}")), Lookup::Absent);
    }

    #[test]
    fn name_finds_one_or_reports_every_candidate() {
        assert_eq!(found_id("name:UNIQUE").as_deref(), Some(A));
        assert_eq!(found_id("name:a/b").as_deref(), Some(D));
        assert_eq!(listing().lookup("name:GONE"), Lookup::Absent);
        assert_eq!(ambiguous_ids("name:DUP"), [B, C]);
        // The same key in two projects is two secrets.
        assert_eq!(ambiguous_ids("name:SHARED"), [E, F]);
    }

    #[test]
    fn project_splits_on_the_first_slash_and_is_ambiguous_on_two_matches() {
        assert_eq!(found_id("project:P/a/b").as_deref(), Some(D));
        assert_eq!(found_id("project:P/SHARED").as_deref(), Some(E));
        assert_eq!(found_id("project:Q/SHARED").as_deref(), Some(F));
        assert_eq!(listing().lookup("project:P/b"), Lookup::Absent);
        assert_eq!(listing().lookup("project:R/SHARED"), Lookup::Absent);
        // Same key, same project: qualifying by project is not enough.
        assert_eq!(ambiguous_ids("project:tools/DUP"), [B, C]);
    }

    #[test]
    fn placeholders_and_bad_shapes_are_not_references() {
        for r in [
            "",
            "REPLACE_WITH_BITWARDEN_SECRET_UUID",
            "00000000-0000-0000-0000-000000000000",
            "uuid:00000000-0000-0000-0000-000000000000",
            "uuid:not-a-uuid",
            "name:",
            "project:tools",
            "project:/UNIQUE",
            "project:tools/",
            "not-a-reference",
            "name:A=name:B",
            // Listed, but a placeholder reference is never looked up
            // (invariant 4), even when a secret carries that key.
            "REPLACE_WITH_KEY",
            "name:REPLACE_WITH_KEY",
            "project:P/REPLACE_WITH_KEY",
        ] {
            let fault = BwRef::parse(r).expect_err(r);
            assert_eq!(listing().lookup(r), Lookup::NotARef(fault), "{r}");
        }
    }

    #[test]
    fn each_malformed_reference_has_one_fault_and_one_wording() {
        let u = "6a1c0e94-1111-2222-3333-444444444444";
        for (r, fault, wording) in [
            (
                "REPLACE_WITH_BITWARDEN_SECRET_UUID",
                BwRefFault::Placeholder("REPLACE_WITH_BITWARDEN_SECRET_UUID".into()),
                "still has placeholder ref REPLACE_WITH_BITWARDEN_SECRET_UUID",
            ),
            (
                "name:A=name:B",
                BwRefFault::ContainsEquals("name:A=name:B".into()),
                "bad bitwarden ref name:A=name:B (a reference cannot contain '=')",
            ),
            (
                "uuid:not-a-uuid",
                BwRefFault::NotAUuid("uuid:not-a-uuid".into()),
                "uuid: value is not a UUID: uuid:not-a-uuid",
            ),
            ("name:", BwRefFault::EmptyName, "empty name: ref"),
            (
                "project:P/",
                BwRefFault::BadProject("project:P/".into()),
                "want project:PROJECT/SECRET (got project:P/)",
            ),
            (
                "junk",
                BwRefFault::UnknownForm("junk".into()),
                "bad bitwarden ref junk (use UUID, uuid:UUID, name:KEY, or project:PROJECT/KEY)",
            ),
        ] {
            assert_eq!(BwRef::parse(r), Err(fault.clone()), "{r}");
            assert_eq!(fault.to_string(), wording, "{r}");
        }
        // A placeholder is caught before its form: a zero UUID is not an id.
        assert!(matches!(
            BwRef::parse("uuid:00000000-0000-0000-0000-000000000000"),
            Err(BwRefFault::Placeholder(_))
        ));
        for r in [
            u,
            &format!("uuid:{u}"),
            "name:KEY",
            "name:a/b",
            "project:P/a/b",
        ] {
            assert!(BwRef::parse(r).is_ok(), "{r}");
        }
    }

    #[test]
    fn a_reference_selects_by_the_identity_its_form_names() {
        let s = BwSecret::new(D, "a/b", "P");
        assert!(BwRef::parse(D).unwrap().selects(&s));
        assert!(BwRef::parse("name:a/b").unwrap().selects(&s));
        assert!(BwRef::parse("project:P/a/b").unwrap().selects(&s));
        assert!(!BwRef::parse("project:Q/a/b").unwrap().selects(&s));
        assert!(!BwRef::parse("name:b").unwrap().selects(&s));
    }

    // ---- the refs-line grammar (issue #82, ADR-0004) ----

    #[test]
    fn an_annotation_needs_whitespace_and_a_hash_to_start() {
        // No Bitwarden reference form contains whitespace, so ` #` is an
        // unambiguous end-of-reference marker.
        assert_eq!(
            split_annotation("name:FOO # uuid:11111111-1111-1111-1111-111111111111"),
            (
                "name:FOO",
                Some("uuid:11111111-1111-1111-1111-111111111111")
            )
        );
        assert_eq!(
            split_annotation("name:FOO\t# note"),
            ("name:FOO", Some("note"))
        );
        // A `#` welded to the reference is part of it: a Bitwarden key may hold
        // one, and guessing otherwise would resolve the wrong secret.
        assert_eq!(split_annotation("name:FOO#BAR"), ("name:FOO#BAR", None));
        assert_eq!(split_annotation("name:FOO"), ("name:FOO", None));
    }

    #[test]
    fn a_recorded_uuid_is_read_out_of_the_annotation() {
        let u = "11111111-1111-1111-1111-111111111111";
        assert_eq!(recorded_uuid(&format!("name:FOO # uuid:{u}")), Some(u));
        // Prose in the comment is not a recording.
        assert_eq!(recorded_uuid("name:FOO # hand pinned, do not touch"), None);
        // Not a UUID, so not a recording.
        assert_eq!(recorded_uuid("name:FOO # uuid:nope"), None);
        // Invariant 4: a placeholder records nothing, so it can never be the
        // evidence that makes a line a rename.
        assert_eq!(
            recorded_uuid("name:FOO # uuid:00000000-0000-0000-0000-000000000000"),
            None
        );
    }

    #[test]
    fn split_glued_line_recovers_the_0_3_0_refresh_blob() {
        // The exact shape that landed on disk: one physical line, 13 mappings.
        let line = "META_AI_API_KEY=name:META_AI_API_KEYFIREWORKS_API_KEY=name:FIREWORKS_API_KEYELEVENLABS_API_KEY=name:ELEVENLABS_API_KEYMUREKA_API_KEY=name:MUREKA_API_KEYGEMINI_API_KEY=name:GEMINI_API_KEYASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEYANTHROPIC_API_KEY=name:ANTHROPIC_API_KEYBASETEN_API_KEY=name:BASETEN_API_KEYTOGETHER_AI_API_KEY=name:TOGETHER_AI_API_KEYDEEPINFRA_API_KEY=name:DEEPINFRA_API_KEYGROQ_API_KEY=name:GROQ_API_KEYHUME_API_KEY=name:HUME_API_KEYHUME_SECRET_KEY=name:HUME_SECRET_KEY";
        let parts = split_glued_bitwarden_line(line).expect("glued");
        assert_eq!(
            parts,
            vec![
                "META_AI_API_KEY=name:META_AI_API_KEY",
                "FIREWORKS_API_KEY=name:FIREWORKS_API_KEY",
                "ELEVENLABS_API_KEY=name:ELEVENLABS_API_KEY",
                "MUREKA_API_KEY=name:MUREKA_API_KEY",
                "GEMINI_API_KEY=name:GEMINI_API_KEY",
                "ASSEMBLY_AI_API_KEY=name:ASSEMBLY_AI_API_KEY",
                "ANTHROPIC_API_KEY=name:ANTHROPIC_API_KEY",
                "BASETEN_API_KEY=name:BASETEN_API_KEY",
                "TOGETHER_AI_API_KEY=name:TOGETHER_AI_API_KEY",
                "DEEPINFRA_API_KEY=name:DEEPINFRA_API_KEY",
                "GROQ_API_KEY=name:GROQ_API_KEY",
                "HUME_API_KEY=name:HUME_API_KEY",
                "HUME_SECRET_KEY=name:HUME_SECRET_KEY",
            ]
        );
        assert!(split_glued_bitwarden_line("OPENAI_API_KEY=name:OPENAI_API_KEY").is_none());
    }
}
