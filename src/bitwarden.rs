//! The **Bitwarden listing**: the secrets one manager token can see, as one
//! `bws secret list` returns them, and the one place a Bitwarden reference is
//! parsed and looked up against them.
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
use crate::validate::{is_placeholder_ref, is_uuid};

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
    /// Parse a reference (annotation already removed). `None` when it is not
    /// one of the four forms, or is a placeholder: invariant 4 keeps those
    /// loud, and nothing should look one up.
    pub fn parse(reference: &'a str) -> Option<BwRef<'a>> {
        // No form contains `=`; one that does is a glued 0.3.0 line.
        if is_placeholder_ref(reference) || reference.contains('=') {
            return None;
        }
        if let Some(rest) = reference.strip_prefix("uuid:") {
            return is_uuid(rest).then_some(BwRef::Id(rest));
        }
        if let Some(key) = reference.strip_prefix("name:") {
            return (!key.is_empty()).then_some(BwRef::Name(key));
        }
        if let Some(rest) = reference.strip_prefix("project:") {
            let (project, key) = rest.split_once('/')?;
            if project.is_empty() || key.is_empty() {
                return None;
            }
            return Some(BwRef::Project { project, key });
        }
        is_uuid(reference).then_some(BwRef::Id(reference))
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
    /// Not one of the four forms, or a placeholder.
    NotARef,
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
        let Some(r) = BwRef::parse(reference) else {
            return Lookup::NotARef;
        };
        let mut hits: Vec<&BwSecret> = self.secrets.iter().filter(|s| r.selects(s)).collect();
        match hits.len() {
            0 => Lookup::Absent,
            1 => Lookup::Found(hits.remove(0)),
            _ => Lookup::Ambiguous(hits),
        }
    }
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

    /// A duplicated key, a key containing `/`, the same key in two projects.
    fn listing() -> BwListing {
        BwListing::from_json(&format!(
            r#"[
              {{"id":"{A}","key":"UNIQUE","project":{{"name":"tools"}}}},
              {{"id":"{B}","key":"DUP","project":{{"name":"tools"}}}},
              {{"id":"{C}","key":"DUP","project":{{"name":"tools"}}}},
              {{"id":"{D}","key":"a/b","project":{{"name":"P"}}}},
              {{"id":"{E}","key":"SHARED","project":{{"name":"P"}}}},
              {{"id":"{F}","key":"SHARED","project":{{"name":"Q"}}}}
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
        ] {
            assert_eq!(listing().lookup(r), Lookup::NotARef, "{r}");
            assert_eq!(BwRef::parse(r), None, "{r}");
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
}
