//! The **1Password listing**: the items one manager token can see, as one
//! `op item list` returns them, plus the fields of the items this `refresh`
//! run expanded — and the one place a 1Password reference is parsed, rendered
//! and looked up against them.
//!
//! The refresh scan, the Refs file writer, validate's blame, `edit-manifest`,
//! the doctor and the refresh gather step all ask this module, so none of them
//! splits `op://` text by hand. It mirrors the **Bitwarden listing**
//! (`src/bitwarden.rs`): a reader who knows one knows the other.
//!
//! Pure and in-process: the listing is built from JSON text, and the `op`
//! process calls stay in `backend`.

use std::collections::HashMap;
use std::fmt;

use crate::error::{Error, Result};
use crate::validate::is_placeholder_ref;

/// A 1Password reference: `op://VAULT/ITEM/FIELD`, or
/// `op://VAULT/ITEM/SECTION/FIELD` for a field in a section.
///
/// The section is not decoration. An item can carry several fields with the
/// same label in different sections, holding different secrets; the
/// unqualified form then resolves to whichever one `op` picks. Both forms were
/// checked against a real vault, including that two section-qualified
/// references return different values.
///
/// Spaces are fine: `op inject` reads a dotenv value to end of line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpRef<'a> {
    pub vault: &'a str,
    pub item: &'a str,
    /// `None`, or an empty section, renders the unqualified form.
    pub section: Option<&'a str>,
    pub field: &'a str,
}

impl<'a> OpRef<'a> {
    /// Parse exactly the 3- and 4-component forms, every component non-empty.
    ///
    /// Shape only: a component `op` cannot read still parses, so the writer's
    /// canonical form and validate's blame keep working on it. Whether `op`
    /// can read it is `is_readable`'s question.
    pub fn parse(reference: &'a str) -> Option<OpRef<'a>> {
        let rest = reference.strip_prefix("op://")?;
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.iter().any(|p| p.is_empty()) {
            return None;
        }
        match parts.as_slice() {
            [vault, item, field] => Some(OpRef {
                vault,
                item,
                section: None,
                field,
            }),
            [vault, item, section, field] => Some(OpRef {
                vault,
                item,
                section: Some(section),
                field,
            }),
            _ => None,
        }
    }

    /// The reference reduced to the field it identifies.
    ///
    /// `op://V/eta-factory-github-app/add more/app-id` and
    /// `op://V/eta-factory-github-app/app-id` are the same secret: a default
    /// section groups fields that were never grouped, and `op` resolves the
    /// unqualified form to the field inside it — checked against a real vault,
    /// by launching with both forms mapped and observing one value under both
    /// names.
    pub fn canonical(self) -> OpRef<'a> {
        OpRef {
            section: self.section.filter(|s| !section_is_default(s)),
            ..self
        }
    }
}

impl fmt::Display for OpRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let OpRef {
            vault, item, field, ..
        } = self;
        match self.section {
            Some(s) if !s.is_empty() => write!(f, "op://{vault}/{item}/{s}/{field}"),
            _ => write!(f, "op://{vault}/{item}/{field}"),
        }
    }
}

/// True when a reference component survives `op inject`'s reference scanner.
///
/// The scanner ends a reference at a character it does not accept, so an item
/// titled `db-admin jstephens MySQL (read-write)` is read as the truncated
/// `op://Orchestrator/db-admin jstephens MySQL` and rejected with "too few
/// '/'": one such item aborts the injection of the entire manifest. Spaces are
/// accepted; parentheses and non-ASCII characters (an em dash in a title, say)
/// are not. Quoting the value is not a workaround, because the scanner runs
/// over the reference text itself rather than the shell-quoted line.
fn component_is_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' '))
}

/// True when the `op inject` scanner can read a whole reference: the scheme,
/// then at least a vault, an item and a field, each built only from characters
/// its scanner accepts. One reference that fails this aborts the injection of
/// the entire manifest, so the doctor and `edit-manifest` check it before a
/// launch rather than during one.
///
/// "Three or more", not the parse's "three or four": tightening it would newly
/// flag a five-component reference, which is a behaviour question of its own.
pub fn is_readable(reference: &str) -> bool {
    let Some(rest) = reference.strip_prefix("op://") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('/').collect();
    parts.len() >= 3 && parts.iter().all(|p| component_is_safe(p))
}

/// True for a section label 1Password supplied rather than the operator.
///
/// `add more` is the label the app gives the section holding custom fields
/// added to an item without choosing a section, so it turns up across a vault
/// without anyone having typed it. Folding it into a variable name gives
/// ANTHROPIC_ADD_MORE_CONDUCTOR_API_KEY where ANTHROPIC_CONDUCTOR_API_KEY was
/// meant, and it carries nothing a reader wants: a section disambiguates
/// fields *within* an item, and this one collects everything never grouped.
///
/// This governs naming, dedupe and lookup only. A written reference always
/// keeps the section it was built with, so what `op` is asked to resolve never
/// changes.
pub fn section_is_default(section: &str) -> bool {
    section.trim().eq_ignore_ascii_case("add more")
}

/// True when a mapping still has the name `refresh` generated before it learned
/// to drop a default section label: the reference sits in a default section,
/// and the variable name carries that label folded into it.
///
/// Both halves, because the name alone is not enough: a field genuinely named
/// `add-more-seats` produces the same fragment, and its reference has no
/// section at all.
pub fn has_legacy_name(var: &str, reference: &str) -> bool {
    OpRef::parse(reference)
        .and_then(|r| r.section)
        .is_some_and(section_is_default)
        && name_folds_default_section(var)
}

/// True when a variable name carries a default section label folded into it.
/// Derived from the label rather than spelled out, so the two cannot drift
/// apart.
fn name_folds_default_section(name: &str) -> bool {
    let fragment = var_from_parts("", Some("add more"), "");
    name.to_ascii_uppercase().contains(&format!("_{fragment}_"))
}

/// One item as `op item list` reports it. The four strings always travel
/// together — a menu row, the argument to `op item get`, and what an existing
/// `op://` reference is judged against all need the same four.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpItem {
    pub id: String,
    pub title: String,
    pub vault: String,
    pub vault_id: String,
}

impl OpItem {
    /// True when a reference's vault and item components name this item.
    ///
    /// Both halves accept either identifier `op` accepts — the vault by name or
    /// id, the item by title or id — and names match case-insensitively,
    /// because `op` resolves them that way. A case difference is not a dangling
    /// ref, and treating one as dangling would delete a line that launches
    /// fine.
    fn named_by(&self, vault: &str, item: &str) -> bool {
        let vault_hit = self.vault.eq_ignore_ascii_case(vault)
            || (!self.vault_id.is_empty() && self.vault_id == vault);
        vault_hit && (self.id == item || self.title.eq_ignore_ascii_case(item))
    }

    /// The item component of a reference: the readable title when `op` can
    /// parse it, otherwise the item's opaque ID, which always parses. Variable
    /// names are still derived from the title, so a fallback here costs
    /// readability only in the reference itself.
    fn reference_component(&self) -> &str {
        if component_is_safe(&self.title) {
            &self.title
        } else {
            &self.id
        }
    }
}

/// A referenceable field: its section (when it is in one) and its label.
/// What `refresh` would choose to map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpField {
    pub section: Option<String>,
    pub label: String,
}

/// A field as a *reference* may name it: by label or by id, optionally
/// qualified by its section. Wider than `OpField` on purpose — this is what
/// exists in the vault, not what `refresh` would choose to map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpFieldIdentity {
    pub section: Option<String>,
    pub label: String,
    pub id: String,
}

impl OpFieldIdentity {
    /// True when a reference component names this field. Either identifier
    /// does: `refresh` generates labels, but an operator may have pinned a
    /// field id, and `op` resolves both. Labels match case-insensitively,
    /// because `op` resolves them that way.
    fn named(&self, want: &str) -> bool {
        self.label.eq_ignore_ascii_case(want) || (!self.id.is_empty() && self.id == want)
    }

    /// True when this field sits in the section a reference names. `None` asks
    /// for no section in particular: an unqualified reference is not required
    /// to name a top-level field, because `op` will find a matching label
    /// wherever it sits, and matching any section keeps a working line working.
    fn in_section(&self, want: Option<&str>) -> bool {
        match want {
            Some(s) => self
                .section
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case(s)),
            None => true,
        }
    }
}

/// What a reference finds in the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// A field on an expanded item: the reference resolves.
    Found(&'a OpItem),
    /// No such item, or no such field on an expanded item: a **dangling ref**.
    Absent,
    /// The item is listed but this run never expanded it, so nothing was
    /// learned about the field: an **unchecked ref** (ADR-0005).
    Unexpanded,
    /// A literal, a shape `op` cannot read, or a placeholder in any component.
    NotARef,
}

/// The items one manager token can see, plus the fields of the items this run
/// expanded.
///
/// Deliberately only what the run already paid for. `op item list` is one call
/// and names every item; fields cost one `op item get` per item, which is why
/// selection is at item level in the first place. So a reference into an item
/// this run expanded is judged down to the field, and a reference into an item
/// it did not is unexpanded — reported, never pruned (ADR-0005).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpListing {
    items: Vec<OpItem>,
    /// Field identities by item id, for the items this run expanded.
    fields: HashMap<String, Vec<OpFieldIdentity>>,
}

impl OpListing {
    /// Parse `op item list --format json`. Rows without an id or title are
    /// skipped.
    pub fn from_json(list_json: &str) -> Result<OpListing> {
        let v: serde_json::Value = serde_json::from_str(list_json)
            .map_err(|e| Error::Message(format!("op item list JSON: {e}")))?;
        let arr = match &v {
            serde_json::Value::Array(a) => a.clone(),
            _ => return Err(Error::Message("op item list: expected a JSON array".into())),
        };
        let mut items = Vec::new();
        for it in arr {
            let id = it.get("id").and_then(|x| x.as_str()).unwrap_or_default();
            let title = it.get("title").and_then(|x| x.as_str()).unwrap_or_default();
            let vault = it
                .get("vault")
                .and_then(|x| x.get("name"))
                .and_then(|x| x.as_str())
                .unwrap_or_default();
            // Kept alongside the name because `op` resolves a reference against
            // either, so a manifest may name the vault by id and a listing
            // holding only names could not match it.
            let vault_id = it
                .get("vault")
                .and_then(|x| x.get("id"))
                .and_then(|x| x.as_str())
                .unwrap_or_default();
            if id.is_empty() || title.is_empty() {
                continue;
            }
            items.push(OpItem {
                id: id.to_string(),
                title: title.to_string(),
                vault: vault.to_string(),
                vault_id: vault_id.to_string(),
            });
        }
        Ok(OpListing {
            items,
            fields: HashMap::new(),
        })
    }

    /// Every listed item, in listing order.
    pub fn items(&self) -> &[OpItem] {
        &self.items
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Expand one item from its `op item get --format json`: one round trip,
    /// read twice.
    ///
    /// Records every field identity a reference may name, and returns the
    /// fields worth mapping. The first view is wider — an OTP or empty-valued
    /// field is one `refresh` will not map and `op` will still resolve — and
    /// judging an existing mapping against the narrow one would call a working
    /// line dangling. On a parse error nothing is recorded, so the item stays
    /// unexpanded.
    pub fn expand(&mut self, item_id: &str, item_json: &str) -> Result<Vec<OpField>> {
        let item: serde_json::Value = serde_json::from_str(item_json)
            .map_err(|e| Error::Message(format!("op item get JSON: {e}")))?;
        let fields = referenceable_fields(&item);
        let identities = field_identities(&item);
        self.fields.insert(item_id.to_string(), identities);
        Ok(fields)
    }

    /// The listed item a reference's vault and item components name, if any.
    fn item_of(&self, vault: &str, item: &str) -> Option<&OpItem> {
        self.items.iter().find(|it| it.named_by(vault, item))
    }

    /// Look a reference up against the listing.
    ///
    /// Lenient by construction: every uncertainty resolves away from "absent".
    /// A wrong absent is a dangling ref `refresh` prunes, removing a line that
    /// launches today, and no report is worth that.
    pub fn lookup(&self, reference: &str) -> Lookup<'_> {
        let r = reference.trim();
        // Invariant 4 keeps placeholders loud, and `secrets validate` owns
        // them. A literal beside the references (a region, a URL) is not a
        // reference, and neither is a shape `op` itself cannot read.
        if is_placeholder_ref(r) || !is_readable(r) {
            return Lookup::NotARef;
        }
        // More components than `op`'s own form has: nothing to judge it by.
        let Some(OpRef {
            vault,
            item,
            section,
            field,
        }) = OpRef::parse(r)
        else {
            return Lookup::NotARef;
        };
        // A placeholder in a component keeps the whole line out of judgement.
        // `is_placeholder_ref` anchors most of its spellings at the start of
        // the string, which behind an `op://` prefix is the scheme, so the
        // components have to be offered to it one at a time. Invariant 4 makes
        // a placeholder fail closed and ADR-0003 keeps prune off it: removing
        // one would take the variable out of the manifest and turn a loud
        // misconfiguration into a secret that quietly stops being injected.
        // The vault is a name the operator chose, not a slot to fill in, and
        // was never offered.
        if [Some(item), section, Some(field)]
            .into_iter()
            .flatten()
            .any(is_placeholder_ref)
        {
            return Lookup::NotARef;
        }
        let Some(found) = self.item_of(vault, item) else {
            // Neither an id nor a title in the listing: the item was deleted,
            // renamed, or moved out of this token's reach. An `op` reference
            // records no source id (ADR-0005), so a rename here is
            // indistinguishable from a deletion and both are absent.
            return Lookup::Absent;
        };
        let Some(fields) = self.fields.get(found.id.as_str()) else {
            return Lookup::Unexpanded;
        };
        // A default section label groups fields that were never grouped, and
        // `op` resolves the unqualified form to the field inside it — the same
        // equivalence `OpRef::canonical` relies on.
        let section = section.filter(|s| !section_is_default(s));
        if fields
            .iter()
            .any(|f| f.named(field) && f.in_section(section))
        {
            Lookup::Found(found)
        } else {
            Lookup::Absent
        }
    }
}

/// One generated mapping: the variable name and the reference to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpMapping {
    pub var: String,
    pub reference: String,
}

/// What one item's referenceable fields become.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemMappings {
    /// Every representable field, mapped, in field order. Exclusions are the
    /// caller's: they are a Refs file rule shared with Bitwarden.
    pub mappings: Vec<OpMapping>,
    /// Fields whose section or label cannot be written as a reference.
    pub skipped: Vec<OpField>,
}

/// Turn one item and its referenceable fields into mappings.
///
/// Named per item, because dropping a default section label can make two of an
/// item's fields want one name, and only the whole item shows that.
pub fn item_mappings(item: &OpItem, fields: Vec<OpField>) -> ItemMappings {
    // An item has an opaque ID to fall back on when its title does not parse;
    // a section or field label has no such fallback. Those are skipped rather
    // than written as a reference that would abort the injection of every
    // other variable in the file.
    let (representable, skipped): (Vec<OpField>, Vec<OpField>) =
        fields.into_iter().partition(|f| {
            f.section.as_deref().is_none_or(component_is_safe) && component_is_safe(&f.label)
        });
    let title = item.title.as_str();
    let mappings = representable
        .iter()
        .map(|f| {
            let section = f.section.as_deref();
            let plain = var_name(title, section, &f.label);
            // Two fields reduced to the same name are two different secrets,
            // so keep the section on both rather than let either win. Rare: it
            // needs one item holding the same label inside and outside its
            // default section.
            let clashes = representable
                .iter()
                .filter(|g| var_name(title, g.section.as_deref(), &g.label) == plain)
                .count()
                > 1;
            let var = if clashes {
                var_name_qualified(title, section, &f.label)
            } else {
                plain
            };
            let reference = OpRef {
                vault: &item.vault,
                item: item.reference_component(),
                section,
                field: &f.label,
            };
            OpMapping {
                var,
                reference: reference.to_string(),
            }
        })
        .collect();
    ItemMappings { mappings, skipped }
}

/// The section as it should count toward a variable name: absent when there is
/// no section, or when 1Password named it rather than the operator.
fn section_for_naming(section: Option<&str>) -> Option<&str> {
    section.filter(|s| !s.is_empty() && !section_is_default(s))
}

/// VAR name for a 1Password field: "anthropic" + "conductor-api-key" becomes
/// ANTHROPIC_CONDUCTOR_API_KEY. An operator-named section is included, because
/// label alone is not unique within an item; a default section label is not
/// (see `section_is_default`). `item_mappings` resolves a clash this causes
/// with `var_name_qualified`.
fn var_name(item: &str, section: Option<&str>, field: &str) -> String {
    var_from_parts(item, section_for_naming(section), field)
}

/// `var_name`, keeping a section label it would otherwise drop. For the one
/// case that needs it: two fields in an item whose names would collide.
fn var_name_qualified(item: &str, section: Option<&str>, field: &str) -> String {
    var_from_parts(item, section.filter(|s| !s.is_empty()), field)
}

fn var_from_parts(item: &str, section: Option<&str>, field: &str) -> String {
    let joined = match section {
        Some(s) => format!("{item}_{s}_{field}"),
        None => format!("{item}_{field}"),
    };
    let mut s: String = joined
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    while s.contains("__") {
        s = s.replace("__", "_");
    }
    let s = s.trim_matches('_').to_string();
    let needs_prefix = !matches!(s.chars().next(), Some(c) if c.is_ascii_alphabetic());
    if needs_prefix {
        format!("SECRET_{s}")
    } else {
        s
    }
}

/// Every field identity on an item: no filtering, and the field id alongside
/// the label, because a reference may name either.
///
/// Metadata only — values are never read here, not even for presence.
fn field_identities(v: &serde_json::Value) -> Vec<OpFieldIdentity> {
    let mut out: Vec<OpFieldIdentity> = Vec::new();
    if let Some(fields) = v.get("fields").and_then(|f| f.as_array()) {
        for f in fields {
            let id = f
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            let label = f
                .get("label")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            if id.is_empty() && label.is_empty() {
                continue;
            }
            out.push(OpFieldIdentity {
                section: section_name(v, f),
                label,
                id,
            });
        }
    }
    if let Some(urls) = v.get("urls").and_then(|u| u.as_array()) {
        for u in urls {
            let label = u
                .get("label")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string();
            if !label.is_empty() {
                out.push(OpFieldIdentity {
                    section: None,
                    label: label.clone(),
                    id: label,
                });
            }
            out.push(OpFieldIdentity {
                section: None,
                label: "website".to_string(),
                id: "website".to_string(),
            });
            out.push(OpFieldIdentity {
                section: None,
                label: "url".to_string(),
                id: "url".to_string(),
            });
        }
    }
    out
}

/// The fields of an `op item get --format json` worth mapping.
///
/// Metadata only: a field is kept based on whether a value is PRESENT, and the
/// value itself is never returned, stored, or logged. Refs files hold
/// references, never secret material (CONTEXT.md invariant).
fn referenceable_fields(v: &serde_json::Value) -> Vec<OpField> {
    let mut out: Vec<OpField> = Vec::new();
    let Some(fields) = v.get("fields").and_then(|f| f.as_array()) else {
        return out;
    };
    for f in fields {
        // OTP fields are time-based; a static reference to one is not useful.
        let ty = f.get("type").and_then(|x| x.as_str()).unwrap_or_default();
        if ty.eq_ignore_ascii_case("OTP") {
            continue;
        }
        // The notes field is free-form prose, and prose routinely contains a
        // blank line or a line starting with '#'. parse_dotenv_pairs treats
        // both as closing an unquoted value, on purpose, so that a stray line
        // cannot graft itself onto an earlier secret. A notes field therefore
        // cannot survive the round trip: the line after the first blank one has
        // nothing to continue and the whole manifest dies with
        // "expected KEY=value", taking every other variable with it.
        //
        // Quoting the reference is not a way out. `op inject` substitutes the
        // value raw, so a note containing a double quote would break the
        // quoting it was meant to be protected by.
        let purpose = f
            .get("purpose")
            .and_then(|x| x.as_str())
            .unwrap_or_default();
        if purpose.eq_ignore_ascii_case("NOTES") {
            continue;
        }
        // Presence check only. Never bind the value to a name.
        let has_value = f
            .get("value")
            .map(|x| match x {
                serde_json::Value::Null => false,
                serde_json::Value::String(s) => !s.is_empty(),
                _ => true,
            })
            .unwrap_or(false);
        if !has_value {
            continue;
        }
        let label = f
            .get("label")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .or_else(|| f.get("id").and_then(|x| x.as_str()))
            .unwrap_or_default();
        if label.is_empty() {
            continue;
        }
        let section = section_name(v, f);
        // One item can hold several fields with the SAME label in different
        // sections - a real vault has three distinct `password` fields on one
        // host item. They are different secrets, so the pair identifies a field,
        // not the label alone.
        if out.iter().any(|e| e.section == section && e.label == label) {
            continue;
        }
        out.push(OpField {
            section,
            label: label.to_string(),
        });
    }
    out
}

/// Section name for a field: the label when set, else the section id, resolved
/// against the item's top-level `sections` when the field only carries an id.
fn section_name(item: &serde_json::Value, field: &serde_json::Value) -> Option<String> {
    let sec = field.get("section")?;
    if let Some(l) = sec.get("label").and_then(|x| x.as_str()) {
        if !l.is_empty() {
            return Some(l.to_string());
        }
    }
    let id = sec
        .get("id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())?;
    let looked_up = item
        .get("sections")
        .and_then(|s| s.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|s| s.get("id").and_then(|x| x.as_str()) == Some(id))
                .and_then(|s| s.get("label").and_then(|x| x.as_str()))
                .filter(|l| !l.is_empty())
        });
    Some(looked_up.unwrap_or(id).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the reference ----

    #[test]
    fn both_forms_round_trip_through_parse_and_render() {
        for text in [
            "op://V/host/password",
            "op://V/host/mysql/password",
            "op://V/github token/add more/fine-grained-token",
            // Parse is shape only: `op` cannot read this, but it is one.
            "op://V/db-admin (rw)/user",
        ] {
            let r = OpRef::parse(text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(r.to_string(), text);
        }
        assert_eq!(
            OpRef::parse("op://V/host/mysql/password"),
            Some(OpRef {
                vault: "V",
                item: "host",
                section: Some("mysql"),
                field: "password",
            })
        );
    }

    #[test]
    fn parse_accepts_only_three_or_four_non_empty_components() {
        for text in [
            "op://V/item",
            "op://V/item/a/b/c",
            "op://V//field",
            "op://V/item/",
            "op:///item/field",
            "op://V/item//field",
            "name:some-secret",
            "us-east-1",
            "",
        ] {
            assert_eq!(OpRef::parse(text), None, "{text}");
        }
    }

    #[test]
    fn an_empty_section_renders_the_unqualified_form() {
        let r = OpRef {
            vault: "V",
            item: "host",
            section: Some(""),
            field: "password",
        };
        // An empty section must not produce a double slash.
        assert_eq!(r.to_string(), "op://V/host/password");
        let none = OpRef { section: None, ..r };
        assert_eq!(none.to_string(), "op://V/host/password");
    }

    #[test]
    fn the_canonical_form_drops_a_default_section_and_only_that() {
        let canon = |t: &str| OpRef::parse(t).unwrap().canonical().to_string();
        assert_eq!(
            canon("op://V/eta-factory-github-app/add more/app-id"),
            "op://V/eta-factory-github-app/app-id"
        );
        assert_eq!(canon("op://V/item/Add More/app-id"), "op://V/item/app-id");
        // A section the operator named distinguishes a field and stays.
        assert_eq!(
            canon("op://V/host/mysql/password"),
            "op://V/host/mysql/password"
        );
        assert_eq!(canon("op://V/host/password"), "op://V/host/password");
    }

    // ---- the readability rule ----

    #[test]
    fn component_safety_matches_what_op_can_parse() {
        // Spaces are accepted by op's reference scanner.
        assert!(component_is_safe("db-admin jstephens MySQL"));
        assert!(component_is_safe("mysql8.etadventures.com"));
        assert!(component_is_safe("add more"));
        // These end the reference early, so op reports "too few '/'".
        assert!(!component_is_safe("db-admin jstephens MySQL (read-write)"));
        assert!(!component_is_safe("Grafana — grafana.etadventures.com"));
        assert!(!component_is_safe(""));
    }

    #[test]
    fn readability_matches_op() {
        assert!(is_readable("op://V/item/field"));
        assert!(is_readable("op://V/item/add more/field"));
        assert!(is_readable("op://V/db-admin jstephens/username"));
        // Three or more: a five-component reference is not flagged here.
        assert!(is_readable("op://V/item/a/b/field"));
        // Truncated by op's scanner, so op reports "too few '/'".
        assert!(!is_readable("op://V/db-admin (read-write)/username"));
        assert!(!is_readable("op://V/Grafana — host/username"));
        // Genuinely too few components, before any character question.
        assert!(!is_readable("op://V/item"));
        // Not a 1Password reference at all.
        assert!(!is_readable("name:some-secret"));
        // Literals are not readable references — callers must gate on the
        // op:// prefix so doctor does not treat them as errors (issue #53).
        assert!(!is_readable("us-east-1"));
        assert!(!is_readable("https://example.com/v1"));
    }

    #[test]
    fn doctor_style_filter_flags_only_malformed_op_refs() {
        // Same rule the doctor and edit-manifest apply: only values that claim
        // to be references, and fail the scanner among those.
        let lines = [
            ("GOOD", "op://V/item/field"),
            ("BAD_PARENS", "op://V/db-admin (rw)/user"),
            ("LITERAL_REGION", "us-east-1"),
            ("LITERAL_URL", "https://example.com/v1"),
        ];
        let flagged: Vec<&str> = lines
            .iter()
            .filter(|(_, v)| v.starts_with("op://") && !is_readable(v))
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(flagged, vec!["BAD_PARENS"]);
    }

    // ---- the listing ----

    #[test]
    fn item_list_yields_id_title_and_vault() {
        let json = r#"[
          {"id":"a1","title":"anthropic","vault":{"id":"v","name":"Orchestrator"}},
          {"id":"a2","title":"github token","vault":{"id":"v","name":"Orchestrator"}}
        ]"#;
        let listing = OpListing::from_json(json).unwrap();
        let rows = listing.items();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0],
            OpItem {
                id: "a1".into(),
                title: "anthropic".into(),
                vault: "Orchestrator".into(),
                vault_id: "v".into(),
            }
        );
        // Titles with spaces survive; op inject reads to end of line.
        assert_eq!(rows[1].title, "github token");
    }

    #[test]
    fn item_list_skips_rows_missing_id_or_title() {
        let json = r#"[{"id":"","title":"x"},{"id":"y","title":""},{"id":"ok","title":"t"}]"#;
        let listing = OpListing::from_json(json).unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing.items()[0].id, "ok");
    }

    #[test]
    fn item_list_rejects_non_array() {
        assert!(OpListing::from_json(r#"{"error":"nope"}"#).is_err());
        assert!(OpListing::from_json("not json").is_err());
    }

    #[test]
    fn notes_field_is_never_referenced() {
        // A note is prose. parse_dotenv_pairs ends an unquoted value at the
        // first blank or '#' line, so a referenced note aborts the whole
        // manifest with "expected KEY=value" the moment the prose has either.
        let json = r#"{"fields":[
          {"id":"password","label":"password","type":"CONCEALED","purpose":"PASSWORD","value":"s"},
          {"id":"notesPlain","label":"notesPlain","type":"STRING","purpose":"NOTES","value":"line\n\nmore"}
        ]}"#;
        assert_eq!(labels(json), vec!["password"]);
    }

    #[test]
    fn notes_purpose_match_is_case_insensitive() {
        let json = r#"{"fields":[
          {"id":"notesPlain","label":"notesPlain","type":"STRING","purpose":"notes","value":"x"}
        ]}"#;
        assert!(labels(json).is_empty());
    }

    #[test]
    fn a_field_merely_labelled_notes_is_still_referenced() {
        // Only the vault's NOTES purpose is prose. A user-created field that
        // happens to be called "notes" is an ordinary value and must survive.
        let json = r#"{"fields":[
          {"id":"f1","label":"notes","type":"STRING","value":"v"}
        ]}"#;
        assert_eq!(labels(json), vec!["notes"]);
    }

    fn labels(json: &str) -> Vec<String> {
        referenceable_fields(&serde_json::from_str(json).unwrap())
            .into_iter()
            .map(|f| match f.section {
                Some(s) => format!("{s}/{}", f.label),
                None => f.label,
            })
            .collect()
    }

    #[test]
    fn fields_keep_only_referenceable_labels() {
        let json = r#"{"fields":[
          {"id":"f1","label":"api-key","type":"CONCEALED","value":"SECRET"},
          {"id":"f2","label":"blank","type":"STRING","value":""},
          {"id":"f3","label":"totp","type":"OTP","value":"otpauth://x"},
          {"id":"f4","label":"","type":"STRING","value":"v"},
          {"id":"f5","type":"STRING","value":"v"}
        ]}"#;
        // api-key kept; blank is empty; totp is OTP; f4 and f5 have no usable
        // label so they fall back to their ids.
        assert_eq!(labels(json), vec!["api-key", "f4", "f5"]);
    }

    #[test]
    fn same_label_in_different_sections_is_kept_as_distinct_fields() {
        // Shape taken from a real vault: one host item with a top-level password
        // plus one per section. These are three different secrets.
        let json = r#"{"sections":[{"id":"s1","label":"mysql"},{"id":"s2","label":"replica"}],
          "fields":[
          {"id":"f1","label":"password","type":"CONCEALED","value":"a"},
          {"id":"f2","label":"password","type":"CONCEALED","value":"b","section":{"id":"s1","label":"mysql"}},
          {"id":"f3","label":"password","type":"CONCEALED","value":"c","section":{"id":"s2"}}
        ]}"#;
        // f3 carries only a section id; the label is resolved from `sections`.
        assert_eq!(
            labels(json),
            vec!["password", "mysql/password", "replica/password"]
        );
    }

    #[test]
    fn section_falls_back_to_its_id_when_unresolvable() {
        let json = r#"{"fields":[
          {"id":"f1","label":"password","type":"CONCEALED","value":"a","section":{"id":"orphan"}}
        ]}"#;
        assert_eq!(labels(json), vec!["orphan/password"]);
    }

    #[test]
    fn fields_are_deduplicated_and_missing_fields_is_not_an_error() {
        // Same label AND same section: a genuine duplicate.
        let json = r#"{"fields":[
          {"id":"f1","label":"dup","type":"STRING","value":"a"},
          {"id":"f2","label":"dup","type":"STRING","value":"b"}
        ]}"#;
        assert_eq!(labels(json), vec!["dup"]);
        assert!(referenceable_fields(&serde_json::json!({"id": "x"})).is_empty());
    }

    /// Two items in one vault: `db.example.com` expanded with a top-level
    /// `password`, a `password` under `mysql`, an `app-id` under the default
    /// section and an OTP that is never mapped; `github token` not expanded.
    fn listing() -> OpListing {
        let mut l = OpListing::from_json(
            r#"[
              {"id":"id-host","title":"db.example.com","vault":{"id":"vault-id-1","name":"Orchestrator"}},
              {"id":"id-other","title":"github token","vault":{"id":"vault-id-1","name":"Orchestrator"}}
            ]"#,
        )
        .unwrap();
        let mapped = l
            .expand(
                "id-host",
                r#"{"sections":[{"id":"s1","label":"mysql"},{"id":"s2","label":"add more"}],
                  "fields":[
                  {"id":"f1","label":"password","type":"CONCEALED","value":"a"},
                  {"id":"f2","label":"password","type":"CONCEALED","value":"b","section":{"id":"s1"}},
                  {"id":"f3","label":"app-id","type":"STRING","value":"c","section":{"id":"s2"}},
                  {"id":"f4","label":"one-time","type":"OTP","value":"otpauth://x"}
                ]}"#,
            )
            .unwrap();
        assert_eq!(mapped.len(), 3, "the OTP is never worth mapping");
        l
    }

    fn found(reference: &str) -> bool {
        matches!(listing().lookup(reference), Lookup::Found(it) if it.id == "id-host")
    }

    #[test]
    fn an_expanded_item_finds_its_fields_by_label_or_id() {
        assert!(found("op://Orchestrator/db.example.com/password"));
        assert!(found("op://Orchestrator/db.example.com/f1"));
        // Wider than what refresh maps: `op` still resolves the OTP field.
        assert!(found("op://Orchestrator/db.example.com/one-time"));
        // The item component may be the opaque id, which is what refresh writes
        // when the title is one `op` cannot parse.
        assert!(found("op://Orchestrator/id-host/password"));
        // Item gone from the listing, and field gone from an item that was read.
        assert_eq!(
            listing().lookup("op://Orchestrator/vanished/password"),
            Lookup::Absent
        );
        assert_eq!(
            listing().lookup("op://Orchestrator/db.example.com/api-key"),
            Lookup::Absent
        );
    }

    #[test]
    fn the_same_label_in_two_sections_is_found_qualified_or_not() {
        assert!(found("op://Orchestrator/db.example.com/mysql/password"));
        // Unqualified matches any section: `op` finds the label wherever it is.
        assert!(found("op://Orchestrator/db.example.com/app-id"));
        // Qualified asks for that section and no other.
        assert_eq!(
            listing().lookup("op://Orchestrator/db.example.com/replica/password"),
            Lookup::Absent
        );
    }

    #[test]
    fn a_default_section_is_the_same_as_no_section() {
        assert!(found("op://Orchestrator/id-host/add more/app-id"));
        assert!(found("op://Orchestrator/id-host/Add More/password"));
    }

    #[test]
    fn names_match_case_insensitively_and_a_vault_by_id() {
        // `op` matches names case-insensitively; a manifest written in another
        // case launches fine and must not be called absent.
        assert!(found("op://orchestrator/DB.Example.com/PASSWORD"));
        assert!(found("op://Orchestrator/db.example.com/MYSQL/password"));
        // `op` accepts a vault id in place of its name, so the listing has to
        // match on either. Judging by name alone would prune a working line.
        assert!(found("op://vault-id-1/db.example.com/password"));
        // A vault this token cannot see holds nothing it can resolve.
        assert_eq!(
            listing().lookup("op://Other/db.example.com/password"),
            Lookup::Absent
        );
        // Ids are not names: they match exactly.
        assert_eq!(
            listing().lookup("op://Orchestrator/ID-HOST/password"),
            Lookup::Absent
        );
    }

    #[test]
    fn an_item_this_run_did_not_expand_is_unexpanded() {
        assert_eq!(
            listing().lookup("op://Orchestrator/github token/api-key"),
            Lookup::Unexpanded
        );
        // An item whose JSON did not parse stays unexpanded.
        let mut l = listing();
        assert!(l.expand("id-other", "not json").is_err());
        assert_eq!(
            l.lookup("op://Orchestrator/github token/api-key"),
            Lookup::Unexpanded
        );
    }

    #[test]
    fn literals_unreadable_shapes_and_placeholders_are_not_references() {
        for r in [
            "us-east-1",
            "https://example.com/v1",
            "op://Orchestrator/db-admin (rw)/password",
            "op://Orchestrator/db.example.com",
            "op://Orchestrator/db.example.com/a/b/password",
            "",
            // A placeholder in any component, not only the spellings that
            // survive being read behind the `op://` prefix: invariant 4 keeps
            // them loud, and pruning one would take the variable out of the
            // manifest.
            "op://Orchestrator/db.example.com/REPLACE_WITH_FIELD",
            "op://Orchestrator/db.example.com/CHANGE_ME",
            "op://Orchestrator/YOUR_ITEM/password",
            "op://Orchestrator/db.example.com/TODO/password",
        ] {
            assert_eq!(listing().lookup(r), Lookup::NotARef, "{r}");
        }
    }

    // ---- naming and item→mappings ----

    #[test]
    fn var_names_uppercase_and_collapse_separators() {
        assert_eq!(
            var_name("anthropic", None, "conductor-api-key"),
            "ANTHROPIC_CONDUCTOR_API_KEY"
        );
        assert_eq!(
            var_name("github token", None, "fine-grained-token"),
            "GITHUB_TOKEN_FINE_GRAINED_TOKEN"
        );
        // Leading/trailing junk must not produce __ or a trailing _.
        assert_eq!(var_name("  spaced  ", None, "-field-"), "SPACED_FIELD");
        // A bare digit start is not a valid shell identifier.
        assert_eq!(var_name("3cx", None, "api-key"), "SECRET_3CX_API_KEY");
    }

    #[test]
    fn section_distinguishes_same_label_fields() {
        // Without the section these collapse to one VAR and one ambiguous
        // reference, silently dropping real secrets.
        let a = var_name("mysql8.etadventures.com", Some("mysql"), "password");
        let b = var_name("mysql8.etadventures.com", None, "password");
        assert_eq!(a, "MYSQL8_ETADVENTURES_COM_MYSQL_PASSWORD");
        assert_eq!(b, "MYSQL8_ETADVENTURES_COM_PASSWORD");
    }

    #[test]
    fn default_section_label_does_not_reach_the_name() {
        // 1Password labels the section holding ungrouped custom fields
        // "add more". Nobody typed it, and it made every generated name carry
        // it: ANTHROPIC_ADD_MORE_CONDUCTOR_API_KEY for a field whose own item
        // and label already say everything.
        assert_eq!(
            var_name("anthropic", Some("add more"), "conductor-api-key"),
            "ANTHROPIC_CONDUCTOR_API_KEY"
        );
        // 1Password's own casing is not guaranteed.
        assert!(section_is_default("Add More"));
        assert!(section_is_default(" add more "));
        // A section the operator named still distinguishes fields, which is the
        // whole reason the section is in the name at all.
        assert!(!section_is_default("mysql"));
        // With no section there is nothing to add back.
        assert_eq!(var_name_qualified("item", None, "field"), "ITEM_FIELD");
    }

    #[test]
    fn legacy_names_are_recognisable_for_doctor() {
        assert!(name_folds_default_section(
            "ETA_FACTORY_GITHUB_APP_ADD_MORE_APP_ID"
        ));
        assert!(name_folds_default_section(&var_name_qualified(
            "anthropic",
            Some("add more"),
            "conductor-api-key"
        )));
        // What refresh generates now must never look legacy.
        assert!(!name_folds_default_section(&var_name(
            "anthropic",
            Some("add more"),
            "conductor-api-key"
        )));
        assert!(!name_folds_default_section("PLAIN_API_KEY"));
        // A field genuinely named "add-more-seats" produces the same fragment,
        // so the name cannot be the whole test. The mapping pairs it with the
        // reference's section, which is only default when there really is one.
        assert!(name_folds_default_section("ZOOM_ADD_MORE_SEATS_URL"));
        assert!(!has_legacy_name(
            "ZOOM_ADD_MORE_SEATS_URL",
            "op://V/zoom/add-more-seats-url"
        ));
        assert!(has_legacy_name(
            "ANTHROPIC_ADD_MORE_CONDUCTOR_API_KEY",
            "op://V/anthropic/add more/conductor-api-key"
        ));
        assert!(!has_legacy_name(
            "ANTHROPIC_CONDUCTOR_API_KEY",
            "op://V/anthropic/add more/conductor-api-key"
        ));
    }

    fn item(title: &str) -> OpItem {
        OpItem {
            id: "7vjm6j5srnx2krtk5nvduzjjoe".into(),
            title: title.into(),
            vault: "V".into(),
            vault_id: "vid".into(),
        }
    }

    fn field(section: Option<&str>, label: &str) -> OpField {
        OpField {
            section: section.map(str::to_string),
            label: label.into(),
        }
    }

    fn pairs(m: &ItemMappings) -> Vec<(&str, &str)> {
        m.mappings
            .iter()
            .map(|m| (m.var.as_str(), m.reference.as_str()))
            .collect()
    }

    #[test]
    fn an_item_maps_each_field_to_a_name_and_a_reference() {
        let m = item_mappings(
            &item("mysql8.etadventures.com"),
            vec![
                field(None, "password"),
                field(Some("mysql"), "password"),
                field(Some("add more"), "api-key"),
            ],
        );
        assert_eq!(
            pairs(&m),
            [
                (
                    "MYSQL8_ETADVENTURES_COM_PASSWORD",
                    "op://V/mysql8.etadventures.com/password"
                ),
                (
                    "MYSQL8_ETADVENTURES_COM_MYSQL_PASSWORD",
                    "op://V/mysql8.etadventures.com/mysql/password"
                ),
                // The name drops the default section; the reference keeps it.
                (
                    "MYSQL8_ETADVENTURES_COM_API_KEY",
                    "op://V/mysql8.etadventures.com/add more/api-key"
                ),
            ]
        );
        assert!(m.skipped.is_empty());
    }

    #[test]
    fn a_clash_keeps_the_section_on_both_fields() {
        // One item carrying `app-id` loose and `app-id` under "add more" holds
        // two secrets. Both are qualified rather than letting one name win and
        // the other secret vanish.
        let m = item_mappings(
            &item("eta-factory-github-app"),
            vec![
                field(None, "app-id"),
                field(Some("add more"), "app-id"),
                field(None, "private-key"),
            ],
        );
        assert_eq!(
            pairs(&m),
            [
                (
                    "ETA_FACTORY_GITHUB_APP_APP_ID",
                    "op://V/eta-factory-github-app/app-id"
                ),
                (
                    "ETA_FACTORY_GITHUB_APP_ADD_MORE_APP_ID",
                    "op://V/eta-factory-github-app/add more/app-id"
                ),
                // A field with no clash keeps its short name.
                (
                    "ETA_FACTORY_GITHUB_APP_PRIVATE_KEY",
                    "op://V/eta-factory-github-app/private-key"
                ),
            ]
        );
    }

    #[test]
    fn an_unsafe_label_or_section_is_skipped() {
        let m = item_mappings(
            &item("host"),
            vec![
                field(None, "password"),
                field(None, "user (rw)"),
                field(Some("Grafana — prod"), "token"),
            ],
        );
        assert_eq!(pairs(&m), [("HOST_PASSWORD", "op://V/host/password")]);
        assert_eq!(
            m.skipped,
            [
                field(None, "user (rw)"),
                field(Some("Grafana — prod"), "token")
            ]
        );
    }

    #[test]
    fn an_unsafe_title_falls_back_to_the_item_id() {
        let m = item_mappings(
            &item("db-admin (read-write)"),
            vec![field(None, "username")],
        );
        // The variable name still comes from the title, so the fallback costs
        // readability only inside the reference.
        assert_eq!(
            pairs(&m),
            [(
                "DB_ADMIN_READ_WRITE_USERNAME",
                "op://V/7vjm6j5srnx2krtk5nvduzjjoe/username"
            )]
        );
    }
}
