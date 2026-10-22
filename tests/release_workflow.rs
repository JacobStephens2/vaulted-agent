//! Release-workflow seam: `.github/workflows/release.yml` as checked in.
//!
//! The build job's token is contents: read. The publish job keeps contents:
//! write, so it can still create the release. A job `permissions` block
//! replaces the workflow block for that job; a job with none inherits it.
//! GitHub documents that override, and an unspecified scope inside a block is
//! none.

use std::fs;
use std::path::Path;

const WORKFLOW: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/.github/workflows/release.yml");

#[derive(Debug)]
struct Scope {
    shorthand: Option<String>,
    contents: Option<String>,
}

impl Scope {
    fn contents_access(&self) -> Option<&str> {
        if let Some(value) = &self.contents {
            return Some(value);
        }
        match self.shorthand.as_deref() {
            Some("read-all") => Some("read"),
            Some("write-all") => Some("write"),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct Job {
    name: String,
    permissions: Option<Scope>,
}

#[derive(Debug)]
struct Workflow {
    permissions: Option<Scope>,
    jobs: Vec<Job>,
}

fn load() -> Workflow {
    let text = fs::read_to_string(Path::new(WORKFLOW)).expect("read release workflow");
    parse(&text)
}

fn parse(text: &str) -> Workflow {
    let mut workflow = Workflow {
        permissions: None,
        jobs: Vec::new(),
    };
    let mut in_jobs = false;
    let mut open: Option<Open> = None;

    for raw in text.lines() {
        let indent = leading_spaces(raw);
        let closes = open.as_ref().is_some_and(|scope| {
            !raw.trim().is_empty() && !raw.trim_start().starts_with('#') && indent <= scope.indent
        });
        if closes {
            close_scope(&mut workflow, open.take().expect("open scope"));
        }

        let Some(text) = code_line(raw) else {
            continue;
        };

        if indent == 0 {
            in_jobs = false;
            if text.starts_with("jobs:") {
                in_jobs = true;
            } else if let Some(value) = key_value(text, "permissions") {
                open = Some(Open {
                    owner: Owner::Workflow,
                    indent,
                    scope: scope_from_header(value),
                });
            }
            continue;
        }

        if in_jobs && indent == 2 && is_job_header(text) {
            workflow.jobs.push(Job {
                name: text.trim_end_matches(':').to_string(),
                permissions: None,
            });
            continue;
        }

        if open.is_some() {
            if let Some(value) = key_value(text, "contents") {
                if let Some(scope) = open.as_mut() {
                    scope.scope.contents = Some(unquote(value).to_string());
                }
            }
            continue;
        }

        if !workflow.jobs.is_empty() {
            if let Some(value) = key_value(text, "permissions") {
                let index = workflow.jobs.len() - 1;
                open = Some(Open {
                    owner: Owner::Job(index),
                    indent,
                    scope: scope_from_header(value),
                });
            }
        }
    }
    if let Some(scope) = open {
        close_scope(&mut workflow, scope);
    }
    workflow
}

struct Open {
    owner: Owner,
    indent: usize,
    scope: Scope,
}

enum Owner {
    Workflow,
    Job(usize),
}

fn close_scope(workflow: &mut Workflow, open: Open) {
    match open.owner {
        Owner::Workflow => workflow.permissions = Some(open.scope),
        Owner::Job(index) => workflow.jobs[index].permissions = Some(open.scope),
    }
}

fn scope_from_header(value: &str) -> Scope {
    let value = unquote(value);
    Scope {
        shorthand: if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        },
        contents: None,
    }
}

/// Effective `contents` for `job`: its own block if it has one, else the
/// workflow block. `None` when neither names contents.
fn effective_contents<'a>(workflow: &'a Workflow, job: &str) -> Option<&'a str> {
    let job = workflow
        .jobs
        .iter()
        .find(|candidate| candidate.name == job)
        .unwrap_or_else(|| panic!("release workflow has no {job} job"));
    job.permissions
        .as_ref()
        .or(workflow.permissions.as_ref())
        .and_then(Scope::contents_access)
}

fn code_line(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let code = match raw.find('#') {
        Some(index) if index == 0 || raw.as_bytes().get(index - 1) == Some(&b' ') => {
            raw[..index].trim_end()
        }
        _ => raw.trim_end(),
    };
    let code = code.trim();
    if code.is_empty() {
        None
    } else {
        Some(code)
    }
}

fn leading_spaces(raw: &str) -> usize {
    raw.chars().take_while(|c| *c == ' ').count()
}

fn is_job_header(text: &str) -> bool {
    let name = text.trim_end_matches(':');
    text.ends_with(':') && !name.is_empty() && !name.contains(':') && !name.starts_with('-')
}

fn key_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let text = text.trim_start_matches("- ").trim();
    let (found, value) = text.split_once(':')?;
    if found.trim() == key {
        Some(value.trim())
    } else {
        None
    }
}

fn unquote(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

/// `uses:` values outside of `run:` block scalars. The ref GitHub fetches is
/// the text after `@`; a comment does not pin it.
fn action_refs(text: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let mut block_indent: Option<usize> = None;
    for raw in text.lines() {
        let indent = leading_spaces(raw);
        if let Some(limit) = block_indent {
            if raw.trim().is_empty() || raw.trim_start().starts_with('#') || indent > limit {
                continue;
            }
            block_indent = None;
        }
        let Some(code) = code_line(raw) else {
            continue;
        };
        if let Some(value) = key_value(code, "uses") {
            refs.push(unquote(value).to_string());
        }
        if let Some(value) = key_value(code, "run") {
            if matches!(value, "|" | ">" | "|-" | ">-" | "|+" | ">+") {
                block_indent = Some(indent);
            }
        }
    }
    refs
}

fn is_commit_sha(action: &str) -> bool {
    let Some((_, rev)) = action.rsplit_once('@') else {
        return false;
    };
    rev.len() == 40 && rev.chars().all(|c| c.is_ascii_hexdigit())
}

fn run_scripts(text: &str) -> Vec<String> {
    let mut scripts = Vec::new();
    let mut block: Option<(usize, String)> = None;
    for raw in text.lines() {
        let indent = leading_spaces(raw);
        if let Some((limit, body)) = block.as_mut() {
            if raw.trim().is_empty() || indent > *limit {
                body.push_str(raw.trim());
                body.push('\n');
                continue;
            }
            scripts.push(std::mem::take(body));
            block = None;
        }
        let Some(code) = code_line(raw) else {
            continue;
        };
        if let Some(value) = key_value(code, "run") {
            if matches!(value, "|" | ">" | "|-" | ">-" | "|+" | ">+") {
                block = Some((indent, String::new()));
            } else {
                scripts.push(unquote(value).to_string());
            }
        }
    }
    if let Some((_, body)) = block {
        scripts.push(body);
    }
    scripts
}

fn is_cross_install(script: &str) -> bool {
    let tokens: Vec<&str> = script.split_whitespace().collect();
    let Some(cargo) = tokens.iter().position(|token| *token == "cargo") else {
        return false;
    };
    if tokens.get(cargo + 1) != Some(&"install") {
        return false;
    }
    tokens
        .iter()
        .any(|token| *token == "cross" || token.strip_prefix("cross@").is_some_and(is_semver))
}

fn records_version(script: &str) -> bool {
    let tokens: Vec<&str> = script.split_whitespace().collect();
    tokens.iter().enumerate().any(|(index, token)| {
        if let Some(rest) = token.strip_prefix("--version=") {
            return is_semver(rest);
        }
        if *token == "--version" || *token == "--tag" {
            return tokens.get(index + 1).is_some_and(|next| is_semver(next));
        }
        token.strip_prefix("cross@").is_some_and(is_semver)
    })
}

fn is_semver(value: &str) -> bool {
    let value = value.strip_prefix('v').unwrap_or(value);
    let mut parts = value.split('.');
    let Some(major) = parts.next() else {
        return false;
    };
    let Some(minor) = parts.next() else {
        return false;
    };
    let Some(patch) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && !major.is_empty()
        && major.chars().all(|c| c.is_ascii_digit())
        && !minor.is_empty()
        && minor.chars().all(|c| c.is_ascii_digit())
        && !patch.is_empty()
        && patch.chars().all(|c| c.is_ascii_digit())
}

#[test]
fn build_job_is_contents_read_and_publish_can_create_the_release() {
    let workflow = load();
    assert_eq!(
        effective_contents(&workflow, "build"),
        Some("read"),
        "the build job's token must be contents: read\n{workflow:#?}"
    );
    assert_eq!(
        effective_contents(&workflow, "publish"),
        Some("write"),
        "the publish job must keep contents: write so it can create the release\n{workflow:#?}"
    );
}

#[test]
fn every_action_reference_is_a_commit_sha() {
    let text = fs::read_to_string(Path::new(WORKFLOW)).expect("read release workflow");
    let refs = action_refs(&text);
    assert!(
        !refs.is_empty(),
        "the release workflow should reference its actions"
    );
    let unpinned: Vec<_> = refs
        .iter()
        .filter(|action| !is_commit_sha(action))
        .cloned()
        .collect();
    assert!(
        unpinned.is_empty(),
        "every action reference must be a 40-character commit SHA, unpinned: {unpinned:?}"
    );
}

#[test]
fn aarch64_cross_install_records_a_version_and_stays_locked() {
    let text = fs::read_to_string(Path::new(WORKFLOW)).expect("read release workflow");
    let installs: Vec<_> = run_scripts(&text)
        .into_iter()
        .filter(|script| is_cross_install(script))
        .collect();
    assert_eq!(
        installs.len(),
        1,
        "expected the one aarch64 cross install, found {installs:?}"
    );
    let script = &installs[0];
    assert!(
        script.split_whitespace().any(|token| token == "--locked"),
        "the aarch64 cross install must keep --locked: {script}"
    );
    assert!(
        records_version(script),
        "the aarch64 cross install must record a version: {script}"
    );
}
