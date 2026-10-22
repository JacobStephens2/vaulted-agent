//! Release-workflow seam: `.github/workflows/release.yml` as checked in.
//!
//! The build job's token is contents: read. The publish job keeps contents:
//! write, so it can still create the release. A job permissions block
//! replaces the workflow block for that job; a job with none inherits it.
//! GitHub documents that override, and an unspecified scope inside a block is
//! none.

use std::fs;
use std::path::Path;

const WORKFLOW: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/.github/workflows/release.yml");

#[derive(Debug)]
struct Permissions {
    contents: Option<String>,
}

#[derive(Debug)]
struct Job {
    name: String,
    permissions: Option<Permissions>,
}

#[derive(Debug)]
struct Parsed {
    permissions: Option<Permissions>,
    jobs: Vec<Job>,
    action_refs: Vec<String>,
    run_scripts: Vec<String>,
}

fn load() -> Parsed {
    let text = fs::read_to_string(Path::new(WORKFLOW)).expect("read release workflow");
    parse(&text)
}

fn parse(text: &str) -> Parsed {
    let mut parsed = Parsed {
        permissions: None,
        jobs: Vec::new(),
        action_refs: Vec::new(),
        run_scripts: Vec::new(),
    };
    let mut in_jobs = false;
    let mut open: Option<OpenPermissions> = None;
    let mut run_block: Option<RunBlock> = None;

    for raw in text.lines() {
        let indent = leading_spaces(raw);
        if let Some(block) = run_block.as_mut() {
            if raw.trim().is_empty() || indent > block.indent {
                block.body.push_str(raw.trim());
                block.body.push('\n');
                continue;
            }
            parsed.run_scripts.push(std::mem::take(&mut block.body));
            run_block = None;
        }

        let closes = open.as_ref().is_some_and(|open_permissions| {
            !raw.trim().is_empty()
                && !raw.trim_start().starts_with('#')
                && indent <= open_permissions.indent
        });
        if closes {
            close_permissions(&mut parsed, open.take().expect("open permissions"));
        }

        let Some(code) = code_line(raw) else {
            continue;
        };

        if indent == 0 {
            in_jobs = false;
            if code.starts_with("jobs:") {
                in_jobs = true;
            } else if key_value(code, "permissions").is_some() {
                open = Some(OpenPermissions::new(Owner::Workflow, indent));
            }
            continue;
        }

        if in_jobs && indent == 2 && is_job_header(code) {
            parsed.jobs.push(Job {
                name: code.trim_end_matches(':').to_string(),
                permissions: None,
            });
            continue;
        }

        if let Some(open_permissions) = open.as_mut() {
            if let Some(value) = key_value(code, "contents") {
                open_permissions.permissions.contents = Some(unquote(value).to_string());
            }
            continue;
        }

        if let Some(value) = key_value(code, "uses") {
            parsed.action_refs.push(unquote(value).to_string());
            continue;
        }

        if let Some(value) = key_value(code, "run") {
            if value == "|" {
                run_block = Some(RunBlock {
                    indent,
                    body: String::new(),
                });
            } else {
                parsed.run_scripts.push(unquote(value).to_string());
            }
            continue;
        }

        if !parsed.jobs.is_empty() && key_value(code, "permissions").is_some() {
            let index = parsed.jobs.len() - 1;
            open = Some(OpenPermissions::new(Owner::Job(index), indent));
        }
    }

    if let Some(block) = run_block {
        parsed.run_scripts.push(block.body);
    }
    if let Some(open_permissions) = open {
        close_permissions(&mut parsed, open_permissions);
    }
    parsed
}

struct OpenPermissions {
    owner: Owner,
    indent: usize,
    permissions: Permissions,
}

impl OpenPermissions {
    fn new(owner: Owner, indent: usize) -> Self {
        Self {
            owner,
            indent,
            permissions: Permissions { contents: None },
        }
    }
}

struct RunBlock {
    indent: usize,
    body: String,
}

enum Owner {
    Workflow,
    Job(usize),
}

fn close_permissions(parsed: &mut Parsed, open_permissions: OpenPermissions) {
    match open_permissions.owner {
        Owner::Workflow => parsed.permissions = Some(open_permissions.permissions),
        Owner::Job(index) => parsed.jobs[index].permissions = Some(open_permissions.permissions),
    }
}

/// Effective `contents` for `job`: its own block if it has one, else the
/// workflow block. `None` when neither names contents.
fn effective_contents<'a>(parsed: &'a Parsed, job: &str) -> Option<&'a str> {
    let job = parsed
        .jobs
        .iter()
        .find(|candidate| candidate.name == job)
        .unwrap_or_else(|| panic!("release workflow has no {job} job"));
    job.permissions
        .as_ref()
        .or(parsed.permissions.as_ref())
        .and_then(|permissions| permissions.contents.as_deref())
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

fn is_commit_sha(action: &str) -> bool {
    let Some((_, rev)) = action.rsplit_once('@') else {
        return false;
    };
    rev.len() == 40 && rev.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_cross_install(script: &str) -> bool {
    let tokens: Vec<&str> = script.split_whitespace().collect();
    let Some(cargo) = tokens.iter().position(|token| *token == "cargo") else {
        return false;
    };
    tokens.get(cargo + 1) == Some(&"install") && tokens.contains(&"cross")
}

fn records_version(script: &str) -> bool {
    let tokens: Vec<&str> = script.split_whitespace().collect();
    tokens.iter().enumerate().any(|(index, token)| {
        *token == "--version" && tokens.get(index + 1).is_some_and(|next| is_semver(next))
    })
}

fn is_semver(value: &str) -> bool {
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
    let parsed = load();
    assert_eq!(
        effective_contents(&parsed, "build"),
        Some("read"),
        "the build job's token must be contents: read\n{parsed:#?}"
    );
    assert_eq!(
        effective_contents(&parsed, "publish"),
        Some("write"),
        "the publish job must keep contents: write so it can create the release\n{parsed:#?}"
    );
}

#[test]
fn every_action_reference_is_a_commit_sha() {
    let parsed = load();
    assert!(
        !parsed.action_refs.is_empty(),
        "the release workflow should reference its actions"
    );
    let unpinned: Vec<_> = parsed
        .action_refs
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
    let installs: Vec<_> = load()
        .run_scripts
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
