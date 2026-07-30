//! Resume argv normalization for claude/codex/grok/kimi.

use crate::error::{Error, Result};
use crate::validate::is_uuid;

/// UUIDv5 over NAMESPACE_URL of `namespace:label` — matches prior bash/python:
/// `uuid.uuid5(uuid.NAMESPACE_URL, f"{namespace}:{label}")`.
pub fn label_to_uuid(label: &str, namespace: &str) -> String {
    let name = format!("{namespace}:{label}");
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, name.as_bytes()).to_string()
}

fn map_labels(args: &[String], labels: bool) -> Result<Vec<String>> {
    if !labels {
        return Ok(args.to_vec());
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--session-id" || a == "-r" || a == "--resume" {
            out.push(a.clone());
            i += 1;
            if i < args.len() && !args[i].starts_with('-') {
                let v = &args[i];
                if is_uuid(v) {
                    out.push(v.clone());
                } else {
                    let mapped = label_to_uuid(v, "vaulted-agent");
                    if !is_uuid(&mapped) {
                        return Err(Error::Message(format!(
                            "labels: failed to map session label {v:?} to UUID"
                        )));
                    }
                    out.push(mapped);
                }
                i += 1;
            }
            continue;
        }
        if let Some(rest) = a
            .strip_prefix("--session-id=")
            .or_else(|| a.strip_prefix("--resume="))
        {
            let flag = a.split('=').next().unwrap();
            if is_uuid(rest) {
                out.push(format!("{flag}={rest}"));
            } else {
                let mapped = label_to_uuid(rest, "vaulted-agent");
                if !is_uuid(&mapped) {
                    return Err(Error::Message(format!(
                        "labels: failed to map session label {rest:?} to UUID"
                    )));
                }
                out.push(format!("{flag}={mapped}"));
            }
            i += 1;
            continue;
        }
        if a == "resume" {
            out.push(a.clone());
            i += 1;
            if i < args.len() && !args[i].starts_with('-') {
                let v = &args[i];
                if is_uuid(v) {
                    out.push(v.clone());
                } else {
                    let mapped = label_to_uuid(v, "vaulted-agent");
                    if !is_uuid(&mapped) {
                        return Err(Error::Message(format!(
                            "labels: failed to map session label {v:?} to UUID"
                        )));
                    }
                    out.push(mapped);
                }
                i += 1;
            }
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    Ok(out)
}

fn normalize_codex(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--resume" || a == "-r" {
            out.push("resume".into());
            i += 1;
            if i < args.len() && !args[i].starts_with('-') {
                out.push(args[i].clone());
                i += 1;
            }
            continue;
        }
        if let Some(rest) = a.strip_prefix("--resume=") {
            out.push("resume".into());
            out.push(rest.to_string());
            i += 1;
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    out
}

fn normalize_flag_resume(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "resume" {
            out.push("--resume".into());
            i += 1;
            if i < args.len() && !args[i].starts_with('-') {
                out.push(args[i].clone());
                i += 1;
            }
            continue;
        }
        out.push(args[i].clone());
        i += 1;
    }
    out
}

/// Apply label mapping then agent-specific resume normalization.
pub fn normalize_argv(agent_base: &str, args: &[String], labels: bool) -> Result<Vec<String>> {
    let args = map_labels(args, labels)?;
    Ok(match agent_base {
        "codex" => normalize_codex(&args),
        "claude" | "grok" | "kimi" => normalize_flag_resume(&args),
        _ => args,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_flag_to_subcommand() {
        let a = normalize_argv("codex", &["--resume".into(), "abc".into()], false).unwrap();
        assert_eq!(a, vec!["resume", "abc"]);
    }

    #[test]
    fn claude_bare_resume_to_flag() {
        let a = normalize_argv("claude", &["resume".into(), "abc".into()], false).unwrap();
        assert_eq!(a, vec!["--resume", "abc"]);
    }

    #[test]
    fn label_maps_to_stable_uuidv5_python_parity() {
        let u = label_to_uuid("my-label", "vaulted-agent");
        // python3: uuid.uuid5(uuid.NAMESPACE_URL, "vaulted-agent:my-label")
        assert_eq!(u, "d248adc0-ec24-5347-a7f7-d3cd06a1c790");
        assert_eq!(u, label_to_uuid("my-label", "vaulted-agent"));
    }

    #[test]
    fn labels_maps_session_arg() {
        let a = normalize_argv("claude", &["--resume".into(), "my-label".into()], true).unwrap();
        assert_eq!(a[0], "--resume");
        assert!(is_uuid(&a[1]), "{a:?}");
        assert_ne!(a[1], "my-label");
    }
}
