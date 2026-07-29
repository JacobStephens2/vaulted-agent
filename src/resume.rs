//! Resume argv normalization for claude/codex/grok/kimi.

use crate::validate::is_uuid;

fn label_to_uuid(label: &str, namespace: &str) -> String {
    // UUIDv5 via python for stability matching bash (uuid.NAMESPACE_URL style with custom ns)
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(
            "import uuid,sys; print(uuid.uuid5(uuid.NAMESPACE_URL, sys.argv[2]+':'+sys.argv[1]))",
        )
        .arg(label)
        .arg(namespace)
        .output()
        .ok();
    out.and_then(|o| {
        if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else {
            None
        }
    })
    .unwrap_or_else(|| label.to_string())
}

fn map_labels(args: &[String], labels: bool) -> Vec<String> {
    if !labels {
        return args.to_vec();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--session-id" || a == "-r" || a == "--resume" {
            out.push(a.clone());
            i += 1;
            if i < args.len() && !args[i].starts_with('-') {
                let mut v = args[i].clone();
                if !is_uuid(&v) {
                    v = label_to_uuid(&v, "vaulted-agent");
                }
                out.push(v);
                i += 1;
            }
            continue;
        }
        if let Some(rest) = a.strip_prefix("--session-id=").or_else(|| a.strip_prefix("--resume=")) {
            let flag = a.split('=').next().unwrap();
            let mut v = rest.to_string();
            if !is_uuid(&v) {
                v = label_to_uuid(&v, "vaulted-agent");
            }
            out.push(format!("{flag}={v}"));
            i += 1;
            continue;
        }
        if a == "resume" {
            out.push(a.clone());
            i += 1;
            if i < args.len() && !args[i].starts_with('-') {
                let mut v = args[i].clone();
                if !is_uuid(&v) {
                    v = label_to_uuid(&v, "vaulted-agent");
                }
                out.push(v);
                i += 1;
            }
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    out
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
pub fn normalize_argv(agent_base: &str, args: &[String], labels: bool) -> Vec<String> {
    let args = map_labels(args, labels);
    match agent_base {
        "codex" => normalize_codex(&args),
        "claude" | "grok" | "kimi" => normalize_flag_resume(&args),
        _ => args,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_flag_to_subcommand() {
        let a = normalize_argv(
            "codex",
            &["--resume".into(), "abc".into()],
            false,
        );
        assert_eq!(a, vec!["resume", "abc"]);
    }

    #[test]
    fn claude_bare_resume_to_flag() {
        let a = normalize_argv("claude", &["resume".into(), "abc".into()], false);
        assert_eq!(a, vec!["--resume", "abc"]);
    }
}
