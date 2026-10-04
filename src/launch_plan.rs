//! Launch plan: the pure half of the launch path.
//!
//! Built from the Harness, the resolved Secret values and the launch facts the
//! adapter in `launch.rs` gathered. No process env, filesystem, `defaults.conf`
//! or vault reads happen here, so every plan rule is testable without exec.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::config::{expand_home, Harness};
use crate::env_scrub::{apply_aliases, build_child_env, MANAGER_TOKEN_VARS};
use crate::error::{Error, Result};
use crate::resume;
use crate::secret::SecretValue;

/// Pure launch plan: everything needed to start the agent without executing yet.
#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub program: String,
    pub args: Vec<String>,
    pub workdir: PathBuf,
    pub env: HashMap<OsString, OsString>,
}

/// What the adapter learned about this launch before the plan is assembled.
#[derive(Debug, Clone)]
pub(crate) struct LaunchFacts {
    /// The Workdir, already settled by the preflight. Carried through unchanged.
    pub workdir: PathBuf,
    /// The launch account's `HOME`, for a leading `$HOME` in `bin` and the program.
    pub home: String,
    /// Snapshot of the parent environment (UTF-8 pairs only).
    pub parent_env: HashMap<String, String>,
    /// The agent's extra argv, after the harness name.
    pub extra_args: Vec<String>,
}

/// Assemble the plan: aliases → child env → `env=` → `bin`/PATH → argv.
pub(crate) fn plan(
    harness: &Harness,
    mut secrets: HashMap<String, SecretValue>,
    facts: LaunchFacts,
) -> Result<LaunchPlan> {
    // Per-harness renames after inject (issue #66). Mutates the secrets map
    // only; values are still never logged. Fail closed if a source is missing.
    apply_aliases(&mut secrets, &harness.aliases)?;

    let mut child_env = build_child_env(&facts.parent_env, &harness.keep, &secrets);

    // Harness `env = NAME = value`: non-secret child vars (e.g. temporary
    // KIMI_CODE_LEGACY_FLAG on kimi.conf until kimi-code#2746). Not for secrets.
    // Conf parsing refuses manager-token names too, but a Harness can be built
    // without a conf (`run`, tests), so invariant 1 is held here as well.
    for (k, v) in &harness.env_sets {
        if MANAGER_TOKEN_VARS.contains(&k.as_str()) {
            return Err(Error::Message(format!(
                "harness env cannot set manager-token name '{k}'"
            )));
        }
        child_env.insert(OsString::from(k.as_str()), OsString::from(v.as_str()));
    }

    let home = &facts.home;
    let mut cmdline = harness.command.clone();
    if let Some(bin) = &harness.bin_dir {
        let bin = expand_home(bin, home);
        let path = child_env
            .get(OsStr::new("PATH"))
            .map(|p| format!("{bin}:{}", p.to_string_lossy()))
            .unwrap_or_else(|| bin.clone());
        child_env.insert(OsString::from("PATH"), OsString::from(path));
    }

    if cmdline.is_empty() {
        return Err(Error::Message("empty command".into()));
    }
    let program = expand_home(&cmdline.remove(0), home);
    let agent_base = Path::new(&program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&program);

    let extra = resume::normalize_argv(agent_base, &facts.extra_args, harness.labels)?;

    let mut args = cmdline;
    args.extend(extra);

    Ok(LaunchPlan {
        program,
        args,
        workdir: facts.workdir,
        env: child_env,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn harness(command: &[&str]) -> Harness {
        Harness {
            name: "h".into(),
            backend: None,
            manifest: "m.env".into(),
            bin_dir: None,
            workdir: None,
            labels: false,
            keep: vec![],
            aliases: vec![],
            env_sets: vec![],
            command: command.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn secrets(pairs: &[(&str, &str)]) -> HashMap<String, SecretValue> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), SecretValue::new(*v)))
            .collect()
    }

    fn parent(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn facts() -> LaunchFacts {
        LaunchFacts {
            workdir: PathBuf::from("/work"),
            home: "/home/op".into(),
            parent_env: HashMap::new(),
            extra_args: vec![],
        }
    }

    fn get(plan: &LaunchPlan, name: &str) -> Option<String> {
        plan.env
            .get(OsStr::new(name))
            .map(|v| v.to_string_lossy().into_owned())
    }

    #[test]
    fn injected_secret_reaches_child() {
        let p = plan(
            &harness(&["agent"]),
            secrets(&[("APP_DB_PASS", "secret-value")]),
            facts(),
        )
        .unwrap();
        assert_eq!(get(&p, "APP_DB_PASS").as_deref(), Some("secret-value"));
        assert_eq!(p.program, "agent");
    }

    #[test]
    fn manager_token_absent_from_child_by_every_route() {
        for &tok in MANAGER_TOKEN_VARS {
            let mut h = harness(&["agent"]);
            h.keep = vec![tok.into()];
            let p = plan(
                &h,
                secrets(&[(tok, "from-secrets")]),
                LaunchFacts {
                    parent_env: parent(&[(tok, "from-parent")]),
                    ..facts()
                },
            )
            .unwrap();
            assert_eq!(get(&p, tok), None, "{tok}");
        }
    }

    #[test]
    fn keep_passes_named_parent_var_and_nothing_else() {
        let mut h = harness(&["agent"]);
        h.keep = vec!["SSH_AUTH_SOCK".into()];
        let p = plan(
            &h,
            HashMap::new(),
            LaunchFacts {
                parent_env: parent(&[
                    ("SSH_AUTH_SOCK", "/tmp/ssh.sock"),
                    ("PARENT_ONLY_SECRET", "leak-me"),
                    ("HOME", "/home/op"),
                ]),
                ..facts()
            },
        )
        .unwrap();
        assert_eq!(get(&p, "SSH_AUTH_SOCK").as_deref(), Some("/tmp/ssh.sock"));
        assert_eq!(get(&p, "HOME").as_deref(), Some("/home/op"));
        assert_eq!(get(&p, "PARENT_ONLY_SECRET"), None);
    }

    #[test]
    fn alias_copies_source() {
        let mut h = harness(&["agent"]);
        h.aliases = vec![("OPENAI_API_KEY".into(), "FIREWORKS_AI_API_KEY".into())];
        let p = plan(&h, secrets(&[("FIREWORKS_AI_API_KEY", "fw")]), facts()).unwrap();
        assert_eq!(get(&p, "OPENAI_API_KEY").as_deref(), Some("fw"));
        assert_eq!(get(&p, "FIREWORKS_AI_API_KEY").as_deref(), Some("fw"));
    }

    #[test]
    fn alias_missing_source_fails_closed() {
        let mut h = harness(&["agent"]);
        h.aliases = vec![("OPENAI_API_KEY".into(), "FIREWORKS_AI_API_KEY".into())];
        let err = plan(&h, secrets(&[("OPENAI_API_KEY", "oai")]), facts()).unwrap_err();
        assert!(
            format!("{err}").contains("not in the resolved manifest"),
            "{err}"
        );
    }

    #[test]
    fn env_sets_a_value() {
        let mut h = harness(&["agent"]);
        h.env_sets = vec![("KIMI_CODE_LEGACY_FLAG".into(), "1".into())];
        let p = plan(&h, HashMap::new(), facts()).unwrap();
        assert_eq!(get(&p, "KIMI_CODE_LEGACY_FLAG").as_deref(), Some("1"));
    }

    #[test]
    fn env_refuses_manager_token_name() {
        let mut h = harness(&["agent"]);
        h.env_sets = vec![("BWS_ACCESS_TOKEN".into(), "x".into())];
        let err = plan(&h, HashMap::new(), facts()).unwrap_err();
        assert!(
            format!("{err}").contains("cannot set manager-token name 'BWS_ACCESS_TOKEN'"),
            "{err}"
        );
    }

    #[test]
    fn bin_prepended_to_path_with_home_expanded() {
        let mut h = harness(&["agent"]);
        h.bin_dir = Some("$HOME/.local/bin".into());
        let p = plan(
            &h,
            HashMap::new(),
            LaunchFacts {
                parent_env: parent(&[("PATH", "/usr/bin:/bin")]),
                ..facts()
            },
        )
        .unwrap();
        assert_eq!(
            get(&p, "PATH").as_deref(),
            Some("/home/op/.local/bin:/usr/bin:/bin")
        );
    }

    #[test]
    fn bin_becomes_path_when_parent_has_none() {
        let mut h = harness(&["agent"]);
        h.bin_dir = Some("${HOME}/bin".into());
        let p = plan(&h, HashMap::new(), facts()).unwrap();
        assert_eq!(get(&p, "PATH").as_deref(), Some("/home/op/bin"));
    }

    #[test]
    fn home_expanded_in_program() {
        let p = plan(
            &harness(&["$HOME/bin/agent", "--x"]),
            HashMap::new(),
            facts(),
        )
        .unwrap();
        assert_eq!(p.program, "/home/op/bin/agent");
        assert_eq!(p.args, vec!["--x".to_string()]);
    }

    #[test]
    fn empty_command_refused() {
        let err = plan(&harness(&[]), HashMap::new(), facts()).unwrap_err();
        assert!(format!("{err}").contains("empty command"), "{err}");
    }

    #[test]
    fn resume_labels_normalized_when_labels_on() {
        let extra = vec!["--resume".to_string(), "my label".to_string()];
        let mut h = harness(&["claude", "--fixed"]);
        h.labels = true;
        let on = plan(
            &h,
            HashMap::new(),
            LaunchFacts {
                extra_args: extra.clone(),
                ..facts()
            },
        )
        .unwrap();
        let uuid = resume::label_to_uuid("my label", "vaulted-agent");
        assert_eq!(on.args, vec!["--fixed", "--resume", uuid.as_str()]);

        h.labels = false;
        let off = plan(
            &h,
            HashMap::new(),
            LaunchFacts {
                extra_args: extra.clone(),
                ..facts()
            },
        )
        .unwrap();
        assert_eq!(off.args, vec!["--fixed", "--resume", "my label"]);
    }

    #[test]
    fn workdir_carried_unchanged() {
        let p = plan(&harness(&["agent"]), HashMap::new(), facts()).unwrap();
        assert_eq!(p.workdir, PathBuf::from("/work"));
    }
}
