mod common;

use common::CliSeam;
use std::env;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;

fn seam_with_agent() -> CliSeam {
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(seam.config_dir.join("manifests/one.env"), "A=1\n").unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend  = plainfile\nmanifest = one.env\ncommand  = agent\n",
    )
    .unwrap();
    seam
}

fn conductor_link(seam: &CliSeam) -> std::path::PathBuf {
    let link = seam.path_dir.join("claude-conductor");
    symlink(Path::new(env!("CARGO_BIN_EXE_vaulted-agent")), &link).unwrap();
    link
}

fn run(seam: &CliSeam, link: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(link);
    cmd.env("VAULTED_AGENT_CONFIG_DIR", &seam.config_dir);
    cmd.env(
        "PATH",
        format!(
            "{}:{}",
            seam.path_dir.display(),
            env::var("PATH").unwrap_or_default()
        ),
    );
    cmd.current_dir(&seam.work_dir);
    cmd.env("VAULTED_AGENT_HANDOFF", "spawn");
    cmd.env_remove("VAULTED_AGENT_PROMPT_AUTH");
    cmd.args(args);
    common::run_retrying_on_busy("launch through conductor symlink", || cmd.output())
}

#[test]
fn conductor_symlink_passes_dash_p_through_to_the_agent() {
    // claude, codex and kimi all use -p for a prompt. Under a symlink the
    // harness is already fixed by the link name, so there is no launcher flag
    // to read here and -p belongs to the agent. Eating it as --prompt-auth
    // silently dropped the prompt and demanded a vault token instead.
    let seam = seam_with_agent();
    let link = conductor_link(&seam);
    let out = run(&seam, &link, &["-p", "explain this"]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("agent");
    let argv = rec.lines().next().unwrap_or_default();
    assert!(argv.contains("-p"), "-p did not reach the agent: {argv}");
    assert!(
        argv.contains("explain"),
        "prompt did not reach the agent: {argv}"
    );
}

#[test]
fn conductor_symlink_still_strips_a_leading_double_dash() {
    let seam = seam_with_agent();
    let link = conductor_link(&seam);
    let out = run(&seam, &link, &["--", "-p", "explain this"]);
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("agent");
    let argv = rec.lines().next().unwrap_or_default();
    assert!(argv.contains("-p"), "{argv}");
    assert!(
        !argv.contains("--\u{20}-p") && !argv.starts_with("ARGV: --"),
        "leading -- should be consumed: {argv}"
    );
}

#[test]
fn conductor_symlink_still_refuses_harness_override() {
    // The link name is authoritative; -H would let a narrow entitlement borrow
    // a wider harness. Unchanged by the -p fix, asserted so it stays that way.
    let seam = seam_with_agent();
    let link = conductor_link(&seam);
    let out = run(&seam, &link, &["-H", "other"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("-H/--harness is not allowed"), "{err}");
}

#[test]
fn conductor_symlink_refuses_a_manifest_override() {
    // -m names the manifest outright, which is the same borrow -H is refused
    // for by a shorter route: the point of the link is that a sudoers rule
    // granting one harness grants one set of credentials.
    let seam = seam_with_agent();
    let link = conductor_link(&seam);
    fs::write(seam.config_dir.join("manifests/wide.env"), "B=2\n").unwrap();

    for args in [
        vec!["-m", "wide.env"],
        vec!["--manifest", "wide.env"],
        vec!["--manifest=wide.env"],
    ] {
        let out = run(&seam, &link, &args);
        assert!(!out.status.success(), "{args:?} should be refused");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("-m/--manifest is not allowed"), "{err}");
    }

    // The agent must not have run at all — a refusal that still launched would
    // be worse than no check.
    assert!(!seam.work_dir.join("agent.record").exists());
}
