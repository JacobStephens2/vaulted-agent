//! Issue #142: one `secrets validate` run resolves a shared Manifest once.
//!
//! Three Harnesses on one Bitwarden refs file used to cost three token loads
//! and three `bws secret list` calls. The Pre-flight report judges each
//! (Manifest, Backend) pair once and repeats the verdict on each Harness line.

mod common;

use common::CliSeam;
use std::fs;

const ID: &str = "12345678-1234-5678-9012-123456789001";

fn seam() -> CliSeam {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("manifests/shared.refs"),
        "FIRST=name:first\n",
    )
    .unwrap();
    for name in ["claude", "codex", "grok"] {
        seam.write_harness(
            name,
            "backend = bitwarden\nmanifest = shared.refs\ncommand = true\n",
        );
    }
    fs::write(
        seam.config_dir.join("bws.env"),
        "BWS_ACCESS_TOKEN=synthetic-manager-token\n",
    )
    .unwrap();
    fs::write(seam.root.join("calls"), "").unwrap();
    // A fake external CLI, not a mock of a launcher module. Record verbs only.
    seam.write_executable(
        "bws",
        &format!(
            r#"#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(__file__).resolve().parent.parent
assert os.environ.get('BWS_ACCESS_TOKEN') == 'synthetic-manager-token'
verb = sys.argv[2]
with (root / 'calls').open('a') as log:
    log.write(verb + '\n')
row = {{"id": "{ID}", "key": "first", "project": {{"name": "tools"}}, "value": "v"}}
print(json.dumps([row] if verb == 'list' else row))
"#
        ),
    );
    seam
}

fn calls(seam: &CliSeam, verb: &str) -> usize {
    fs::read_to_string(seam.root.join("calls"))
        .unwrap()
        .lines()
        .filter(|line| *line == verb)
        .count()
}

#[test]
fn three_harnesses_sharing_one_refs_file_list_the_vault_once() {
    let seam = seam();
    let out = seam
        .vaulted_agent()
        .args(["secrets", "validate"])
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .env("VAULTED_AGENT_AUTH_MODE", "file")
        .output()
        .expect("validate");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout={stdout}\nstderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Every Harness keeps its own line.
    for name in ["claude", "codex", "grok"] {
        assert!(
            stdout.contains(&format!("{name} (")) && stdout.contains("shared.refs"),
            "{stdout}"
        );
    }
    assert_eq!(
        stdout.matches("ok (1 variable(s) resolved)").count(),
        3,
        "{stdout}"
    );
    assert_eq!(calls(&seam, "list"), 1, "shared refs file listed per row");
    assert_eq!(calls(&seam, "get"), 1, "shared refs file resolved per row");
}
