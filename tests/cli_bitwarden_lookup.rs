//! Issue #100: bound remote lookup work at the CLI acceptance seam.

mod common;

use common::CliSeam;
use std::fs;
use std::process::Output;

const FIRST: &str = "12345678-1234-5678-9012-123456789001";
const SECOND: &str = "12345678-1234-5678-9012-123456789002";
const THIRD: &str = "12345678-1234-5678-9012-123456789003";

fn harness(manifest: &str) -> CliSeam {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("harnesses.d/agy.conf"),
        "backend = bitwarden\nmanifest = test.refs\ncommand = agy\nworkdir = caller\n",
    )
    .unwrap();
    fs::write(seam.config_dir.join("manifests/test.refs"), manifest).unwrap();
    fs::write(
        seam.config_dir.join("bws.env"),
        "BWS_ACCESS_TOKEN=synthetic-manager-token\n",
    )
    .unwrap();
    seam.install_stub_agent("agy");
    fs::write(seam.root.join("calls"), "").unwrap();
    fs::write(
        seam.root.join("vault.json"),
        serde_json::json!([
            {"id": FIRST, "key": "first", "project": {"name": "tools"}, "value": "first-value"},
            {"id": SECOND, "key": "second", "project": {"name": "tools"}, "value": "second-value"},
            {"id": THIRD, "key": "second", "project": {"name": "other"}, "value": "other-project-value"}
        ])
        .to_string(),
    )
    .unwrap();
    // A fake external CLI, not a mock of a launcher module. Record verbs only.
    seam.write_executable(
        "bws",
        r#"#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(__file__).resolve().parent.parent
assert os.environ.get('BWS_ACCESS_TOKEN') == 'synthetic-manager-token'
assert sys.argv[1] == 'secret'
verb = sys.argv[2]
with (root / 'calls').open('a') as log:
    log.write(verb + '\n')
if (root / ('fail-' + verb)).exists():
    sys.exit('fixture forced ' + verb + ' failure')
rows = json.loads((root / 'vault.json').read_text())
if verb == 'list':
    print(json.dumps(rows))
elif verb == 'get':
    row = next(row for row in rows if row['id'] == sys.argv[3])
    print(json.dumps(row))
else:
    sys.exit('unexpected fake bws command')
"#,
    );
    seam
}

fn launch(seam: &CliSeam) -> Output {
    seam.vaulted_agent()
        .env("VAULTED_AGENT_AUTH_MODE", "file")
        .args(["agy", "--conversation", "conv-123"])
        .output()
        .expect("launch")
}

fn assert_success(out: &Output) {
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn calls(seam: &CliSeam, verb: &str) -> usize {
    fs::read_to_string(seam.root.join("calls"))
        .unwrap()
        .lines()
        .filter(|line| *line == verb)
        .count()
}

#[test]
fn mixed_refs_share_one_listing_and_preserve_the_child_contract() {
    let seam = harness(&format!(
        "BARE={FIRST}\nNAMED=name:first # uuid:{SECOND}\n\
         QUALIFIED=project:tools/second\nPREFIXED=uuid:{SECOND}\n"
    ));
    let out = launch(&seam);
    assert_success(&out);
    let child = seam.read_stub_record("agy");
    for expected in [
        "ENV BARE=first-value",
        "ENV NAMED=first-value",
        "ENV QUALIFIED=second-value",
        "ENV PREFIXED=second-value",
    ] {
        assert!(child.contains(expected), "missing {expected}: {child}");
    }
    assert_eq!(child.lines().next(), Some("ARGV: --conversation conv-123"));
    let cwd = child
        .lines()
        .find_map(|line| line.strip_prefix("ENV PWD="))
        .unwrap();
    assert_eq!(
        fs::canonicalize(cwd).unwrap(),
        fs::canonicalize(&seam.work_dir).unwrap()
    );
    assert!(!child.contains("BWS_ACCESS_TOKEN="));
    assert!(!child.contains("OP_SERVICE_ACCOUNT_TOKEN="));
    assert!(out.stdout.is_empty());
    assert!(out.stderr.is_empty());
    assert_eq!(calls(&seam, "get"), 4);
    assert_eq!(calls(&seam, "list"), 1, "listing repeated for named refs");
}

#[test]
fn uuid_only_and_empty_manifests_do_not_list() {
    for (manifest, gets) in [
        (format!("BARE={FIRST}\nPREFIXED=uuid:{SECOND}\n"), 2),
        ("# No references\n".to_string(), 0),
    ] {
        let seam = harness(&manifest);
        // Listing must not even be attempted, including when it is unavailable.
        fs::write(seam.root.join("fail-list"), "").unwrap();
        assert_success(&launch(&seam));
        assert_eq!(calls(&seam, "list"), 0);
        assert_eq!(calls(&seam, "get"), gets);
    }
}

#[test]
fn each_launch_reads_current_lookup_metadata_and_values() {
    let seam = harness("NAMED=name:first\nQUALIFIED=project:tools/second\n");
    assert_success(&launch(&seam));
    assert!(seam
        .read_stub_record("agy")
        .contains("ENV NAMED=first-value"));

    fs::write(
        seam.root.join("vault.json"),
        serde_json::json!([
            {"id": THIRD, "key": "first", "value": "new-first-value"},
            {"id": SECOND, "key": "second", "project": {"name": "tools"}, "value": "rotated-second-value"}
        ])
        .to_string(),
    )
    .unwrap();
    assert_success(&launch(&seam));
    let child = seam.read_stub_record("agy");
    assert!(child.contains("ENV NAMED=new-first-value"));
    assert!(child.contains("ENV QUALIFIED=rotated-second-value"));
    assert_eq!(calls(&seam, "list"), 2);
    assert_eq!(calls(&seam, "get"), 4);
}

#[test]
fn unresolved_refs_fail_closed_even_with_source_recordings() {
    for (reference, error, lists, gets) in [
        (
            format!("name:missing # uuid:{SECOND}"),
            "no secret matched",
            1,
            1,
        ),
        (
            format!("name:second # uuid:{SECOND}"),
            "multiple secrets named",
            1,
            1,
        ),
        ("project:missing/second".into(), "no secret matched", 1, 1),
        ("uuid:not-a-uuid".into(), "uuid: value is not a UUID", 0, 0),
    ] {
        let seam = harness(&format!("GOOD=name:first\nBAD={reference}\n"));
        let out = launch(&seam);
        assert!(!out.status.success(), "accepted {reference}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(error), "{stderr}");
        assert!(!seam.work_dir.join("agy.record").exists());
        assert_eq!(calls(&seam, "list"), lists);
        assert_eq!(calls(&seam, "get"), gets);
    }
}

#[test]
fn backend_failures_do_not_start_the_child() {
    for (verb, gets) in [("list", 0), ("get", 1)] {
        let seam = harness("NAMED=name:first\nQUALIFIED=project:tools/second\n");
        fs::write(seam.root.join(format!("fail-{verb}")), "").unwrap();
        let out = launch(&seam);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr)
            .contains(&format!("fixture forced {verb} failure")));
        assert!(!seam.work_dir.join("agy.record").exists());
        assert_eq!(calls(&seam, "list"), 1);
        assert_eq!(calls(&seam, "get"), gets);
    }
}
