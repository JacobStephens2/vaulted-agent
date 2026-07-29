//! Tickets 11–14: backends + va run.

mod common;

use common::CliSeam;
use std::fs;

#[test]
fn bitwarden_launch_resolves_name_ref_via_fake_bws() {
    let seam = CliSeam::new();
    let map = seam.write_secrets_json(
        "secrets.json",
        r#"{"openai-api-key":"sk-live-from-bws"}"#,
    );
    // Improved fake bws: list by key, get by id or key
    let script = format!(
        r#"#!/usr/bin/env bash
set -euo pipefail
map='{map}'
case "${{1-}} ${{2-}}" in
  "secret list")
    python3 -c "
import json
m=json.load(open('$map'))
print(json.dumps([{{'id': '00000000-0000-0000-0000-%012d' % i, 'key': k, 'project': {{'name': 'tools'}}}} for i,k in enumerate(m)]))
"
    ;;
  "secret get")
    id="${{3-}}"
    python3 -c "
import json,sys
m=json.load(open('$map'))
keys=list(m.keys())
# id ends with index padded
idx=int(sys.argv[1].split('-')[-1])
k=keys[idx]
print(json.dumps({{'value': m[k], 'key': k}}))
" "$id"
    ;;
  *)
    echo "fake-bws: unexpected: $*" >&2
    exit 1
    ;;
esac
"#,
        map = map.display()
    );
    seam.write_executable("bws", &script);
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/openai.env.refs"),
        "OPENAI_API_KEY=name:openai-api-key\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/claude.conf"),
        "backend = bitwarden\nmanifest = openai.env.refs\ncommand = agent\n",
    )
    .unwrap();
    fs::write(seam.config_dir.join("bws.env"), "BWS_ACCESS_TOKEN=test-token\n").unwrap();

    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .env("VAULTED_AGENT_AUTH_MODE", "file")
        .arg("claude")
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    let rec = seam.read_stub_record("agent");
    assert!(rec.contains("ENV OPENAI_API_KEY"), "{rec}");
    assert!(!rec.contains("BWS_ACCESS_TOKEN"), "token leaked: {rec}");
}

#[test]
fn va_run_injects_plainfile_into_command() {
    let seam = CliSeam::new();
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/full.env"),
        "APP_DB_PASS=from-run\n",
    )
    .unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .args([
            "run",
            "-m",
            "full.env",
            "--backend",
            "plainfile",
            "--",
            "agent",
        ])
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("agent");
    assert!(rec.contains("ENV APP_DB_PASS"), "{rec}");
}

#[test]
fn pass_backend_resolves_via_fake_pass() {
    let seam = CliSeam::new();
    seam.write_executable(
        "pass",
        "#!/usr/bin/env bash\nset -euo pipefail\nif [[ \"${1-}\" == show ]]; then echo \"pass-secret-value\"; exit 0; fi\nexit 1\n",
    );
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/pass.env.refs"),
        "APP_DB_PASS=apps/db\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/x.conf"),
        "backend = pass\nmanifest = pass.env.refs\ncommand = agent\n",
    )
    .unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("x")
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("agent");
    assert!(rec.contains("ENV APP_DB_PASS"), "{rec}");
}

#[test]
fn sops_backend_resolves_via_fake_sops() {
    let seam = CliSeam::new();
    seam.write_executable(
        "sops",
        "#!/usr/bin/env bash\nset -euo pipefail\necho 'APP_DB_PASS=sops-value'\n",
    );
    seam.install_stub_agent("agent");
    fs::write(seam.config_dir.join("age.key"), "AGE-SECRET-KEY-TEST\n").unwrap();
    fs::write(
        seam.config_dir.join("manifests/enc.env"),
        "APP_DB_PASS=encrypted\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/x.conf"),
        "backend = sops\nmanifest = enc.env\ncommand = agent\n",
    )
    .unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .arg("x")
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("agent");
    assert!(rec.contains("ENV APP_DB_PASS"), "{rec}");
}

#[test]
fn op_backend_resolves_via_fake_op_inject() {
    let seam = CliSeam::new();
    seam.write_executable(
        "op",
        "#!/usr/bin/env bash\nset -euo pipefail\nif [[ \"${1-}\" == inject ]]; then echo 'APP_DB_PASS=from-op'; exit 0; fi\nexit 1\n",
    );
    seam.install_stub_agent("agent");
    fs::write(
        seam.config_dir.join("manifests/op.env.refs"),
        "APP_DB_PASS=op://vault/item/password\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/x.conf"),
        "backend = onepassword\nmanifest = op.env.refs\ncommand = agent\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("op.env"),
        "OP_SERVICE_ACCOUNT_TOKEN=ops-test\n",
    )
    .unwrap();
    let out = seam
        .vaulted_agent()
        .env("VAULTED_AGENT_HANDOFF", "spawn")
        .env("VAULTED_AGENT_AUTH_MODE", "file")
        .arg("x")
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rec = seam.read_stub_record("agent");
    assert!(rec.contains("ENV APP_DB_PASS"), "{rec}");
}
