//! CLI acceptance seam helpers (spec: single process boundary).
//! Fixture config dir + PATH doubles + stub agent that records env/argv.

#![allow(dead_code)]

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// ETXTBSY, by number: unambiguous and stable everywhere.
const ETXTBSY: i32 = 26;

/// Run a command, retrying briefly while the kernel reports ETXTBSY.
///
/// These tests write a stub executable and immediately run it, while sibling
/// test threads in the same binary are spawning children of their own. A child
/// that forks in the window where the stub's write handle is still open
/// inherits that descriptor, and the kernel refuses to exec a file another
/// process holds open for writing. Nothing is wrong with the stub, and the
/// condition clears the moment that child execs, so wait it out rather than
/// fail the suite. Without this the seam fails roughly one run in five under
/// load, always with "Text file busy".
pub fn run_retrying_on_busy<T>(label: &str, mut attempt: impl FnMut() -> std::io::Result<T>) -> T {
    for _ in 0..100 {
        match attempt() {
            Ok(v) => return v,
            Err(e) if e.raw_os_error() == Some(ETXTBSY) => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => panic!("{label}: {e}"),
        }
    }
    panic!("{label}: still ETXTBSY after retrying for a second")
}

/// Isolated environment for one CLI acceptance test.
pub struct CliSeam {
    pub root: PathBuf,
    pub config_dir: PathBuf,
    pub path_dir: PathBuf,
    pub work_dir: PathBuf,
    _tmp: tempfile::TempDir,
}

impl CliSeam {
    pub fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmp = tempfile::Builder::new()
            .prefix(&format!("va-cli-{n}-"))
            .tempdir()
            .expect("tempdir");
        let root = tmp.path().to_path_buf();
        let config_dir = root.join("etc");
        let path_dir = root.join("bin");
        let work_dir = root.join("work");
        fs::create_dir_all(config_dir.join("harnesses.d")).unwrap();
        fs::create_dir_all(config_dir.join("manifests")).unwrap();
        fs::create_dir_all(&path_dir).unwrap();
        fs::create_dir_all(&work_dir).unwrap();
        Self {
            root,
            config_dir,
            path_dir,
            work_dir,
            _tmp: tmp,
        }
    }

    /// Command for the vaulted-agent under test with config + PATH wired.
    pub fn vaulted_agent(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_vaulted-agent"));
        cmd.env("VAULTED_AGENT_CONFIG_DIR", &self.config_dir);
        let path = format!(
            "{}:{}",
            self.path_dir.display(),
            env::var("PATH").unwrap_or_default()
        );
        cmd.env("PATH", path);
        cmd.current_dir(&self.work_dir);
        cmd.env_remove("BWS_ACCESS_TOKEN");
        cmd.env_remove("OP_SERVICE_ACCOUNT_TOKEN");
        cmd
    }

    pub fn write_executable(&self, name: &str, body: &str) -> PathBuf {
        let path = self.path_dir.join(name);
        fs::write(&path, body).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();
        path
    }

    /// Stub agent: writes argv and full ENV name=value lines to work_dir/<name>.record
    pub fn install_stub_agent(&self, name: &str) -> PathBuf {
        let record = self.work_dir.join(format!("{name}.record"));
        let script = format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nrec='{}'\n{{\n  printf 'ARGV:'\n  printf ' %q' \"$@\"\n  printf '\\n'\n  env | sort | sed 's/^/ENV /'\n}} > \"$rec\"\n",
            record.display()
        );
        self.write_executable(name, &script)
    }

    pub fn read_stub_record(&self, name: &str) -> String {
        fs::read_to_string(self.work_dir.join(format!("{name}.record")))
            .unwrap_or_else(|e| panic!("read stub record {name}: {e}"))
    }

    /// Minimal fake `bws` reading a JSON object map of key -> value from a file.
    /// `secret get` resolves by id suffix index (not first-key fallback).
    pub fn install_fake_bws(&self, secrets_json: &Path) -> PathBuf {
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
idx=int(sys.argv[1].rsplit('-', 1)[-1])
if idx < 0 or idx >= len(keys):
    sys.exit('fake-bws: id index out of range')
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
            map = secrets_json.display()
        );
        self.write_executable("bws", &script)
    }

    pub fn write_secrets_json(&self, name: &str, json: &str) -> PathBuf {
        let p = self.root.join(name);
        fs::write(&p, json).unwrap();
        p
    }

    /// Minimal fake `op` covering the two calls `refresh` makes:
    /// `item list --format json` and `item get <id> --format json`.
    ///
    /// Fixture deliberately includes an item title with a space, an empty
    /// field, an OTP field, and an item with no fields at all - each of which
    /// the real vault contains and the refs builder has to handle.
    /// Requires OP_SERVICE_ACCOUNT_TOKEN so tests prove the token reaches `op`.
    pub fn install_fake_op(&self) -> PathBuf {
        let script = r#"#!/usr/bin/env bash
set -euo pipefail
: "${OP_SERVICE_ACCOUNT_TOKEN:?fake-op: no token in env}"
case "${1-} ${2-}" in
  "item list")
    cat <<'JSON'
[
  {"id":"id-anthropic","title":"anthropic","vault":{"id":"v1","name":"Orchestrator"}},
  {"id":"id-github","title":"github token","vault":{"id":"v1","name":"Orchestrator"}},
  {"id":"id-bare","title":"bare item","vault":{"id":"v1","name":"Orchestrator"}},
  {"id":"id-host","title":"db.example.com","vault":{"id":"v1","name":"Orchestrator"}},
  {"id":"id-flaky","title":"flaky item","vault":{"id":"v1","name":"Orchestrator"}}
]
JSON
    ;;
  "item get")
    # Real `op` refuses `item get` without a vault query when the caller is a
    # service account, which is how this tool authenticates. Enforce it here so
    # dropping the flag fails in tests instead of only against a live vault.
    case " $* " in
      *" --vault "*) : ;;
      *) echo "fake-op: item get without --vault (service accounts require one)" >&2; exit 1 ;;
    esac
    case "${3-}" in
      id-anthropic)
        cat <<'JSON'
{"id":"id-anthropic","title":"anthropic","fields":[
  {"id":"f1","label":"conductor-api-key","type":"CONCEALED","value":"sk-SECRET-VALUE-1"},
  {"id":"f2","label":"blank-field","type":"STRING","value":""},
  {"id":"f3","label":"one-time","type":"OTP","value":"otpauth://SECRET-VALUE-2"}
]}
JSON
        ;;
      id-github)
        cat <<'JSON'
{"id":"id-github","title":"github token","fields":[
  {"id":"f1","label":"fine-grained-token","type":"CONCEALED","value":"github_pat_SECRET_VALUE_3"}
]}
JSON
        ;;
      id-host)
        # Shape from a real vault: one label repeated across sections, holding
        # different secrets. The second section carries only an id.
        cat <<'JSON'
{"id":"id-host","title":"db.example.com",
 "sections":[{"id":"s1","label":"mysql"},{"id":"s2","label":"replica"}],
 "fields":[
  {"id":"f1","label":"password","type":"CONCEALED","value":"SECRET-TOP"},
  {"id":"f2","label":"password","type":"CONCEALED","value":"SECRET-MYSQL","section":{"id":"s1","label":"mysql"}},
  {"id":"f3","label":"password","type":"CONCEALED","value":"SECRET-REPLICA","section":{"id":"s2"}}
]}
JSON
        ;;
      id-bare)
        printf '{"id":"id-bare","title":"bare item","fields":[]}\n'
        ;;
      id-flaky)
        # Stands in for a transient vault API failure (a real 502 aborted a
        # 50-second run mid-way) or an item the token cannot read.
        echo "[ERROR] error initializing client: Unknown: (502)" >&2
        exit 1
        ;;
      *)
        echo "fake-op: unknown item ${3-}" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    echo "fake-op: unexpected: $*" >&2
    exit 1
    ;;
esac
"#;
        self.write_executable("op", script)
    }

    pub fn write_harness(&self, name: &str, body: &str) -> PathBuf {
        let p = self
            .config_dir
            .join("harnesses.d")
            .join(format!("{name}.conf"));
        fs::write(&p, body).unwrap();
        p
    }
}
