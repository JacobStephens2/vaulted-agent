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

    /// Stub agent: writes argv and env var *names* to work_dir/<name>.record
    pub fn install_stub_agent(&self, name: &str) -> PathBuf {
        let record = self.work_dir.join(format!("{name}.record"));
        let script = format!(
            "#!/usr/bin/env bash\nset -euo pipefail\nrec='{}'\n{{\n  printf 'ARGV:'\n  printf ' %q' \"$@\"\n  printf '\\n'\n  env | sed -n 's/=.*//p' | sort | sed 's/^/ENV /'\n}} > \"$rec\"\n",
            record.display()
        );
        self.write_executable(name, &script)
    }

    pub fn read_stub_record(&self, name: &str) -> String {
        fs::read_to_string(self.work_dir.join(format!("{name}.record")))
            .unwrap_or_else(|e| panic!("read stub record {name}: {e}"))
    }

    /// Minimal fake `bws` reading a JSON object map of key -> value from a file.
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
    key="${{3-}}"
    python3 -c "
import json,sys
m=json.load(open('$map'))
k=sys.argv[1]
v=m.get(k)
if v is None:
    # try match fake id suffix as index
    keys=list(m.keys())
    v=m[keys[0]] if keys else ''
print(json.dumps({{'value': v}}))
" "$key"
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
}
