//! Release-script seam: `scripts/release.sh` as a process.
//!
//! The hosted bootstrap at https://vaultedagent.com/install.sh is piped into
//! bash as root on other people's machines. The script's job is the order in
//! docs/hosting-the-installer.md: never publish a DEFAULT_VERSION that has no
//! GitHub assets, and never serve the fat installer. Tests drive the script
//! with a fixture tree, a curl stub, and a local dest — no network, no SSH.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/release.sh");

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    path_dir: PathBuf,
    site: PathBuf,
    http: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("repo");
        let path_dir = tmp.path().join("bin");
        let site = tmp.path().join("site");
        let http = tmp.path().join("http");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&path_dir).unwrap();
        fs::create_dir_all(&site).unwrap();
        fs::create_dir_all(&http).unwrap();
        write_tree(&root);
        write_curl_stub(&path_dir, &http);
        Self {
            _tmp: tmp,
            root,
            path_dir,
            site,
            http,
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new("bash");
        cmd.arg(SCRIPT)
            .args(args)
            .current_dir(&self.root)
            .env("PATH", self.path())
            .env("VAULTED_AGENT_RELEASE_ROOT", &self.root)
            .env("VAULTED_AGENT_DEPLOY_LOCAL", "1")
            .env("VAULTED_AGENT_DEPLOY_PATH", &self.site)
            .env("GITHUB", "https://github.com");
        cmd
    }

    fn path(&self) -> String {
        format!(
            "{}:{}",
            self.path_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        )
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        self.cmd(args).output().expect("run release.sh")
    }

    fn set_asset(&self, version: &str, code: &str) {
        let musl = self.http.join(format!(
            "JacobStephens2/vaulted-agent/releases/download/{version}/vaulted-agent-x86_64-unknown-linux-musl.tar.gz"
        ));
        let src = self.http.join(format!(
            "JacobStephens2/vaulted-agent/archive/refs/tags/{version}.tar.gz"
        ));
        for path in [&musl, &src] {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(format!("{}.code", path.display()), code).unwrap();
        }
    }
}

fn write_tree(root: &Path) {
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"vaulted-agent\"\nversion = \"0.4.24\"\n",
    )
    .unwrap();
    fs::write(
        root.join("Cargo.lock"),
        "[[package]]\nname = \"vaulted-agent\"\nversion = \"0.4.24\"\n",
    )
    .unwrap();
    let remote = root.join("install-remote.sh");
    fs::write(
        &remote,
        "#!/usr/bin/env bash\nDEFAULT_VERSION=\"v0.4.24\"\ndetect_assets() { :; }\n",
    )
    .unwrap();
    fs::set_permissions(&remote, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(
        root.join("install.sh"),
        "#!/usr/bin/env bash\n# fat installer — must never be hosted\nSERVICE_USER=\"\"\n",
    )
    .unwrap();
    fs::write(
        root.join("AGENTS.md"),
        "Current release pin (product install): **v0.4.24**\n\
         VAULTED_AGENT_VERSION=v0.4.24 curl -fsSL https://vaultedagent.com/install.sh | bash\n\
         vaulted-agent version   # expect 0.4.24 (git stamp may appear in parentheses)\n\
         | Replace the installed launcher binary | `va update` / `va update v0.4.24` |\n",
    )
    .unwrap();
    fs::write(
        root.join("README.md"),
        "Latest: [v0.4.24](https://github.com/JacobStephens2/vaulted-agent/releases/tag/v0.4.24)\n\
         `VAULTED_AGENT_VERSION=v0.4.24` (or `latest`).\n\
         va update v0.4.24         # pin\n\
         Latest: [v0.4.24](https://github.com/JacobStephens2/vaulted-agent/releases/tag/v0.4.24)\n",
    )
    .unwrap();
    fs::write(
        root.join("MIGRATION.md"),
        "# Migration: updates add missing Harnesses (v0.4.24)\n\
         `va update v0.4.24` pins. `--check` and `--dry-run` write nothing.\n",
    )
    .unwrap();
}

fn write_curl_stub(path_dir: &Path, http: &Path) {
    let stub = path_dir.join("curl");
    fs::write(
        &stub,
        format!(
            r#"#!/usr/bin/env bash
set -euo pipefail
http="{http}"
url=""
want_code=0
for arg in "$@"; do
  case "$arg" in
    *'%{{http_code}}'*) want_code=1 ;;
    https://*|http://*|file://*) url=$arg ;;
  esac
done
[[ -n "$url" ]] || {{ echo "curl stub: no url in $*" >&2; exit 1; }}
path=${{url#https://github.com/}}
path=${{path#http://github.com/}}
code_file="$http/${{path}}.code"
if [[ "$want_code" -eq 1 ]]; then
  if [[ -f "$code_file" ]]; then cat "$code_file"; else printf '404'; fi
  exit 0
fi
if [[ -f "$code_file" && "$(cat "$code_file")" == "200" ]]; then
  printf 'stub-body\n'
  exit 0
fi
echo "curl stub: not found $url" >&2
exit 22
"#,
            http = http.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_ok(out: &std::process::Output) {
    assert!(
        out.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        out.status.code(),
        stdout(out),
        stderr(out)
    );
}

fn assert_fails(out: &std::process::Output, needle: &str) {
    assert!(
        !out.status.success(),
        "expected failure\nstdout={}\nstderr={}",
        stdout(out),
        stderr(out)
    );
    let combined = format!("{}{}", stdout(out), stderr(out));
    assert!(
        combined.contains(needle),
        "stderr/stdout should mention {needle:?}\n{combined}"
    );
}

#[test]
fn prepare_bumps_crate_bootstrap_and_pins_but_not_latest_links() {
    let fx = Fixture::new();
    let out = fx.run(&["prepare", "v0.4.25"]);
    assert_ok(&out);

    let cargo = fs::read_to_string(fx.root.join("Cargo.toml")).unwrap();
    assert!(cargo.contains("version = \"0.4.25\""), "{cargo}");
    assert!(!cargo.contains("version = \"0.4.24\""), "{cargo}");

    let lock = fs::read_to_string(fx.root.join("Cargo.lock")).unwrap();
    assert!(lock.contains("version = \"0.4.25\""), "{lock}");

    let bootstrap = fs::read_to_string(fx.root.join("install-remote.sh")).unwrap();
    assert!(
        bootstrap.contains("DEFAULT_VERSION=\"v0.4.25\""),
        "{bootstrap}"
    );
    let mode = fs::metadata(fx.root.join("install-remote.sh"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o111,
        0o111,
        "prepare must keep install-remote.sh executable"
    );

    let agents = fs::read_to_string(fx.root.join("AGENTS.md")).unwrap();
    assert!(agents.contains("**v0.4.25**"), "{agents}");
    assert!(agents.contains("VAULTED_AGENT_VERSION=v0.4.25"), "{agents}");
    assert!(agents.contains("expect 0.4.25"), "{agents}");
    assert!(agents.contains("`va update v0.4.25`"), "{agents}");
    assert!(!agents.contains("v0.4.24"), "{agents}");

    let readme = fs::read_to_string(fx.root.join("README.md")).unwrap();
    assert!(
        readme.contains("`VAULTED_AGENT_VERSION=v0.4.25`"),
        "{readme}"
    );
    assert!(readme.contains("va update v0.4.25"), "{readme}");
    let latest_lines: Vec<_> = readme.lines().filter(|l| l.contains("Latest:")).collect();
    assert_eq!(latest_lines.len(), 2, "{readme}");
    for line in latest_lines {
        assert!(
            line.contains("v0.4.24"),
            "prepare must not rewrite Latest links before the tag exists: {line}"
        );
        assert!(!line.contains("v0.4.25"), "{line}");
    }

    let migration = fs::read_to_string(fx.root.join("MIGRATION.md")).unwrap();
    assert!(
        migration.contains("# Migration: updates add missing Harnesses (v0.4.24)"),
        "historical heading must stay: {migration}"
    );
    assert!(
        migration.contains("`va update v0.4.25` pins."),
        "{migration}"
    );
}

#[test]
fn check_assets_fails_when_musl_asset_is_404() {
    let fx = Fixture::new();
    fx.set_asset("v0.4.25", "404");
    let out = fx.run(&["check-assets", "v0.4.25"]);
    assert_fails(&out, "404");
}

#[test]
fn check_assets_passes_when_both_urls_are_200() {
    let fx = Fixture::new();
    fx.set_asset("v0.4.25", "200");
    let out = fx.run(&["check-assets", "v0.4.25"]);
    assert_ok(&out);
}

#[test]
fn deploy_site_refuses_when_assets_404() {
    let fx = Fixture::new();
    fx.set_asset("v0.4.25", "404");
    fs::write(
        fx.root.join("install-remote.sh"),
        "#!/usr/bin/env bash\nDEFAULT_VERSION=\"v0.4.25\"\ndetect_assets() { :; }\n",
    )
    .unwrap();
    fs::write(fx.site.join("install.sh"), "old-bootstrap\n").unwrap();
    let out = fx.run(&["deploy-site", "v0.4.25"]);
    assert_fails(&out, "404");
    let dest = fs::read_to_string(fx.site.join("install.sh")).unwrap();
    assert_eq!(dest, "old-bootstrap\n");
}

#[test]
fn deploy_site_refuses_fat_installer() {
    let fx = Fixture::new();
    fx.set_asset("v0.4.25", "200");
    fs::write(
        fx.root.join("install-remote.sh"),
        "#!/usr/bin/env bash\nDEFAULT_VERSION=\"v0.4.25\"\nSERVICE_USER=\"\"\n",
    )
    .unwrap();
    fs::write(fx.site.join("install.sh"), "old-bootstrap\n").unwrap();
    let out = fx.run(&["deploy-site", "v0.4.25"]);
    assert_fails(&out, "detect_assets");
    let dest = fs::read_to_string(fx.site.join("install.sh")).unwrap();
    assert_eq!(dest, "old-bootstrap\n");
}

#[test]
fn deploy_site_refuses_when_bootstrap_pin_does_not_match() {
    let fx = Fixture::new();
    fx.set_asset("v0.4.25", "200");
    // fixture tree still pins v0.4.24
    fs::write(fx.site.join("install.sh"), "old-bootstrap\n").unwrap();
    let out = fx.run(&["deploy-site", "v0.4.25"]);
    assert_fails(&out, "DEFAULT_VERSION");
    let dest = fs::read_to_string(fx.site.join("install.sh")).unwrap();
    assert_eq!(dest, "old-bootstrap\n");
}

#[test]
fn deploy_site_writes_bootstrap_and_backup_when_assets_ok() {
    let fx = Fixture::new();
    fx.set_asset("v0.4.25", "200");
    fs::write(
        fx.root.join("install-remote.sh"),
        "#!/usr/bin/env bash\nDEFAULT_VERSION=\"v0.4.25\"\ndetect_assets() { :; }\n",
    )
    .unwrap();
    fs::write(
        fx.root.join("AGENTS.md"),
        "Current release pin (product install): **v0.4.25**\n",
    )
    .unwrap();
    fs::write(
        fx.site.join("install.sh"),
        "#!/usr/bin/env bash\nDEFAULT_VERSION=\"v0.4.24\"\ndetect_assets() { :; }\n",
    )
    .unwrap();
    fs::write(fx.site.join("AGENTS.md"), "old-agents\n").unwrap();
    fs::write(
        fx.site.join("index.html"),
        "Open source · macOS · Linux · v0.4.24\nCurrent release: `v0.4.24`\nUpgrading from v0.4.23 or earlier.\n",
    )
    .unwrap();

    let out = fx.run(&["deploy-site", "v0.4.25"]);
    assert_ok(&out);

    let dest = fs::read_to_string(fx.site.join("install.sh")).unwrap();
    assert!(dest.contains("DEFAULT_VERSION=\"v0.4.25\""), "{dest}");
    assert!(dest.contains("detect_assets"), "{dest}");
    let bak = fs::read_to_string(fx.site.join("install.sh.bak")).unwrap();
    assert!(bak.contains("DEFAULT_VERSION=\"v0.4.24\""), "{bak}");

    let agents = fs::read_to_string(fx.site.join("AGENTS.md")).unwrap();
    assert!(agents.contains("**v0.4.25**"), "{agents}");
    let agents_bak = fs::read_to_string(fx.site.join("AGENTS.md.bak")).unwrap();
    assert_eq!(agents_bak, "old-agents\n");

    let page = fs::read_to_string(fx.site.join("index.html")).unwrap();
    assert!(page.contains("Linux · v0.4.25"), "{page}");
    assert!(page.contains("`v0.4.25`"), "{page}");
    assert!(
        page.contains("Upgrading from v0.4.23 or earlier."),
        "historical notes must stay: {page}"
    );
}

#[test]
fn deploy_site_dry_run_writes_nothing() {
    let fx = Fixture::new();
    fx.set_asset("v0.4.25", "200");
    fs::write(
        fx.root.join("install-remote.sh"),
        "#!/usr/bin/env bash\nDEFAULT_VERSION=\"v0.4.25\"\ndetect_assets() { :; }\n",
    )
    .unwrap();
    fs::write(fx.site.join("install.sh"), "old-bootstrap\n").unwrap();
    let out = fx.run(&["deploy-site", "--dry-run", "v0.4.25"]);
    assert_ok(&out);
    let dest = fs::read_to_string(fx.site.join("install.sh")).unwrap();
    assert_eq!(dest, "old-bootstrap\n");
    assert!(!fx.site.join("install.sh.bak").exists());
}

#[test]
fn readme_latest_rewrites_the_two_latest_links() {
    let fx = Fixture::new();
    let out = fx.run(&["readme-latest", "v0.4.25"]);
    assert_ok(&out);
    let readme = fs::read_to_string(fx.root.join("README.md")).unwrap();
    let latest: Vec<_> = readme.lines().filter(|l| l.contains("Latest:")).collect();
    assert_eq!(latest.len(), 2, "{readme}");
    for line in latest {
        assert!(line.contains("v0.4.25"), "{line}");
        assert!(line.contains("/releases/tag/v0.4.25"), "{line}");
        assert!(!line.contains("v0.4.24"), "{line}");
    }
    assert!(
        readme.contains("`VAULTED_AGENT_VERSION=v0.4.24`"),
        "readme-latest only touches Latest links: {readme}"
    );
}
