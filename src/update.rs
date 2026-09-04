//! Replace the installed launcher binary from a GitHub release asset.
//!
//! Binary only: does not re-run install.sh and does not touch harnesses,
//! manifests, or token files. Asset names match `install-remote.sh`.

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};

const DEFAULT_REPO: &str = "JacobStephens2/vaulted-agent";
const DEFAULT_GITHUB: &str = "https://github.com";
const DEFAULT_GITHUB_API: &str = "https://api.github.com";

/// Release-asset stems, best first, for this OS/arch pair.
///
/// `os`/`arch` are `std::env::consts` values (`linux`/`macos`, `x86_64`/`aarch64`).
pub fn asset_names(os: &str, arch: &str) -> Result<Vec<&'static str>> {
    match (os, arch) {
        ("linux", "x86_64") => Ok(vec![
            "vaulted-agent-x86_64-unknown-linux-musl",
            "vaulted-agent-x86_64-unknown-linux-gnu",
        ]),
        ("linux", "aarch64") => Ok(vec![
            "vaulted-agent-aarch64-unknown-linux-musl",
            "vaulted-agent-aarch64-unknown-linux-gnu",
        ]),
        ("macos", "x86_64") => Ok(vec!["vaulted-agent-x86_64-apple-darwin"]),
        ("macos", "aarch64") => Ok(vec!["vaulted-agent-aarch64-apple-darwin"]),
        _ => Err(Error::Message(format!(
            "update: no release asset for {os}-{arch}"
        ))),
    }
}

pub fn normalize_tag(raw: &str) -> String {
    let t = raw.trim();
    if t.is_empty() || t.starts_with('v') || t.starts_with('V') {
        t.to_string()
    } else if t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("v{t}")
    } else {
        t.to_string()
    }
}

pub fn parse_latest_tag(json: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| Error::Message(format!("update: latest release JSON: {e}")))?;
    let tag = v
        .get("tag_name")
        .and_then(|t| t.as_str())
        .ok_or_else(|| Error::Message("update: latest release response had no tag_name".into()))?;
    let tag = tag.trim();
    if tag.is_empty() {
        return Err(Error::Message(
            "update: latest release response had no tag_name".into(),
        ));
    }
    Ok(normalize_tag(tag))
}

struct Opts {
    check: bool,
    dry_run: bool,
    help: bool,
    tag: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Opts> {
    let mut check = false;
    let mut dry_run = false;
    let mut help = false;
    let mut tag = None;
    for a in args {
        match a.as_str() {
            "--check" => check = true,
            "--dry-run" => dry_run = true,
            "-h" | "--help" => help = true,
            s if s.starts_with('-') => {
                return Err(Error::Message(format!(
                    "update: unknown option '{s}'\n{}",
                    usage_text()
                )));
            }
            s => {
                if tag.is_some() {
                    return Err(Error::Message(
                        "update: extra argument; want at most one VERSION".into(),
                    ));
                }
                tag = Some(normalize_tag(s));
            }
        }
    }
    Ok(Opts {
        check,
        dry_run,
        help,
        tag,
    })
}

fn usage_text() -> &'static str {
    "usage: vaulted-agent update [VERSION]\n\
     \x20      vaulted-agent update --check [VERSION]\n\
     \x20      vaulted-agent update --dry-run [VERSION]\n\
     \nReplace the installed launcher binary with a GitHub release asset.\n\
     Default VERSION is VAULTED_AGENT_VERSION, else the latest GitHub release.\n\
     Does not re-run install.sh and does not change harnesses or manifests."
}

fn print_usage() {
    eprintln!("{}", usage_text());
}

pub fn cmd_update(args: &[String]) -> Result<()> {
    let opts = parse_args(args)?;
    if opts.help {
        print_usage();
        return Ok(());
    }

    let dest = resolve_dest()?;
    let current = env!("CARGO_PKG_VERSION");
    let tag = resolve_tag(opts.tag.as_deref())?;

    println!("current: {current}");
    println!("target:  {tag}");
    println!("dest:    {}", dest.display());

    if opts.check {
        if current_matches(current, &tag) {
            println!("already current");
        } else {
            println!("update available");
        }
        return Ok(());
    }

    let work = work_dir()?;
    let extracted = match env::var_os("VAULTED_AGENT_UPDATE_ASSET") {
        Some(p) => {
            let bin = extract_tarball(Path::new(&p), &work)?;
            prepare_bin(&bin)?;
            bin
        }
        None => download_asset(&tag, &work)?,
    };

    if opts.dry_run {
        println!(
            "dry-run: would install {} -> {}",
            extracted.display(),
            dest.display()
        );
        let _ = fs::remove_dir_all(&work);
        return Ok(());
    }

    install_over(&extracted, &dest)?;
    let _ = fs::remove_dir_all(&work);
    println!("updated {}", dest.display());
    Ok(())
}

fn current_matches(current: &str, tag: &str) -> bool {
    let t = tag.strip_prefix('v').unwrap_or(tag);
    current == t
}

fn resolve_tag(explicit: Option<&str>) -> Result<String> {
    if let Some(t) = explicit {
        return Ok(t.to_string());
    }
    if let Ok(v) = env::var("VAULTED_AGENT_VERSION") {
        let v = v.trim();
        if !v.is_empty() && v != "latest" {
            return Ok(normalize_tag(v));
        }
    }
    if env::var_os("VAULTED_AGENT_UPDATE_ASSET").is_some() {
        return Ok("local".into());
    }
    fetch_latest()
}

fn resolve_dest() -> Result<PathBuf> {
    if let Some(p) = env::var_os("VAULTED_AGENT_UPDATE_DEST") {
        return Ok(PathBuf::from(p));
    }
    let exe =
        env::current_exe().map_err(|e| Error::Message(format!("update: current exe: {e}")))?;
    Ok(fs::canonicalize(&exe).unwrap_or(exe))
}

fn work_dir() -> Result<PathBuf> {
    let dir = env::temp_dir().join(format!("vaulted-agent-update-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| Error::Io {
        path: dir.clone(),
        source: e,
    })?;
    Ok(dir)
}

fn repo() -> String {
    env::var("VAULTED_AGENT_REPO").unwrap_or_else(|_| DEFAULT_REPO.into())
}

fn github() -> String {
    env::var("GITHUB").unwrap_or_else(|_| DEFAULT_GITHUB.into())
}

fn github_api() -> String {
    env::var("GITHUB_API").unwrap_or_else(|_| DEFAULT_GITHUB_API.into())
}

fn fetch_latest() -> Result<String> {
    need("curl")?;
    let url = format!("{}/repos/{}/releases/latest", github_api(), repo());
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            &url,
        ])
        .output()
        .map_err(|e| Error::Message(format!("update: curl: {e}")))?;
    if !out.status.success() {
        return Err(Error::Message(format!(
            "update: could not fetch latest release for {}\n  Create a GitHub release, or pin with: va update vX.Y.Z",
            repo()
        )));
    }
    let json = String::from_utf8_lossy(&out.stdout);
    parse_latest_tag(&json)
}

fn download_asset(tag: &str, work: &Path) -> Result<PathBuf> {
    need("curl")?;
    let names = asset_names(env::consts::OS, env::consts::ARCH)?;
    let mut last = Error::Message("update: no usable release asset".into());
    for name in names {
        match try_asset(tag, name, work) {
            Ok(p) => return Ok(p),
            Err(e) => {
                eprintln!("vaulted-agent: {e}");
                last = e;
            }
        }
    }
    Err(last)
}

fn try_asset(tag: &str, asset_name: &str, work: &Path) -> Result<PathBuf> {
    let tgz = work.join("bin.tgz");
    let url = format!(
        "{}/{}/releases/download/{}/{}.tar.gz",
        github(),
        repo(),
        tag,
        asset_name
    );
    eprintln!("trying release binary: {url}");
    let code = curl_to_file(&url, &tgz)?;
    match code.as_str() {
        "200" => {}
        "404" => {
            return Err(Error::Message(format!(
                "update: no {asset_name} asset in {tag}"
            )));
        }
        other => {
            return Err(Error::Message(format!(
                "update: failed to download release binary (HTTP {other}): {url}"
            )));
        }
    }
    let sum_url = format!("{url}.sha256");
    let sum_path = work.join("bin.tgz.sha256");
    if curl_to_file(&sum_url, &sum_path).ok().as_deref() == Some("200") {
        verify_sha256(&tgz, &sum_path)?;
        eprintln!("  checksum ok");
    } else {
        eprintln!("  warning: no .sha256 asset; installing without checksum verification");
    }
    let bin = extract_tarball(&tgz, work)?;
    // Same as install-remote.sh try_asset: a stem that will not start is the
    // wrong candidate, not a hard failure. Drop it and let the caller try
    // the next name (musl then gnu on Linux).
    if let Err(e) = prepare_bin(&bin) {
        let _ = fs::remove_file(&bin);
        return Err(e);
    }
    Ok(bin)
}

fn curl_to_file(url: &str, dest: &Path) -> Result<String> {
    let out = Command::new("curl")
        .args([
            "-sS",
            "-L",
            "-o",
            dest.to_str()
                .ok_or_else(|| Error::Message("update: dest path".into()))?,
            "-w",
            "%{http_code}",
            url,
        ])
        .output()
        .map_err(|e| Error::Message(format!("update: curl: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn verify_sha256(tgz: &Path, sum_path: &Path) -> Result<()> {
    let text = fs::read_to_string(sum_path).map_err(|e| Error::Io {
        path: sum_path.to_path_buf(),
        source: e,
    })?;
    let want = text
        .split_whitespace()
        .next()
        .ok_or_else(|| Error::Message("update: empty sha256 file".into()))?;
    let (prog, args): (&str, Vec<String>) = if command_exists("sha256sum") {
        ("sha256sum", vec![tgz.to_string_lossy().into_owned()])
    } else if command_exists("shasum") {
        (
            "shasum",
            vec![
                "-a".into(),
                "256".into(),
                tgz.to_string_lossy().into_owned(),
            ],
        )
    } else {
        return Err(Error::Message(
            "update: need shasum or sha256sum to verify release checksum".into(),
        ));
    };
    let out = Command::new(prog)
        .args(&args)
        .output()
        .map_err(|e| Error::Message(format!("update: {prog}: {e}")))?;
    let got = String::from_utf8_lossy(&out.stdout);
    let got = got.split_whitespace().next().unwrap_or("");
    if got != want {
        return Err(Error::Message(format!(
            "update: checksum verification failed (want {want}, got {got})"
        )));
    }
    Ok(())
}

fn extract_tarball(tgz: &Path, work: &Path) -> Result<PathBuf> {
    let status = Command::new("tar")
        .args(["-xzf", tgz.to_str().unwrap_or(""), "-C"])
        .arg(work)
        .status()
        .map_err(|e| Error::Message(format!("update: tar: {e}")))?;
    if !status.success() {
        return Err(Error::Message("update: tar extract failed".into()));
    }
    let named = work.join("vaulted-agent");
    if named.is_file() {
        return Ok(named);
    }
    // release.yml stages the binary under the per-target asset name.
    if let Ok(rd) = fs::read_dir(work) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension()
                .is_some_and(|e| e == "tgz" || e == "gz" || e == "sha256")
            {
                continue;
            }
            if p.is_file() {
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                if name.starts_with("vaulted-agent") {
                    let dest = work.join("vaulted-agent");
                    fs::rename(&p, &dest).map_err(|e| Error::Io {
                        path: dest.clone(),
                        source: e,
                    })?;
                    return Ok(dest);
                }
            }
        }
    }
    Err(Error::Message(
        "update: archive contained neither vaulted-agent nor a vaulted-agent-* binary".into(),
    ))
}

fn prepare_bin(bin: &Path) -> Result<()> {
    fs::set_permissions(bin, fs::Permissions::from_mode(0o755)).map_err(|e| Error::Io {
        path: bin.to_path_buf(),
        source: e,
    })?;
    let status = Command::new(bin)
        .arg("version")
        .status()
        .map_err(|e| Error::Message(format!("update: new binary will not start: {e}")))?;
    if !status.success() {
        return Err(Error::Message(format!(
            "update: {} does not run on this host; skipping it",
            bin.display()
        )));
    }
    Ok(())
}

fn dest_sibling(dest: &Path, suffix: &str) -> PathBuf {
    let name = dest
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vaulted-agent".into());
    dest.with_file_name(format!("{name}.{suffix}"))
}

fn install_over(src: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| Error::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
    }
    let staged = dest_sibling(dest, "new");
    if let Err(e) = fs::copy(src, &staged) {
        if e.kind() == ErrorKind::PermissionDenied {
            return sudo_install(src, dest);
        }
        return Err(Error::Io {
            path: staged,
            source: e,
        });
    }
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).ok();
    match fs::rename(&staged, dest) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            let _ = fs::remove_file(&staged);
            sudo_install(src, dest)
        }
        Err(e) => {
            // Running dest on some hosts refuses a direct overwrite. Move it
            // aside first, then put the new file on the original name.
            let bak = dest_sibling(dest, "old");
            if fs::rename(dest, &bak).is_ok() {
                match fs::rename(&staged, dest) {
                    Ok(()) => {
                        let _ = fs::remove_file(&bak);
                        Ok(())
                    }
                    Err(e2) => {
                        let _ = fs::rename(&bak, dest);
                        Err(Error::Io {
                            path: dest.to_path_buf(),
                            source: e2,
                        })
                    }
                }
            } else {
                let _ = fs::remove_file(&staged);
                Err(Error::Io {
                    path: dest.to_path_buf(),
                    source: e,
                })
            }
        }
    }
}

fn sudo_install(src: &Path, dest: &Path) -> Result<()> {
    eprintln!(
        "update: {} is not writable; retrying with sudo install",
        dest.display()
    );
    let status = Command::new("sudo")
        .args([
            "install",
            "-m",
            "0755",
            src.to_str().unwrap_or(""),
            dest.to_str().unwrap_or(""),
        ])
        .status()
        .map_err(|e| Error::Message(format!("update: sudo: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::Message(format!(
            "update: could not write {}\n  Re-run as the account that owns it, e.g.:\n    sudo va update",
            dest.display()
        )))
    }
}

fn need(cmd: &str) -> Result<()> {
    if command_exists(cmd) {
        Ok(())
    } else {
        Err(Error::Message(format!("update: need '{cmd}' on PATH")))
    }
}

fn command_exists(cmd: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {cmd} >/dev/null")])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_x86_64_prefers_musl() {
        assert_eq!(
            asset_names("linux", "x86_64").unwrap()[0],
            "vaulted-agent-x86_64-unknown-linux-musl"
        );
    }

    #[test]
    fn macos_arm_is_apple_darwin() {
        assert_eq!(
            asset_names("macos", "aarch64").unwrap(),
            vec!["vaulted-agent-aarch64-apple-darwin"]
        );
    }

    #[test]
    fn unknown_platform_fails_closed() {
        assert!(asset_names("windows", "x86_64").is_err());
    }

    #[test]
    fn normalize_adds_v_to_bare_semver() {
        assert_eq!(normalize_tag("0.4.20"), "v0.4.20");
        assert_eq!(normalize_tag("v0.4.20"), "v0.4.20");
        assert_eq!(normalize_tag(" latest "), "latest");
    }

    #[test]
    fn parse_latest_tag_reads_tag_name() {
        let json = r#"{"tag_name":"v0.4.20","draft":false}"#;
        assert_eq!(parse_latest_tag(json).unwrap(), "v0.4.20");
    }

    #[test]
    fn dest_sibling_keeps_the_basename() {
        let dest = Path::new("/usr/local/bin/vaulted-agent");
        assert_eq!(
            dest_sibling(dest, "new"),
            Path::new("/usr/local/bin/vaulted-agent.new")
        );
        assert_eq!(
            dest_sibling(dest, "old"),
            Path::new("/usr/local/bin/vaulted-agent.old")
        );
    }

    /// install-remote.sh is the hosted bootstrap: it cannot read a repo data
    /// file before the tarball exists. The stems still have to match. Drive
    /// `detect_assets` with a mocked `uname` and compare to `asset_names`.
    #[test]
    fn asset_names_match_install_remote_detect_assets() {
        let pairs = [
            ("linux", "x86_64", "Linux", "x86_64"),
            ("linux", "aarch64", "Linux", "aarch64"),
            ("linux", "aarch64", "Linux", "arm64"),
            ("macos", "x86_64", "Darwin", "x86_64"),
            ("macos", "aarch64", "Darwin", "arm64"),
        ];
        for (os, arch, uname_s, uname_m) in pairs {
            let rust = asset_names(os, arch).unwrap();
            let shell = shell_detect_assets(uname_s, uname_m);
            assert_eq!(
                rust, shell,
                "asset_names({os}, {arch}) vs detect_assets uname -s {uname_s} -m {uname_m}"
            );
        }
    }

    fn shell_detect_assets(uname_s: &str, uname_m: &str) -> Vec<String> {
        let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/install-remote.sh"));
        let start = src
            .find("detect_assets() {")
            .expect("detect_assets in install-remote.sh");
        let rest = &src[start..];
        let end = rest.find("\n}\n").expect("end of detect_assets");
        let func = &rest[..=end + 1];
        let script = format!(
            "{func}\nuname() {{ case \"$1\" in -s) printf '%s\\n' '{uname_s}';; -m) printf '%s\\n' '{uname_m}';; esac; }}\ndetect_assets\n"
        );
        let out = Command::new("bash")
            .arg("-c")
            .arg(&script)
            .output()
            .expect("run detect_assets");
        assert!(
            out.status.success(),
            "detect_assets {uname_s}:{uname_m}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .map(|s| s.to_string())
            .collect()
    }
}
