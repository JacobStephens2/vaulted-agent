//! Issue #184: vault rejection names the Manager token's actual source.

mod common;

use common::CliSeam;
use std::fs;
use std::process::{Command, Output};

const TOKEN: &str = "synthetic-expired-manager-token";
const UUID: &str = "bdc77275-1234-5678-9012-123456789abc";
const INVALID_CLIENT: &str = r#"Error:
   0: Received error message from server: [400 Bad Request] {"error":"invalid_client"}

Location:
   crates/bws/src/main.rs:107

Backtrace omitted. Run with RUST_BACKTRACE=1 environment variable to display it.
Run with RUST_BACKTRACE=full to include source snippets.
"#;
const COMMANDS: &[&[&str]] = &[
    &["probe"],
    &["refresh"],
    &["secrets", "validate"],
    &["secrets", "validate", "probe"],
];

fn fixture(backend: &str, error: &str) -> CliSeam {
    let seam = CliSeam::new();
    fs::write(
        seam.config_dir.join("defaults.conf"),
        format!("auth_mode = file\ndefault_backend = {backend}\n"),
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/probe.conf"),
        format!("backend = {backend}\nmanifest = test.refs\ncommand = agent\n"),
    )
    .unwrap();
    let reference = if backend == "bitwarden" {
        UUID
    } else {
        "op://Vault/item/credential"
    };
    fs::write(
        seam.config_dir.join("manifests/test.refs"),
        format!("API_KEY={reference}\n"),
    )
    .unwrap();
    seam.install_stub_agent("agent");
    seam.write_executable(
        if backend == "bitwarden" { "bws" } else { "op" },
        &format!("#!/bin/sh\ncat >&2 <<'ERROR'\n{error}\nERROR\nexit 1\n"),
    );
    seam
}

fn command(seam: &CliSeam, args: &[&str]) -> Command {
    let mut cmd = seam.vaulted_agent();
    cmd.args(args)
        .env_remove("VAULTED_AGENT_PROMPT_AUTH")
        .env("VAULTED_AGENT_AUTH_MODE", "file")
        .env("VAULTED_AGENT_NO_REEXEC", "1");
    cmd
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_rejected(seam: &CliSeam, out: &Output, key: &str, detail: &str) -> String {
    let text = combined(out);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("rejected by the vault"), "{text}");
    assert!(text.contains(key), "{text}");
    assert!(text.contains(detail), "{text}");
    assert!(!text.contains("Location:"), "{text}");
    assert!(!text.contains("RUST_BACKTRACE"), "{text}");
    assert!(!text.contains(TOKEN), "token leaked: {text}");
    assert!(!seam.work_dir.join("agent.record").exists(), "{text}");
    text
}

#[test]
fn rejected_bitwarden_file_names_its_path_and_rotation_on_every_command() {
    let seam = fixture("bitwarden", INVALID_CLIENT);
    let path = seam.config_dir.join("bws.env");
    let body = format!("BWS_ACCESS_TOKEN={TOKEN}\n");
    fs::write(&path, &body).unwrap();
    for args in COMMANDS {
        let out = command(&seam, args).output().unwrap();
        let text = assert_rejected(&seam, &out, "BWS_ACCESS_TOKEN", "invalid_client");
        assert!(text.contains(&path.display().to_string()), "{text}");
        assert!(
            text.contains("printf %s \"$TOKEN\" | sudo vaulted-agent setup bitwarden --set-token"),
            "{text}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), body);
    }
}

#[test]
fn rejected_export_wins_over_file_and_prompt_on_every_command() {
    let seam = fixture("bitwarden", INVALID_CLIENT);
    let path = seam.config_dir.join("bws.env");
    fs::write(&path, "BWS_ACCESS_TOKEN=other-synthetic-token\n").unwrap();
    for args in COMMANDS {
        let out = command(&seam, args)
            .env("BWS_ACCESS_TOKEN", TOKEN)
            .env("VAULTED_AGENT_PROMPT_AUTH", "1")
            .output()
            .unwrap();
        let text = assert_rejected(&seam, &out, "exported BWS_ACCESS_TOKEN", "invalid_client");
        assert!(text.contains("unset BWS_ACCESS_TOKEN"), "{text}");
        assert!(text.contains("export a working token"), "{text}");
        assert!(!text.contains(&path.display().to_string()), "{text}");
        assert!(!text.contains("--set-token"), "{text}");
    }
}

/// Give the real CLI a controlling terminal and paste only once echo is off.
/// Bound the wait and reap this child even on failure; no interactive runner
/// or global process lookup is needed in headless CI (Linux and macOS).
fn pasted(mut base: Command) -> Output {
    base.env("TEST_PASTED_TOKEN", TOKEN);
    let mut cmd = Command::new("python3");
    cmd.args([
        "-c",
        r#"
import errno, os, pty, select, signal, sys, termios, time
token = os.environ.pop('TEST_PASTED_TOKEN')
pid, master = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])
output = bytearray()
pasted = False
reaped = False
try:
    deadline = time.monotonic() + 20
    while True:
        if time.monotonic() > deadline:
            raise RuntimeError('timed out waiting for token prompt or CLI exit')
        if (not pasted and b'(hidden, not written to disk):' in output
                and not termios.tcgetattr(master)[3] & termios.ECHO):
            os.write(master, token.encode() + b'\n')
            pasted = True
        if not select.select([master], [], [], 0.01)[0]:
            continue
        try:
            chunk = os.read(master, 65536)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            break
        if not chunk:
            break
        output.extend(chunk)
    _, status = os.waitpid(pid, 0)
    reaped = True
    sys.stdout.buffer.write(output)
    sys.exit(os.waitstatus_to_exitcode(status))
finally:
    os.close(master)
    if not reaped:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
"#,
    ])
    .arg(base.get_program())
    .args(base.get_args());
    for (key, value) in base.get_envs() {
        match value {
            Some(value) => cmd.env(key, value),
            None => cmd.env_remove(key),
        };
    }
    if let Some(dir) = base.get_current_dir() {
        cmd.current_dir(dir);
    }
    cmd.output().unwrap()
}

#[test]
fn rejected_prompt_paste_is_named_without_retrying_or_storing() {
    for force_prompt in [false, true] {
        let seam = fixture("bitwarden", INVALID_CLIENT);
        // Without a file, file mode falls back to a prompt. Both that route
        // and an explicit prompt must report the paste as the actual source.
        for args in COMMANDS {
            let mut cmd = command(&seam, args);
            if force_prompt {
                cmd.env("VAULTED_AGENT_PROMPT_AUTH", "1");
            }
            let out = pasted(cmd);
            let text = assert_rejected(&seam, &out, "pasted BWS_ACCESS_TOKEN", "invalid_client");
            assert!(text.contains("paste a working token"), "{text}");
            assert!(!text.contains("--set-token"), "{text}");
            assert!(!seam.config_dir.join("bws.env").exists(), "{text}");
        }
    }
}

#[test]
fn http_auth_rejections_name_the_token_for_both_vaults() {
    for (backend, key, errors) in [
        (
            "bitwarden",
            "BWS_ACCESS_TOKEN",
            &[
                "Error: Received error message from server: [401 Unauthorized]",
                "Error: HTTP status code: 401",
                "Unauthorized",
            ][..],
        ),
        (
            "onepassword",
            "OP_SERVICE_ACCOUNT_TOKEN",
            &["[ERROR] error initializing client: Authentication: (401), Server: (Unauthorized)"][..],
        ),
    ] {
        for error in errors {
            let seam = fixture(backend, error);
            for args in COMMANDS {
                let out = command(&seam, args).env(key, TOKEN).output().unwrap();
                let text = assert_rejected(&seam, &out, key, error);
                assert!(text.contains(&format!("unset {key}")), "{text}");
            }
        }
    }
}

#[test]
fn other_backend_failures_keep_their_original_stderr() {
    for (backend, key) in [
        ("bitwarden", "BWS_ACCESS_TOKEN"),
        ("onepassword", "OP_SERVICE_ACCOUNT_TOKEN"),
    ] {
        for error in [
            "Error: could not connect to https://vault.example/401: connection refused\n\nLocation:\n   source.rs:401\nRUST_BACKTRACE=1",
            "[ERROR] could not find item Unauthorized in vault v1",
            "Error: [403 Forbidden] insufficient permissions",
            "Error: unexpected status code: 4010",
            "Error: could not resolve reference invalid_client",
        ] {
            let seam = fixture(backend, error);
            for args in COMMANDS {
                let out = command(&seam, args).env(key, TOKEN).output().unwrap();
                let text = combined(&out);
                assert!(!out.status.success(), "{text}");
                assert!(text.contains(error), "{text}");
                assert!(!text.contains("rejected by the vault"), "{text}");
            }
        }
    }
}

#[test]
fn onepassword_rejection_mid_refresh_aborts_before_writing() {
    let seam = fixture("onepassword", "unused");
    seam.write_executable(
        "op",
        r#"#!/bin/sh
case "$1 $2 $3" in
  'item list --format')
    echo '[{"id":"good","title":"good","vault":{"id":"v1","name":"Vault"}},
           {"id":"revoked","title":"revoked","vault":{"id":"v1","name":"Vault"}}]'
    ;;
  'item get good')
    echo '{"id":"good","fields":[{"id":"f1","label":"credential","type":"CONCEALED","value":"synthetic-value"}]}'
    ;;
  *)
    echo '[ERROR] error initializing client: Authentication: (401), Server: (Unauthorized)' >&2
    exit 1
    ;;
esac
"#,
    );
    let path = seam.config_dir.join("manifests/test.refs");
    let before = fs::read(&path).unwrap();
    let out = command(&seam, &["refresh", "--all", "--prune"])
        .env("OP_SERVICE_ACCOUNT_TOKEN", TOKEN)
        .output()
        .unwrap();
    assert_rejected(&seam, &out, "exported OP_SERVICE_ACCOUNT_TOKEN", "(401)");
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn setup_still_refuses_the_rejected_file_without_claiming_a_write() {
    let seam = fixture("bitwarden", INVALID_CLIENT);
    let path = seam.config_dir.join("bws.env");
    let body = format!("BWS_ACCESS_TOKEN={TOKEN}\n");
    fs::write(&path, &body).unwrap();
    let out = command(&seam, &["setup", "bitwarden"]).output().unwrap();
    let text = assert_rejected(&seam, &out, "BWS_ACCESS_TOKEN", "invalid_client");
    assert!(text.contains("nothing written"), "{text}");
    assert!(!text.contains("wrote "), "{text}");
    assert_eq!(fs::read_to_string(path).unwrap(), body);
}
