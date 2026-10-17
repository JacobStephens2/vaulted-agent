//! Selected Backend prerequisites at the setup CLI boundary (issue #172).
mod common;

use common::CliSeam;
use std::fs::{self, File};
use std::io::{Seek, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Output, Stdio};

const BACKENDS: [(&str, &str); 4] = [
    ("bitwarden", "bws"),
    ("onepassword", "op"),
    ("pass", "pass"),
    ("sops", "sops"),
];

fn seam() -> CliSeam {
    let s = CliSeam::new();
    symlink("/usr/bin/id", s.path_dir.join("id")).unwrap();
    fs::write(s.config_dir.join("defaults.conf"), "auth_mode = file\n").unwrap();
    s.write_harness(
        "agent",
        "backend = plainfile\nmanifest = empty.env\ncommand = agent\n",
    );
    fs::write(s.config_dir.join("manifests/empty.env"), "").unwrap();
    s
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn missing_or_non_executable_cli_fails_before_token_input() {
    for (backend, tool) in BACKENDS {
        for non_executable in [false, true] {
            let s = seam();
            if non_executable {
                let p = s.path_dir.join(tool);
                fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
                fs::set_permissions(p, fs::Permissions::from_mode(0o644)).unwrap();
            }
            let mut variants = vec![vec!["setup", backend]];
            if matches!(backend, "bitwarden" | "onepassword") {
                variants.push(vec!["setup", backend, "--set-token"]);
            }
            for args in variants {
                let input = s.root.join("input");
                File::create(&input)
                    .unwrap()
                    .write_all(b"fake-token\n")
                    .unwrap();
                let mut input = File::open(input).unwrap();
                let out = s
                    .vaulted_agent()
                    .env("PATH", &s.path_dir)
                    .args(args)
                    .stdin(Stdio::from(input.try_clone().unwrap()))
                    .output()
                    .unwrap();
                let all = text(&out);
                assert!(!out.status.success(), "{backend}: {all}");
                assert!(all.contains("Vault setup incomplete"), "{all}");
                assert!(all.contains(backend) && all.contains(tool), "{all}");
                assert!(
                    all.contains("setup execution")
                        && all.contains("PATH")
                        && all.contains("https://"),
                    "{all}"
                );
                assert!(
                    !all.contains("input hidden") && !all.contains("hidden, not written"),
                    "{all}"
                );
                assert_eq!(
                    input.stream_position().unwrap(),
                    0,
                    "token input was read: {all}"
                );
                assert!(!s.config_dir.join("bws.env").exists());
                assert!(!s.config_dir.join("op.env").exists());
            }
        }
    }
}

#[test]
fn wire_only_warns_but_finishes_wiring_without_vault_calls() {
    for (backend, tool) in BACKENDS {
        let s = seam();
        for available in [false, true] {
            if available {
                s.write_executable(
                    tool,
                    "#!/bin/sh\necho 'unexpected vault call' >&2\nexit 99\n",
                );
            }
            let out = s
                .vaulted_agent()
                .env("PATH", &s.path_dir)
                .args(["setup", backend, "--wire-only"])
                .output()
                .unwrap();
            let all = text(&out);
            assert!(out.status.success(), "{all}");
            assert_eq!(all.contains("Vault setup incomplete"), !available, "{all}");
            assert!(!all.contains("unexpected vault call"), "{all}");
            assert!(fs::read_to_string(s.config_dir.join("defaults.conf"))
                .unwrap()
                .contains(&format!("default_backend = {backend}")));
            if backend != "sops" {
                assert!(
                    fs::read_to_string(s.config_dir.join("harnesses.d/agent.conf"))
                        .unwrap()
                        .contains(&format!("backend = {backend}"))
                );
            }
        }
    }
}

#[test]
fn available_selected_tool_preserves_setup_without_unrelated_tools() {
    for (backend, tool) in BACKENDS {
        let s = seam();
        let body = match backend {
            "bitwarden" => "#!/bin/sh\n[ -n \"$BWS_ACCESS_TOKEN\" ] || exit 9\necho '[]'\n",
            "onepassword" => {
                "#!/bin/sh\n[ -n \"$OP_SERVICE_ACCOUNT_TOKEN\" ] || exit 9\necho '{}'\n"
            }
            _ => "#!/bin/sh\necho 'unexpected vault call' >&2\nexit 99\n",
        };
        s.write_executable(tool, body);
        let mut cmd = s.vaulted_agent();
        cmd.env("PATH", &s.path_dir).args(["setup", backend]);
        let mut token = tempfile::tempfile().unwrap();
        token.write_all(b"fake-integration-token\n").unwrap();
        token.rewind().unwrap();
        if matches!(backend, "bitwarden" | "onepassword") {
            cmd.arg("--set-token").stdin(Stdio::from(token));
        }
        let out = cmd.output().unwrap();
        let all = text(&out);
        assert!(out.status.success(), "{all}");
        assert!(
            !all.contains("Vault setup incomplete") && !all.contains("unexpected vault call"),
            "{all}"
        );
        let key = match backend {
            "bitwarden" => Some(("bws.env", "BWS_ACCESS_TOKEN")),
            "onepassword" => Some(("op.env", "OP_SERVICE_ACCOUNT_TOKEN")),
            _ => None,
        };
        if let Some((file, key)) = key {
            assert_eq!(
                fs::read_to_string(s.config_dir.join(file)).unwrap(),
                format!("{key}=fake-integration-token\n")
            );
        }
    }
}

#[test]
fn setup_checks_the_launch_accounts_sudo_path_and_names_the_context() {
    for (setup_has_tool, launch_has_tool) in [(true, false), (false, true), (true, true)] {
        let s = seam();
        fs::write(
            s.config_dir.join("defaults.conf"),
            "service_user = vault-service\nauth_mode = file\n",
        )
        .unwrap();
        let launch_bin = s.root.join("launch-bin");
        fs::create_dir(&launch_bin).unwrap();
        if setup_has_tool {
            s.write_executable("pass", "#!/bin/sh\nexit 99\n");
        }
        if launch_has_tool {
            let path = launch_bin.join("pass");
            fs::write(&path, "#!/bin/sh\nexit 99\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        s.write_executable("sudo", &format!(
            "#!/bin/sh\n[ \"$1 $2 $3 $4\" = '-n -u vault-service --' ] || exit 98\n[ -z \"${{BWS_ACCESS_TOKEN-}}${{OP_SERVICE_ACCOUNT_TOKEN-}}\" ] || exit 97\nshift 4\nPATH='{}' exec \"$@\"\n", launch_bin.display()));
        let out = s
            .vaulted_agent()
            .env("PATH", &s.path_dir)
            .env("VAULTED_AGENT_NO_REEXEC", "1")
            .env("BWS_ACCESS_TOKEN", "fake-ambient-token")
            .args(["setup", "pass"])
            .output()
            .unwrap();
        let all = text(&out);
        assert_eq!(
            out.status.success(),
            setup_has_tool && launch_has_tool,
            "{all}"
        );
        assert_eq!(
            all.contains("Unavailable in: launch account"),
            !launch_has_tool,
            "{all}"
        );
        assert_eq!(
            all.contains("setup execution account"),
            !setup_has_tool,
            "{all}"
        );
    }
}
