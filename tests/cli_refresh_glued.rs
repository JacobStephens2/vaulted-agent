//! `va refresh` splits Bitwarden refs that bash 0.3.0 glued onto one line.

mod common;

use common::CliSeam;
use std::fs;

#[test]
fn refresh_splits_glued_name_refs_even_when_every_secret_is_already_named() {
    // The substring `name:META_AI_API_KEY` sits inside the glued blob, so
    // merge used to treat every secret as mapped and write nothing.
    let seam = CliSeam::new();
    let map = seam.write_secrets_json(
        "vault.json",
        r#"{"OPENAI_API_KEY": "a", "META_AI_API_KEY": "b", "FIREWORKS_API_KEY": "c"}"#,
    );
    seam.install_fake_bws(&map);
    fs::write(
        seam.config_dir.join("manifests/bws.refs"),
        "OPENAI_API_KEY=name:OPENAI_API_KEY\n\
         META_AI_API_KEY=name:META_AI_API_KEYFIREWORKS_API_KEY=name:FIREWORKS_API_KEY\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("harnesses.d/grok.conf"),
        "backend = bitwarden\nmanifest = bws.refs\ncommand = true\n",
    )
    .unwrap();
    fs::write(
        seam.config_dir.join("bws.env"),
        "BWS_ACCESS_TOKEN=test-token\n",
    )
    .unwrap();

    let out = seam
        .vaulted_agent()
        .args(["refresh", "--all"])
        .env("VAULTED_AGENT_AUTH_MODE", "file")
        .env("VAULTED_AGENT_NO_REEXEC", "1")
        .output()
        .expect("run refresh");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(text.contains("glued onto one line"), "{text}");

    let body = fs::read_to_string(seam.config_dir.join("manifests/bws.refs")).unwrap();
    let mappings: Vec<&str> = body
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && t.contains('=')
        })
        .collect();
    assert_eq!(
        mappings,
        vec![
            "OPENAI_API_KEY=name:OPENAI_API_KEY",
            "META_AI_API_KEY=name:META_AI_API_KEY",
            "FIREWORKS_API_KEY=name:FIREWORKS_API_KEY",
        ],
        "{body}"
    );
}
