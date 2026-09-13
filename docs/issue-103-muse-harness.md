# Muse Harness — issue #103

Design discussion for [issue #103](https://github.com/JacobStephens2/vaulted-agent/issues/103).
Shared understanding confirmed by Jacob on 2026-09-13. Implemented using the
existing Harness mechanism.

## Settled requirements

- `va muse` launches Muse Code as a normal Harness, following the existing
  support model used by `va claude` and the other agent Harnesses.
- Secret delivery uses a fresh launch through `va`. Adding credentials to an
  already-running session is outside this issue.
- The default command is bare `muse`, with `workdir = caller` and labels off.
  Muse owns its permission settings; the Launcher adds no permission flags.
- Arguments following the Harness name pass through unchanged. In particular,
  `va muse --yolo` injects the selected Manifest and launches Muse in its native
  yolo mode. Native subcommands such as `va muse resume --last` also pass through.
- The existing Harness, Manifest, Secret value, Manager token, and Child
  environment concepts apply; no new domain term is needed so far.

## Integration scope implied by ordinary Harness support

- Ship a Muse sample profile and detect the installed `muse` executable during
  installation. Follow existing preservation of user profiles and installer
  defaults: plainfile plus `empty.env`, caller directory, and detected binary
  directory. Existing installer vault wiring applies to the starter profile.
- Use the generic Harness support for listing, picking, Manifest overrides,
  aliases, Backend resolution, Manager token removal, and Service-user re-exec.
- Include Muse in Doctor's existing agent-specific working-directory checks.
- Document the launch and argument examples alongside the other Harnesses.
- Preserve the distinction between installer vault wiring and `va setup`:
  the latter currently creates configuration and tells the operator how to
  point a Harness at the Manifest; it does not automatically rewire profiles.

## Acceptance and verification

- CLI coverage verifies injection of a synthetic Secret value, absence of
  Manager tokens, caller directory, and exact forwarding of `--yolo` and
  native resume arguments through a Muse executable stub.
- Installer coverage verifies discovery, starter configuration, and preservation
  of an existing Muse profile. Doctor coverage checks Muse's working-directory
  behavior.
- A bounded runtime probe through the built Launcher and shipped Muse profile
  passed on macOS with Muse 1.1.1. A temporary Manifest provided only the
  non-secret `VA_MUSE_PROBE=sentinel-103`; `muse exec --yolo` ran a shell check.
  The actual `tool.result` event reported exit code 0 and
  `VA_MUSE_INHERITANCE_OK`, proving delivery to Muse's shell tool. This did not
  exercise a real third-party credential or authenticated external action.

Local inspection of Muse 1.1.1 confirms bare `muse`, `--yolo`, and native
`resume` support. Its login help also states that `META_API_KEY` takes precedence
over account login; normal Manifest selection continues to determine what is
injected. No Muse-specific authentication configuration is required by this
design.

The current decisions use the established Launcher architecture and do not yet
justify a separate ADR.
