# ADR 0001 — Linux release assets are static musl builds

**Status:** accepted (v0.4.1)

## Decision

The published Linux binaries target `*-unknown-linux-musl` and link statically.
The `*-unknown-linux-gnu` targets are not published.

## Why

Release assets were built on `ubuntu-latest`. When that image moved to 24.04
(glibc 2.39), the resulting binary stopped loading on older distros:

```
va: /lib64/libc.so.6: version `GLIBC_2.39' not found (required by va)
```

Nothing in this codebase calls anything from glibc 2.39. The dependency comes
from the Rust standard library's process-spawn path, which uses `pidfd_spawnp`
and `pidfd_getpid` when they exist *at build time*. Both are weak *symbols*,
but the version reference the linker records is not marked `VER_FLG_WEAK`:

```
required from libc.so.6:
  ...
  0x069691b9 0x00 09 GLIBC_2.39     <- flags 0x00, not weak
```

`ld.so` resolves version dependencies before any symbol is looked up, so it
rejects the image outright. There is no runtime fallback and no way to satisfy
it on the target: glibc is the distro's core C library, not something you
upgrade under a supported RHEL/Debian install.

glibc is backward compatible, never forward compatible. Build on new, run on
old is broken by construction, and which libc the *build* machine had is not a
property anyone reviewing this repo would think to check. Affected hosts
include RHEL/Rocky/Alma 9 and Amazon Linux 2023 (2.34), Ubuntu 22.04 (2.35),
and Debian 12 (2.36) — i.e. most stable server distros in service.

## Alternatives rejected

- **Build the gnu target in an older container** (or via `cross`, or
  `cargo-zigbuild --target x86_64-unknown-linux-gnu.2.17`). Works, and keeps a
  glibc-native artifact. Rejected because it only moves the floor rather than
  removing it: the artifact still has one, and it silently tracks whatever base
  image CI happens to use. This failure was not noticed until an install broke
  on a live host.
- **Publish both musl and gnu.** Doubles the matrix and puts the trap back in
  the installer's selection logic for no benefit this binary can use.

## What makes musl safe here

Static musl's real limitation is NSS: `getpwnam`/`getgrnam` cannot load
`nss_sssd`/`nss_ldap` modules, so directory-backed users do not resolve. This
binary never does user or group lookup in-process — `gid_for_user` (`src/auth.rs`)
shells out to `id`, and the service-user hop shells out to `sudo`. Those child
processes are ordinary dynamically-linked distro binaries and resolve directory
users normally. If in-process user lookup is ever added, this ADR has to be
revisited before it ships.

No `musl-gcc` / `musl-tools` step is needed: rustc links these targets
self-contained, with bundled crt objects and `libc.a`.

## Guard

`release.yml` fails the build if a Linux asset has an `INTERP` segment or any
`GLIBC_` version reference. Without it, this regresses invisibly — the binary
runs fine on the runner that built it and on the maintainer's machine.

`install-remote.sh` runs `<asset> version` before installing and falls through
to the next candidate (or a source build) if it will not start, so a bad asset
fails at install time instead of at first launch.
