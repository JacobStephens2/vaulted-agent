//! Stamp the build with its git description.
//!
//! A launcher that mediates credentials is one you patch in place and rebuild
//! on the box more often than most software, so "which build is installed" has
//! to be answerable from the binary. Without this a locally patched build and
//! the released one both report the same version string and are otherwise
//! indistinguishable.
//!
//! Absent or unavailable git is normal, not an error: release tarballs and
//! vendored builds have no repository, and those simply report the crate
//! version alone.

use std::process::Command;

fn main() {
    // Rebuild when HEAD moves, so the stamp does not go stale mid-session.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    let desc = Command::new("git")
        .args(["describe", "--always", "--dirty", "--tags"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_default();

    println!("cargo:rustc-env=VA_BUILD_DESC={desc}");
}
