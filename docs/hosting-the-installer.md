# Hosting the bootstrap installer

Maintainer procedure for refreshing the script served at
`https://vaultedagent.com/install.sh`, the target of the `curl … | bash`
one-liner in the README. (`https://stephens.page/vaulted-agent/install.sh`
301-redirects there.)

## The contract

| | |
|---|---|
| file in this repo | `install-remote.sh` |
| served as | `https://vaultedagent.com/install.sh` |
| served mode | static file, no execution on the host |

The repo ships **two** installers and hosting the wrong one breaks every install:

- `install-remote.sh` (~9 KB) is the thin bootstrap that belongs at this URL. It
  resolves a version, tries release binary assets best-first, and falls back to
  a source build.
- `install.sh` (~42 KB) is the real installer. The bootstrap downloads it inside
  the tagged source tarball and runs it as root. It is never served directly.

The served filename is `install.sh` while its content is `install-remote.sh`.
That mismatch is intentional (the one-liner reads better) and is the easy
mistake to make here.

## If the GitHub repo is renamed

Update `REPO` in `install-remote.sh` and redeploy. GitHub 301-redirects the old
paths, so downloads keep working and the breakage hides: the tarball's top
directory is named after the repo's **current** name, so anything matching that
directory by name stops matching. That is exactly what broke every remote
install when `vaulted-agent-launcher` became `vaulted-agent` - the bootstrap
downloaded fine and then died with "unexpected layout". The script now finds
the source tree by looking for the directory that contains `install.sh`, and
`tests/install_remote_layout.rs` holds that line.

## Order of operations

`install-remote.sh` pins `DEFAULT_VERSION`, and that pin must never point at a
tag that does not exist yet. When it does, an unpinned `curl … | bash` fails
outright: both asset candidates 404, the source-archive fetch for the tag 404s,
and the script calls `die`. That is strictly worse than shipping nothing.

So, per release:

1. Bump `version` in `Cargo.toml` and `DEFAULT_VERSION` in `install-remote.sh`
   to the same `vX.Y.Z`. Merge.
2. Tag `vX.Y.Z` and push the tag. `release.yml` builds the assets and publishes
   the GitHub release.
3. Confirm the release assets exist (below).
4. **Then** refresh the hosted script.
5. Update the two `Latest: vX.Y.Z` links in `README.md`.

Steps 2 and 4 are the ones that must not be reordered.

## Precondition check

Both must return `200` before you deploy anything:

```bash
VERSION=v0.4.1   # the release you are publishing
base=https://github.com/JacobStephens2/vaulted-agent
curl -sIL -o /dev/null -w 'musl asset: %{http_code}\n' \
  "$base/releases/download/$VERSION/vaulted-agent-x86_64-unknown-linux-musl.tar.gz"
curl -sIL -o /dev/null -w 'source tar: %{http_code}\n' \
  "$base/archive/refs/tags/$VERSION.tar.gz"
```

A 404 on either means the release is not cut. Stop. Do not hand-edit
`DEFAULT_VERSION` to route around it - that value and the published tag are
meant to move together, and decoupling them is how the pin silently starts
lying.

## Deploy

Find what is actually served rather than assuming a docroot, and prove it before
touching it:

```bash
grep -rn 'vaulted-agent' /etc/nginx /etc/httpd /etc/apache2 2>/dev/null
find /var/www -path '*vaulted-agent*' 2>/dev/null

curl -fsSL https://vaultedagent.com/install.sh | sha256sum
sha256sum /path/you/found        # must match; if not, wrong file or a cache in front
```

Back up, then verify into a temp file and install from there. Never pipe a
download straight over the live path - this file is piped into `bash` as root on
other people's machines, so serving an unverified script is the one unrecoverable
mistake in this procedure.

```bash
cp -a /path/to/install.sh /path/to/install.sh.bak

tmp=$(mktemp)
curl -fsSL -o "$tmp" \
  https://raw.githubusercontent.com/JacobStephens2/vaulted-agent/main/install-remote.sh

bash -n "$tmp"                              # syntax
grep -n 'DEFAULT_VERSION=' "$tmp"           # must equal the release you just cut
grep -q 'detect_assets' "$tmp" && echo ok   # proves it is the bootstrap, not install.sh
sha256sum "$tmp"                            # record this; you verify it again after deploy

install -m 0644 "$tmp" /path/to/install.sh  # match the previous mode if it differed
# Live path today: /var/www/stephens.page/vaulted-agent/install.sh
# (DocumentRoot for vaultedagent.com)
```

## Verify after deploy

Check the live URL, not the file on disk. A stale CDN or proxy cache is silent
and would leave every new install broken:

```bash
curl -fsSL https://vaultedagent.com/install.sh | sha256sum   # matches $tmp
curl -fsSL https://vaultedagent.com/install.sh | wc -c
```

Then smoke-test the asset the script would actually select:

```bash
cd "$(mktemp -d)"
curl -fsSL -O "https://github.com/JacobStephens2/vaulted-agent/releases/download/$VERSION/vaulted-agent-x86_64-unknown-linux-musl.tar.gz"
tar -xzf vaulted-agent-x86_64-unknown-linux-musl.tar.gz
mv vaulted-agent-x86_64-unknown-linux-musl vaulted-agent    # required, see below
chmod +x vaulted-agent
./vaulted-agent version
file vaulted-agent                                  # expect: static-pie linked
readelf -V vaulted-agent | grep GLIBC_ || echo "no glibc version deps - correct"
```

The rename is required, not cosmetic. The launcher dispatches on `argv[0]` and
refuses any name that is not `vaulted-agent`, `va`, or a `*-conductor` link.
Run the asset under its download name and it fails with a symlink error that
reads like a corrupt binary but is not.

The `readelf` check is the one that matters most. A Linux asset carrying any
`GLIBC_` version reference will not load on distros older than the build runner,
which is the failure [ADR 0001](adr/0001-static-musl-linux-releases.md) exists to
prevent. `release.yml` guards this at build time; this is the second look, after
publication.

## Rollback

```bash
cp -a /path/to/install.sh.bak /path/to/install.sh
```

Confirm via the live URL. Rollback is safe at any point - an older bootstrap
still installs older pinned versions correctly, and `detect_assets` keeps the
`-gnu` asset names as fallbacks so pins through v0.4.0 continue to resolve.
