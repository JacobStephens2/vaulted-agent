#!/usr/bin/env bash
# Behavior tests for the hosted bootstrap installer (install-remote.sh, served
# as https://vaultedagent.com/install.sh).
#
#   bash tests/install_remote_bootstrap.sh            # the file in this tree
#   INSTALL_SH=staged/install.sh bash tests/install_remote_bootstrap.sh
#
# The pinned version and digest come from the file under test. One test
# downloads that tag's published archive and checks it against the recorded
# digest; INSTALL_REMOTE_TEST_OFFLINE=1 skips it (CI, where the tag may not
# exist yet). scripts/release.sh deploy-site runs the whole suite online
# against the staged file before it is hosted.
set -euo pipefail

INSTALL_SH="${INSTALL_SH:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/install-remote.sh}"
PIN="$(sed -n 's/^DEFAULT_VERSION="\(v[0-9.]*\)".*/\1/p' "$INSTALL_SH" | head -n 1)"
[[ -n "$PIN" ]] || { printf 'no DEFAULT_VERSION in %s\n' "$INSTALL_SH" >&2; exit 2; }
ORIG_PATH="$PATH"
LAST_STATUS=0
FAILS=0

RUN_TMP="" STUB_BIN="" SPY="" TAR_SPY="" STDOUT="" STDERR=""
FAKE_ARCHIVE="" FAKE_ARCHIVE_STATUS="" FAKE_ASSET_STATUS="" FAKE_ASSET_BODY=""
FAKE_SUM_STATUS="" FAKE_SUM_BODY="" FAKE_LATEST_BODY="" EXPECTED_ARCHIVE_SHA=""

assert() {
  local msg="$1"
  shift
  if ! "$@"; then
    printf 'assertion failed: %s\n' "$msg" >&2
    printf 'status=%s\n' "$LAST_STATUS" >&2
    printf 'stderr:\n' >&2
    cat "$STDERR" >&2 || true
    printf 'stdout:\n' >&2
    cat "$STDOUT" >&2 || true
    printf 'spy:\n' >&2
    cat "$SPY" >&2 || true
    printf 'tar:\n' >&2
    cat "$TAR_SPY" >&2 || true
    exit 1
  fi
}

install_stubs() {
  cat >"$STUB_BIN/curl" <<'EOF'
#!/bin/bash
set -euo pipefail
out=""
url=""
fail=0
print_code=0
args=("$@")
i=0
while (( i < ${#args[@]} )); do
  a="${args[$i]}"
  case "$a" in
    -o)
      i=$((i + 1))
      out="${args[$i]}"
      ;;
    -w)
      i=$((i + 1))
      print_code=1
      ;;
    -H)
      i=$((i + 1))
      ;;
    http://*|https://*)
      url="$a"
      ;;
    -*)
      if [[ "$a" == *f* ]]; then fail=1; fi
      ;;
    *)
      url="$a"
      ;;
  esac
  i=$((i + 1))
done

respond() {
  local code="$1" body="${2:-}"
  if (( print_code )); then
    if [[ "$code" == "200" && -n "$body" ]]; then
      cp "$body" "$out"
    elif [[ -n "$out" ]]; then
      : >"$out"
    fi
    printf '%s' "$code"
    exit 0
  fi
  if (( fail )) && [[ "$code" != "200" ]]; then
    exit 22
  fi
  if [[ -n "$out" ]]; then
    if [[ -n "$body" ]]; then
      cp "$body" "$out"
    else
      : >"$out"
    fi
  elif [[ -n "$body" ]]; then
    cat "$body"
  fi
  exit 0
}

case "$url" in
  *.sha256)
    respond "${FAKE_SUM_STATUS:-404}" "${FAKE_SUM_BODY:-}"
    ;;
  */releases/download/*.tar.gz)
    respond "${FAKE_ASSET_STATUS:-404}" "${FAKE_ASSET_BODY:-}"
    ;;
  */releases/latest)
    if [[ -z "${FAKE_LATEST_BODY:-}" ]]; then
      printf 'curl stub: latest release was not stubbed\n' >&2
      exit 1
    fi
    respond 200 "$FAKE_LATEST_BODY"
    ;;
  *.tar.gz)
    respond "${FAKE_ARCHIVE_STATUS:-200}" "${FAKE_ARCHIVE:-}"
    ;;
  *)
    printf 'curl stub: unexpected URL %s\n' "$url" >&2
    exit 1
    ;;
esac
EOF

  cat >"$STUB_BIN/tar" <<'EOF'
#!/bin/bash
set -euo pipefail
if [[ -n "${TAR_SPY:-}" ]]; then
  printf '%s\n' "$*" >>"$TAR_SPY"
fi
exec /bin/tar "$@"
EOF

  cat >"$STUB_BIN/bash" <<'EOF'
#!/bin/bash
set -euo pipefail
if [[ "${1:-}" == "-c" ]]; then
  exec /bin/bash "$@"
fi
{
  printf 'PWD=%s\n' "$(pwd)"
  if [[ -f ./install.sh ]] && grep -q 'per-harness symlinks' ./install.sh; then
    printf 'UPSTREAM_INSTALL=1\n'
  else
    printf 'UPSTREAM_INSTALL=0\n'
  fi
  if [[ -f ./marker ]]; then
    printf 'MARKER=%s\n' "$(cat ./marker)"
  else
    printf 'MARKER=\n'
  fi
  parent="$(dirname "$(pwd)")"
  hash_dir_has() {
    local dir="$1" f got
    [[ -n "${EXPECTED_ARCHIVE_SHA:-}" ]] || return 1
    case "$dir" in
      "${TMPDIR:-}"|"${TMPDIR:-}"/*) ;;
      *) return 1 ;;
    esac
    for f in "$dir"/*; do
      [[ -f "$f" ]] || continue
      got="$(sha256sum "$f" | awk '{print $1}')"
      if [[ "$got" == "$EXPECTED_ARCHIVE_SHA" ]]; then
        return 0
      fi
    done
    return 1
  }
  if hash_dir_has "$parent"; then
    printf 'PARENT_HAS_ARCHIVE=1\n'
  else
    printf 'PARENT_HAS_ARCHIVE=0\n'
  fi
  ancestor_has=0
  dir="$(dirname "$parent")"
  while [[ -n "${EXPECTED_ARCHIVE_SHA:-}" && "$dir" != "/" && "$dir" != "." ]]; do
    case "$dir" in
      "${TMPDIR:-}"|"${TMPDIR:-}"/*) ;;
      *) break ;;
    esac
    if hash_dir_has "$dir"; then
      ancestor_has=1
    fi
    dir="$(dirname "$dir")"
  done
  printf 'ANCESTOR_HAS_ARCHIVE=%s\n' "$ancestor_has"
} >>"${INSTALL_SPY:?}"
exit 0
EOF

  cat >"$STUB_BIN/sudo" <<'EOF'
#!/bin/bash
set -euo pipefail
exec "$@"
EOF

  chmod +x "$STUB_BIN/curl" "$STUB_BIN/tar" "$STUB_BIN/bash" "$STUB_BIN/sudo"
}

setup() {
  RUN_TMP="$(mktemp -d)"
  STUB_BIN="$RUN_TMP/bin"
  mkdir -p "$STUB_BIN"
  SPY="$RUN_TMP/spy"
  TAR_SPY="$RUN_TMP/tar-spy"
  STDOUT="$RUN_TMP/stdout"
  STDERR="$RUN_TMP/stderr"
  : >"$SPY"
  : >"$TAR_SPY"
  FAKE_ARCHIVE="$RUN_TMP/archive.tgz"
  FAKE_ARCHIVE_STATUS=200
  FAKE_ASSET_STATUS=404
  FAKE_ASSET_BODY=""
  FAKE_SUM_STATUS=404
  FAKE_SUM_BODY=""
  FAKE_LATEST_BODY=""
  EXPECTED_ARCHIVE_SHA=""
  trap 'rm -rf "$RUN_TMP"' EXIT
  install_stubs
}

# Build a source archive whose top-level directory contains install.sh.
# The bytes are intentionally not the published default tag archive.
make_fixture_archive() {
  local root="$RUN_TMP/fixture-src"
  rm -rf "$root"
  mkdir -p "$root/pkg"
  printf 'fixture-marker\n' >"$root/pkg/marker"
  cat >"$root/pkg/install.sh" <<'EOF'
#!/usr/bin/env bash
printf 'fixture install\n'
EOF
  chmod +x "$root/pkg/install.sh"
  /bin/tar -C "$root" -czf "$FAKE_ARCHIVE" pkg
  EXPECTED_ARCHIVE_SHA="$(sha256sum "$FAKE_ARCHIVE" | awk '{print $1}')"
}

# A release asset whose member name is the program name, so try_asset can run it.
make_asset() {
  local root="$RUN_TMP/asset-src"
  rm -rf "$root"
  mkdir -p "$root"
  printf '#!/bin/sh\nexit 0\n' >"$root/vaulted-agent"
  chmod +x "$root/vaulted-agent"
  FAKE_ASSET_BODY="$RUN_TMP/asset.tgz"
  /bin/tar -C "$root" -czf "$FAKE_ASSET_BODY" vaulted-agent
  FAKE_ASSET_STATUS=200
}

write_sum() {
  local mode="$1" dest="$RUN_TMP/asset.sha256" hash
  case "$mode" in
    good)
      hash="$(sha256sum "$FAKE_ASSET_BODY" | awk '{print $1}')"
      ;;
    bad)
      hash="0000000000000000000000000000000000000000000000000000000000000000"
      ;;
    *)
      printf 'write_sum: unknown mode %s\n' "$mode" >&2
      exit 2
      ;;
  esac
  printf '%s  bin.tgz\n' "$hash" >"$dest"
  FAKE_SUM_BODY="$dest"
  FAKE_SUM_STATUS=200
}

# Checksummed asset that also carries install.sh under the installer's
# fixed extract directory. The program stub only has to exit 0 so the
# asset is accepted; the planted script is the payload.
make_planting_asset() {
  local root="$RUN_TMP/plant-src"
  rm -rf "$root"
  mkdir -p "$root/source/0-planted"
  printf '#!/bin/sh\nexit 0\n' >"$root/vaulted-agent"
  chmod +x "$root/vaulted-agent"
  printf 'planted-marker\n' >"$root/source/0-planted/marker"
  printf '#!/usr/bin/env bash\nprintf "planted install\\n"\n' \
    >"$root/source/0-planted/install.sh"
  chmod +x "$root/source/0-planted/install.sh"
  FAKE_ASSET_BODY="$RUN_TMP/asset.tgz"
  /bin/tar -C "$root" -czf "$FAKE_ASSET_BODY" vaulted-agent source
  FAKE_ASSET_STATUS=200
}

# Stand in for a source archive that already matched the recorded digest,
# so the fixture can take the default-tag path without fetching the
# published tarball. Asset hashes still go to the real shasum.
install_pinned_digest_shasum() {
  local pin
  pin="$(sed -n 's/^DEFAULT_ARCHIVE_SHA256="\([0-9a-f]\{64\}\)".*/\1/p' "$INSTALL_SH" | head -n 1)"
  [[ -n "$pin" ]] || return 0
  export PINNED_ARCHIVE_SHA256="$pin"
  cat >"$STUB_BIN/shasum" <<'EOF'
#!/bin/bash
set -euo pipefail
real=/usr/bin/shasum
for a in "$@"; do
  if [[ "$a" == "-c" ]]; then
    exec "$real" "$@"
  fi
done
file=""
for a in "$@"; do
  case "$a" in
    -*) ;;
    *) file="$a" ;;
  esac
done
if [[ -n "${PINNED_ARCHIVE_SHA256:-}" && "$(basename -- "$file")" == "src.tar.gz" ]]; then
  printf '%s  %s\n' "$PINNED_ARCHIVE_SHA256" "$file"
  exit 0
fi
exec "$real" "$@"
EOF
  chmod +x "$STUB_BIN/shasum"
}

# Record the install.sh path bash was asked to run. The default spy reads
# ./marker from the caller's cwd, which misses the script selected by the
# pre-change installer.
install_script_spy() {
  cat >"$STUB_BIN/bash" <<'EOF'
#!/bin/bash
set -euo pipefail
if [[ "${1:-}" == "-c" ]]; then
  exec /bin/bash "$@"
fi
script="${1:-}"
case "$script" in
  /*) ;;
  ./*) script="$(pwd)/${script#./}" ;;
  *) script="$(pwd)/$script" ;;
esac
dir="$(dirname -- "$script")"
{
  printf 'SCRIPT=%s\n' "$script"
  if [[ -f "$dir/marker" ]]; then
    printf 'MARKER=%s\n' "$(cat "$dir/marker")"
  else
    printf 'MARKER=\n'
  fi
} >>"${INSTALL_SPY:?}"
exit 0
EOF
  chmod +x "$STUB_BIN/bash"
}

invoke() {
  local version="" archive_url="" repo="" github=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --version) version="$2"; shift 2 ;;
      --archive-url) archive_url="$2"; shift 2 ;;
      --repo) repo="$2"; shift 2 ;;
      --github) github="$2"; shift 2 ;;
      *)
        printf 'invoke: unknown argument %s\n' "$1" >&2
        exit 2
        ;;
    esac
  done
  local status=0
  (
    unset VAULTED_AGENT_VERSION VAULTED_AGENT_ARCHIVE_URL VAULTED_AGENT_BIN VAULTED_AGENT_REPO GITHUB || true
    [[ -z "$version" ]] || export VAULTED_AGENT_VERSION="$version"
    [[ -z "$archive_url" ]] || export VAULTED_AGENT_ARCHIVE_URL="$archive_url"
    [[ -z "$repo" ]] || export VAULTED_AGENT_REPO="$repo"
    [[ -z "$github" ]] || export GITHUB="$github"
    export PATH="$STUB_BIN:$ORIG_PATH"
    export TMPDIR="$RUN_TMP"
    export INSTALL_SPY="$SPY"
    export TAR_SPY="$TAR_SPY"
    export FAKE_ARCHIVE FAKE_ARCHIVE_STATUS FAKE_ASSET_STATUS FAKE_ASSET_BODY
    export FAKE_SUM_STATUS FAKE_SUM_BODY FAKE_LATEST_BODY EXPECTED_ARCHIVE_SHA
    cd "$RUN_TMP"
    timeout 15 /bin/bash "$INSTALL_SH"
  ) >"$STDOUT" 2>"$STDERR" || status=$?
  LAST_STATUS=$status
}

spy_value() {
  local key="$1"
  awk -F= -v k="$key" '$1 == k { print substr($0, index($0, "=") + 1); exit }' "$SPY"
}

# Default tagged source archive: bytes that are not the recorded digest are
# refused, and the archive is not extracted.
test_default_archive_mismatch_refuses_before_extract() {
  setup
  make_fixture_archive
  invoke
  assert "installer exits non-zero" test "$LAST_STATUS" -ne 0
  assert "digest failure is reported" grep -q 'digest' "$STDERR"
  assert "archive was not extracted" test ! -s "$TAR_SPY"
  assert "install.sh was not run" test ! -s "$SPY"
}

# A different tag is not the recorded digest's archive. The fixture bytes install.
test_version_override_skips_recorded_digest() {
  setup
  make_fixture_archive
  invoke --version v0.9.9
  assert "version override exits 0" test "$LAST_STATUS" -eq 0
  assert "fixture install.sh ran" test "$(spy_value MARKER)" = "fixture-marker"
}

# latest is a caller-supplied version, even when the API answers with some tag.
test_latest_override_skips_recorded_digest() {
  setup
  make_fixture_archive
  printf '%s\n' '{"tag_name":"v9.9.9"}' >"$RUN_TMP/latest.json"
  FAKE_LATEST_BODY="$RUN_TMP/latest.json"
  invoke --version latest
  assert "latest override exits 0" test "$LAST_STATUS" -eq 0
  assert "fixture install.sh ran" test "$(spy_value MARKER)" = "fixture-marker"
}

# Naming the default tag still fetches that archive, so the recorded digest applies.
test_explicit_default_version_requires_recorded_digest() {
  setup
  make_fixture_archive
  invoke --version "${PIN}"
  assert "explicit default version exits non-zero" test "$LAST_STATUS" -ne 0
  assert "digest failure is reported" grep -q 'digest' "$STDERR"
  assert "archive was not extracted" test ! -s "$TAR_SPY"
}

test_archive_url_override_skips_recorded_digest() {
  setup
  make_fixture_archive
  invoke --archive-url "https://example.test/custom.tar.gz"
  assert "archive URL override exits 0" test "$LAST_STATUS" -eq 0
  assert "fixture install.sh ran" test "$(spy_value MARKER)" = "fixture-marker"
}

# Even the canonical URL string, when supplied by the caller, stays an override.
test_canonical_archive_url_override_skips_recorded_digest() {
  setup
  make_fixture_archive
  invoke --archive-url "https://github.com/JacobStephens2/vaulted-agent/archive/refs/tags/${PIN}.tar.gz"
  assert "caller-supplied canonical URL exits 0" test "$LAST_STATUS" -eq 0
  assert "fixture install.sh ran" test "$(spy_value MARKER)" = "fixture-marker"
}

test_repo_override_skips_recorded_digest() {
  setup
  make_fixture_archive
  invoke --repo example/fork
  assert "repo override exits 0" test "$LAST_STATUS" -eq 0
  assert "fixture install.sh ran" test "$(spy_value MARKER)" = "fixture-marker"
}

# A substituted host for the default archive still has to match the recorded digest.
test_mirror_host_requires_recorded_digest() {
  setup
  make_fixture_archive
  invoke --github "https://mirror.example"
  assert "mirror host exits non-zero" test "$LAST_STATUS" -ne 0
  assert "digest failure is reported" grep -q 'digest' "$STDERR"
  assert "archive was not extracted" test ! -s "$TAR_SPY"
}

# Published default tag archive: digest matches, extract into its own directory,
# and run that tree's install.sh with the tree as the working directory.
test_matching_default_archive_runs_from_its_own_directory() {
  if [[ "${INSTALL_REMOTE_TEST_OFFLINE:-}" == 1 ]]; then
    printf 'skip (offline): published archive digest\n'
    return 0
  fi
  setup
  /usr/bin/curl -fsSL -o "$FAKE_ARCHIVE" \
    "https://github.com/JacobStephens2/vaulted-agent/archive/refs/tags/${PIN}.tar.gz"
  EXPECTED_ARCHIVE_SHA="$(sha256sum "$FAKE_ARCHIVE" | awk '{print $1}')"
  assert "installer records the published archive digest" \
    grep -F -q "$EXPECTED_ARCHIVE_SHA" "$INSTALL_SH"
  invoke
  assert "matching default archive exits 0" test "$LAST_STATUS" -eq 0
  assert "ran install.sh from the extracted tree" test "$(spy_value UPSTREAM_INSTALL)" = "1"
  assert "tarball is not next to the extracted tree" test "$(spy_value PARENT_HAS_ARCHIVE)" = "0"
  assert "tarball lives outside the extract directory" test "$(spy_value ANCESTOR_HAS_ARCHIVE)" = "1"
}

test_release_asset_without_checksum_stops() {
  setup
  make_fixture_archive
  make_asset
  invoke
  assert "missing checksum exits non-zero" test "$LAST_STATUS" -ne 0
  assert "missing checksum is reported" grep -q 'no checksum' "$STDERR"
  assert "unverified asset was not extracted" test ! -s "$TAR_SPY"
  assert "install.sh was not run" test ! -s "$SPY"
}

test_release_asset_checksum_mismatch_stops() {
  setup
  make_fixture_archive
  make_asset
  write_sum bad
  invoke
  assert "bad checksum exits non-zero" test "$LAST_STATUS" -ne 0
  assert "checksum mismatch is reported" grep -q 'checksum verification failed' "$STDERR"
  assert "unverified asset was not extracted" test ! -s "$TAR_SPY"
  assert "install.sh was not run" test ! -s "$SPY"
}

test_release_asset_checksum_match_continues() {
  setup
  make_fixture_archive
  make_asset
  write_sum good
  invoke --version v0.9.9
  assert "checked asset exits 0" test "$LAST_STATUS" -eq 0
  assert "checksum was accepted" grep -q 'checksum ok' "$STDOUT"
  assert "fixture install.sh ran" test "$(spy_value MARKER)" = "fixture-marker"
  assert "source archive was extracted into its own directory" \
    test "$(spy_value PARENT_HAS_ARCHIVE)" = "0"
  assert "source tarball lives outside that directory" \
    test "$(spy_value ANCESTOR_HAS_ARCHIVE)" = "1"
}

# Default tag path: the recorded digest has matched, and a checksummed
# release asset has already been unpacked into the work directory. The
# asset must not be able to choose which install.sh runs.
test_release_asset_cannot_plant_source_install_sh() {
  setup
  make_fixture_archive
  make_planting_asset
  write_sum good
  install_pinned_digest_shasum
  install_script_spy
  export LC_ALL=C
  invoke
  assert "planted asset still installs" test "$LAST_STATUS" -eq 0
  assert "source archive install.sh ran" test "$(spy_value MARKER)" = "fixture-marker"
  assert "planted install.sh was not selected" \
    test "$(spy_value MARKER)" != "planted-marker"
}

run_test() {
  local name="$1"
  shift
  if ( "$@" ); then
    printf 'ok %s\n' "$name"
  else
    printf 'not ok %s\n' "$name" >&2
    FAILS=$((FAILS + 1))
  fi
}

run_test "default archive mismatch refuses before extract" \
  test_default_archive_mismatch_refuses_before_extract
run_test "version override skips recorded digest" \
  test_version_override_skips_recorded_digest
run_test "latest override skips recorded digest" \
  test_latest_override_skips_recorded_digest
run_test "explicit default version requires recorded digest" \
  test_explicit_default_version_requires_recorded_digest
run_test "archive URL override skips recorded digest" \
  test_archive_url_override_skips_recorded_digest
run_test "canonical archive URL override skips recorded digest" \
  test_canonical_archive_url_override_skips_recorded_digest
run_test "repo override skips recorded digest" \
  test_repo_override_skips_recorded_digest
run_test "mirror host requires recorded digest" \
  test_mirror_host_requires_recorded_digest
run_test "matching default archive runs from its own directory" \
  test_matching_default_archive_runs_from_its_own_directory
run_test "release asset without checksum stops" \
  test_release_asset_without_checksum_stops
run_test "release asset checksum mismatch stops" \
  test_release_asset_checksum_mismatch_stops
run_test "release asset checksum match continues" \
  test_release_asset_checksum_match_continues
run_test "release asset cannot plant source install.sh" \
  test_release_asset_cannot_plant_source_install_sh

if [[ "$FAILS" -ne 0 ]]; then
  printf '%s failed\n' "$FAILS" >&2
  exit 1
fi
printf 'all tests passed\n'
