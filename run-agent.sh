#!/usr/bin/env bash
# Install (or upgrade) the latest ghostpsy agent at /usr/local/bin/ghostpsy.
#
# This script is install-only. It detects the CPU architecture, downloads the
# matching release binary from GitHub Releases, verifies its SHA256, and writes
# it to /usr/local/bin/ghostpsy. It does NOT register the host with the API
# and does NOT need a bootstrap token. After this script finishes, run:
#
#   sudo ghostpsy register --bootstrap="<your bootstrap token>"
#
# The dashboard's "Add a machine" modal walks through the three steps end to
# end (export token → install binary → register).
#
# Trust model:
#   * First install (this script): integrity rests on GitHub Releases over
#     HTTPS plus the SHA256SUMS check below. Ed25519 signature verification
#     is not possible at install time without a pre-existing trust anchor —
#     the embedded public key in the *installed* binary becomes the anchor
#     for every auto-update after this point.
#   * Subsequent auto-updates: ``ghostpsy update`` verifies SHA256SUMS.sig
#     with the embedded public key before swapping the binary.
#
# Requires: bash, curl, sha256sum or shasum. Run as root (or via sudo) so the
# binary can be written to /usr/local/bin.

set -euo pipefail

REPO_OWNER="ghostpsy"
REPO_NAME="agent-linux"
UA="ghostpsy-agent-install/1.0"
INSTALL_PATH="/usr/local/bin/ghostpsy"

die() {
  echo "Error: $*" >&2
  exit 1
}

map_arch() {
  case "$(uname -m)" in
    x86_64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    i386 | i686) echo i386 ;;
    *)
      die "Unsupported CPU: $(uname -m). Supported: x86_64, aarch64/arm64, i386/i686."
      ;;
  esac
}

if [[ $EUID -ne 0 ]]; then
  die "This script installs to ${INSTALL_PATH} — run as root or via sudo."
fi

goarch="$(map_arch)"
tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

release_json="$tmpdir/release.json"
if ! curl -fsSL -H "Accept: application/vnd.github+json" -H "User-Agent: $UA" \
  -o "$release_json" \
  "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"; then
  echo >&2
  echo "Could not load the latest GitHub Release (none published yet or GitHub API unreachable)." >&2
  echo "See https://github.com/${REPO_OWNER}/${REPO_NAME}/releases for binaries and SHA256SUMS." >&2
  exit 1
fi

release_blob="$(tr -d '\n\r' < "$release_json")"
if [[ "$release_blob" == *'"message"'*'rate_limit'* ]] || [[ "$release_blob" == *"API rate limit"* ]]; then
  die "GitHub API rate limit — wait and retry, or download from https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
fi
re_bin="https://github\\.com/${REPO_OWNER}/${REPO_NAME}/releases/download/[^\"]+/ghostpsy_[^\"]+_linux_${goarch}\""
re_sums="https://github\\.com/${REPO_OWNER}/${REPO_NAME}/releases/download/[^\"]+/SHA256SUMS\""
bin_url=""
sums_url=""
if [[ "$release_blob" =~ $re_bin ]]; then
  bin_url="${BASH_REMATCH[0]%\"}"
fi
if [[ -z "$bin_url" && "$goarch" == "i386" ]]; then
  re_legacy="https://github\\.com/${REPO_OWNER}/${REPO_NAME}/releases/download/[^\"]+/ghostpsy_[^\"]+_linux_386\""
  if [[ "$release_blob" =~ $re_legacy ]]; then
    bin_url="${BASH_REMATCH[0]%\"}"
  fi
fi
if [[ "$release_blob" =~ $re_sums ]]; then
  sums_url="${BASH_REMATCH[0]%\"}"
fi
[[ -n "$bin_url" ]] || die "No binary asset for linux/${goarch} in latest release. See https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
[[ -n "$sums_url" ]] || die "SHA256SUMS missing in latest release."

bin_path="$tmpdir/ghostpsy"
curl -fsSL -H "User-Agent: $UA" -o "$bin_path" "$bin_url"
curl -fsSL -H "User-Agent: $UA" -o "$tmpdir/SHA256SUMS" "$sums_url"
if [[ "$goarch" == "i386" ]]; then
  sum_line="$(grep -E "_linux_(i386|386)" "$tmpdir/SHA256SUMS" | head -n 1 || true)"
else
  sum_line="$(grep "_linux_${goarch}" "$tmpdir/SHA256SUMS" | head -n 1 || true)"
fi
[[ -n "$sum_line" ]] || die "Could not find checksum line for linux/${goarch} in SHA256SUMS"
read -r expected_hash expected_file <<<"$sum_line"
if command -v sha256sum >/dev/null 2>&1; then
  read -r actual_hash _ <<<"$(sha256sum "$bin_path")"
elif command -v shasum >/dev/null 2>&1; then
  read -r actual_hash _ <<<"$(shasum -a 256 "$bin_path")"
else
  die "Need sha256sum or shasum to verify the download."
fi
[[ "$actual_hash" == "$expected_hash" ]] || die "Checksum mismatch for ${expected_file}"

install -m 0755 "$bin_path" "$INSTALL_PATH"

echo ""
echo "Installed ${expected_file} at ${INSTALL_PATH}."
echo "Next:"
echo "  sudo ghostpsy register --bootstrap=\"\$GHOSTPSY_BOOTSTRAP_TOKEN\""
echo "  sudo ghostpsy cron install"
