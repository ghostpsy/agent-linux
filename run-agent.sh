#!/usr/bin/env bash
# Install the latest ghostpsy agent to /usr/local/bin and run the first scan
# with a bootstrap token. The API issues the persistent agent token in the
# response and the agent stores it in /etc/ghostpsy/agent.conf (mode 0600).
#
# Requires: bash, curl, sha256sum or shasum. Run as root (or via sudo) so the
# binary can be installed and /etc/ghostpsy/agent.conf can be written.
#
# Usage:
#   sudo GHOSTPSY_BOOTSTRAP_TOKEN=xxx bash run-agent.sh
#
# Or, when piping:
#   curl -fsSL https://raw.githubusercontent.com/ghostpsy/agent-linux/main/run-agent.sh | \
#     sudo env "GHOSTPSY_BOOTSTRAP_TOKEN=$GHOSTPSY_BOOTSTRAP_TOKEN" bash

set -euo pipefail

REPO_OWNER="ghostpsy"
REPO_NAME="agent-linux"
UA="ghostpsy-agent-run-script/2.0"
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
  die "This script installs to ${INSTALL_PATH} and writes /etc/ghostpsy/agent.conf — run as root or via sudo."
fi

if [[ -z "${GHOSTPSY_BOOTSTRAP_TOKEN-}" ]]; then
  die "Set GHOSTPSY_BOOTSTRAP_TOKEN before running. Generate one in the dashboard (https://app.ghostpsy.com)."
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
chmod +x "$bin_path"

install -m 0755 "$bin_path" "$INSTALL_PATH"

export GHOSTPSY_API_URL="${GHOSTPSY_API_URL:-https://api.ghostpsy.com}"
"$INSTALL_PATH" register --bootstrap="$GHOSTPSY_BOOTSTRAP_TOKEN"

echo ""
echo "Next: enable scheduled scans:"
echo "  sudo ${INSTALL_PATH} cron install"
