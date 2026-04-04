#!/usr/bin/env bash
# Download the latest GitHub Release binary for this machine, then run `ghostpsy scan`.
# Requires: bash, curl, jq, sha256sum or shasum.

set -euo pipefail

REPO_OWNER="ghostpsy"
REPO_NAME="agent-linux"
UA="ghostpsy-agent-run-script/1.0"

die() {
  echo "Error: $*" >&2
  exit 1
}

map_arch() {
  case "$(uname -m)" in
    x86_64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    i386 | i686) echo 386 ;;
    *)
      die "Unsupported CPU: $(uname -m). Supported: x86_64, aarch64/arm64, i386/i686."
      ;;
  esac
}

goarch="$(map_arch)"
command -v jq >/dev/null 2>&1 || die "This script needs jq. Install: apt install jq, dnf install jq, brew install jq — https://jqlang.org/download/"
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
  echo "No GitHub Release found yet (or GitHub API unreachable)." >&2
  echo "Download a binary from a successful workflow run instead:" >&2
  echo "  https://github.com/${REPO_OWNER}/${REPO_NAME}/actions/workflows/build.yml" >&2
  echo "Open the latest run → Artifacts → ghostpsy-linux-${goarch} (and SHA256SUMS)." >&2
  exit 1
fi

bin_url="$(jq -r --arg arch "$goarch" '
  .assets[]
  | select((.name | startswith("ghostpsy_")) and (.name | endswith("_linux_" + $arch)))
  | .browser_download_url
  ' "$release_json" | head -n 1)"
sums_url="$(jq -r '.assets[] | select(.name == "SHA256SUMS") | .browser_download_url' "$release_json" | head -n 1)"
[[ -n "$bin_url" && "$bin_url" != "null" ]] || die "No binary asset for linux/${goarch} in latest release. See https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
[[ -n "$sums_url" && "$sums_url" != "null" ]] || die "SHA256SUMS missing in latest release."

bin_path="$tmpdir/ghostpsy"
curl -fsSL -H "User-Agent: $UA" -o "$bin_path" "$bin_url"
curl -fsSL -H "User-Agent: $UA" -o "$tmpdir/SHA256SUMS" "$sums_url"
sum_line="$(grep "_linux_${goarch}" "$tmpdir/SHA256SUMS" | head -n 1 || true)"
[[ -n "$sum_line" ]] || die "Could not find checksum line for linux/${goarch} in SHA256SUMS"
read -r expected_hash expected_file <<<"$sum_line"
if command -v sha256sum >/dev/null 2>&1; then
  actual_hash="$(sha256sum "$bin_path" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual_hash="$(shasum -a 256 "$bin_path" | awk '{print $1}')"
else
  die "Need sha256sum or shasum to verify the download."
fi
[[ "$actual_hash" == "$expected_hash" ]] || die "Checksum mismatch for ${expected_file}"
chmod +x "$bin_path"

if [[ -z "${GHOSTPSY_API_URL:-}" ]]; then
  read -r -p "Ghostpsy API base URL (example: https://app.yourcompany.com): " GHOSTPSY_API_URL
  [[ -n "${GHOSTPSY_API_URL// }" ]] || die "API URL is required."
fi

if [[ -z "${GHOSTPSY_INGEST_TOKEN:-}" ]]; then
  echo ""
  echo "Ingest token — get one from the Ghostpsy web app: sign in, then use **New ingest token**"
  echo "in the header. Copy it when shown; each token is valid for **one** successful upload."
  echo ""
  read -r -s -p "Paste ingest token: " GHOSTPSY_INGEST_TOKEN
  echo ""
  [[ -n "${GHOSTPSY_INGEST_TOKEN// }" ]] || die "Ingest token is required."
fi

export GHOSTPSY_API_URL
export GHOSTPSY_INGEST_TOKEN
exec "$bin_path" scan
