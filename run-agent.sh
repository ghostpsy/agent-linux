#!/usr/bin/env bash
# Download the latest GitHub Release binary for this machine, then run `ghostpsy scan`.
# Requires: bash, curl, sha256sum or shasum. (Do not run with `sh`; use `bash run-agent.sh` or `./run-agent.sh`.)

set -euo pipefail

REPO_OWNER="ghostpsy"
REPO_NAME="agent-linux"
UA="ghostpsy-agent-run-script/1.0"
DEFAULT_GHOSTPSY_API_URL="https://api.ghostpsy.com"

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

# Join response lines: GitHub returns minified JSON; macOS awk match() on dynamic ERE is unreliable — use bash [[ =~ ]].
release_blob="$(tr -d '\n\r' < "$release_json")"
if [[ "$release_blob" == *'"message"'*'rate_limit'* ]] || [[ "$release_blob" == *"API rate limit"* ]]; then
  die "GitHub API rate limit — wait and retry, or download binaries from Actions: https://github.com/${REPO_OWNER}/${REPO_NAME}/actions/workflows/build.yml"
fi
re_bin="https://github\\.com/${REPO_OWNER}/${REPO_NAME}/releases/download/[^\"]+/ghostpsy_[^\"]+_linux_${goarch}\""
re_sums="https://github\\.com/${REPO_OWNER}/${REPO_NAME}/releases/download/[^\"]+/SHA256SUMS\""
bin_url=""
sums_url=""
if [[ "$release_blob" =~ $re_bin ]]; then
  bin_url="${BASH_REMATCH[0]%\"}"
fi
if [[ "$release_blob" =~ $re_sums ]]; then
  sums_url="${BASH_REMATCH[0]%\"}"
fi
[[ -n "$bin_url" ]] || die "No binary asset for linux/${goarch} in latest release (or unexpected API JSON). See https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
[[ -n "$sums_url" ]] || die "SHA256SUMS missing in latest release."

bin_path="$tmpdir/ghostpsy"
curl -fsSL -H "User-Agent: $UA" -o "$bin_path" "$bin_url"
curl -fsSL -H "User-Agent: $UA" -o "$tmpdir/SHA256SUMS" "$sums_url"
sum_line="$(grep "_linux_${goarch}" "$tmpdir/SHA256SUMS" | head -n 1 || true)"
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

if [[ -z "${GHOSTPSY_API_URL// }" ]]; then
  GHOSTPSY_API_URL="$DEFAULT_GHOSTPSY_API_URL"
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
