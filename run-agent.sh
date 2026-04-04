#!/usr/bin/env bash
# Download the latest GitHub Release binary for this machine, then run `ghostpsy scan`.
# Requires: bash, curl, python3, chmod. Optional: sha256sum (or shasum) to verify checksums.

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

read -r bin_url sums_url <<<"$(python3 << PY
import json, sys
goarch = "${goarch}"
path = "${release_json}"
with open(path, encoding="utf-8") as f:
    data = json.load(f)
assets = {a["name"]: a["browser_download_url"] for a in data.get("assets", [])}
bin_name = next(
    (
        n
        for n in assets
        if n.startswith("ghostpsy_") and n.endswith(f"_linux_{goarch}") and not n.endswith(".asc")
    ),
    None,
)
if not bin_name:
    print("no matching binary in latest release", file=sys.stderr)
    sys.exit(1)
sums = assets.get("SHA256SUMS")
if not sums:
    print("SHA256SUMS missing in release", file=sys.stderr)
    sys.exit(1)
print(assets[bin_name], sums)
PY
)" || die "Could not find a release asset for linux/${goarch}. See https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"

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
