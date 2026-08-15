#!/usr/bin/env bash
# Install the ghostpsy agent and set it up to keep reporting.
#
#   curl -fsSL <this script> | sudo bash -s -- --token=<code from the dashboard>
#
# It detects the CPU architecture, downloads the matching release binary from
# GitHub Releases, verifies its SHA256, installs it to /usr/local/bin/ghostpsy,
# and then hands over to `ghostpsy setup`, which creates the locked ghostpsy
# user, installs a scoped sudo rule and starts the background service.
#
# Options:
#   --token=CODE    the single-use code from the dashboard
#   --dry-run       show every change and make none. Downloads to a temporary
#                   directory so it can show you the real plan, then stops.
#   --binary-only   install the binary and nothing else. No user, no service,
#                   no sudo rule. For reading `ghostpsy sudoers` first.
#
# This script stays deliberately thin. Everything that can damage a server —
# the sudo rule, the user, the service — lives in `ghostpsy setup`, where it
# is covered by tests.
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

# This script needs bash: it uses [[ ]] and BASH_REMATCH. /bin/sh is dash on
# Debian and Ubuntu, where those are syntax errors and $EUID is unset. Say so
# here rather than failing later with something confusing.
if [ -z "${BASH_VERSION:-}" ]; then
  echo "Error: this installer needs bash, not sh." >&2
  echo "Run:  curl -fsSL <this script> | sudo bash -s -- --token=<code>" >&2
  exit 1
fi

set -euo pipefail

REPO_OWNER="ghostpsy"
REPO_NAME="agent-linux"
UA="ghostpsy-agent-install/2.0"
INSTALL_PATH="/usr/local/bin/ghostpsy"

TOKEN=""
DRY_RUN=0
BINARY_ONLY=0

die() {
  echo "Error: $*" >&2
  exit 1
}

# Kept next to the flags it documents. The previous version printed a fixed
# line range of the header comment, which silently truncated as soon as anyone
# added a line above it.
usage() {
  cat <<'EOF'
Install the ghostpsy agent and set it up to keep reporting.

  curl -fsSL <this script> | sudo bash -s -- --token=<code from the dashboard>

Options:
  --token=CODE    the single-use code from the dashboard
  --dry-run       show every change and make none
  --binary-only   install the binary only: no user, no service, no sudo rule
  -h, --help      this text

Everything that can change a server lives in `ghostpsy setup`, which this
script calls once the binary is in place.
EOF
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

# Parsed after the helpers above are defined: a shell only knows a function
# once it has read it, and --help calls usage().
for arg in "$@"; do
  case "$arg" in
    --token=*) TOKEN="${arg#*=}" ;;
    --dry-run) DRY_RUN=1 ;;
    --binary-only) BINARY_ONLY=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      echo "Run with --help to see what this accepts." >&2
      exit 2
      ;;
  esac
done

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

# A dry run stops here. The binary has been downloaded to a temporary
# directory, which changes nothing on this server, and running it from there
# lets us show the real plan rather than a guess at one.
if [[ $DRY_RUN -eq 1 ]]; then
  echo ""
  echo "This is what would happen. Nothing is being changed."
  echo ""
  echo "  - Install ${expected_file} at ${INSTALL_PATH}"
  chmod 0755 "$bin_path"
  "$bin_path" setup --dry-run --token="$TOKEN"
  exit 0
fi

install -m 0755 "$bin_path" "$INSTALL_PATH"
echo "  ok  Installed ${expected_file} at ${INSTALL_PATH}"

if [[ $BINARY_ONLY -eq 1 ]]; then
  echo ""
  echo "The binary is installed and nothing else was touched."
  echo "To see the sudo rights it would need:  ghostpsy sudoers"
  echo "To finish the install:                 sudo ghostpsy setup --token=<code>"
  exit 0
fi

if [[ -z "$TOKEN" ]]; then
  echo ""
  echo "The binary is installed, but no code was given, so this machine is not"
  echo "registered yet. Copy the full command from the dashboard's Add machine"
  echo "screen — it includes the code."
  exit 1
fi

exec "$INSTALL_PATH" setup --token="$TOKEN"
