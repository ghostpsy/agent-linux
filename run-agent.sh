#!/usr/bin/env bash
# Download the latest GitHub Release binary for this machine, then run `ghostpsy scan`.
# Requires: bash, curl, sha256sum or shasum. (Do not run with `sh`; use `bash run-agent.sh` or `./run-agent.sh`.)

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
    i386 | i686) echo i386 ;;
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
[[ -n "$bin_url" ]] || die "No binary asset for linux/${goarch} in latest release (or unexpected API JSON). See https://github.com/${REPO_OWNER}/${REPO_NAME}/releases"
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

export GHOSTPSY_API_URL="https://api.ghostpsy.com"

had_token_at_start=0
[[ -n "${GHOSTPSY_INGEST_TOKEN-}" ]] && had_token_at_start=1

if [[ -z "${GHOSTPSY_INGEST_TOKEN-}" ]]; then
  echo "" >&2
  echo "Get a token: open https://app.ghostpsy.com in a browser, sign in, then create a token from the app header." >&2
  echo "After you enter the token, this machine will be scanned and a JSON report will be shown. Nothing is sent to Ghostpsy Cloud until you confirm at the end; you can review the payload before that." >&2
  echo "" >&2
  if [[ ! -r /dev/tty ]]; then
    die "Set GHOSTPSY_INGEST_TOKEN in the environment (no TTY to prompt — e.g. some piped or automated runs)."
  fi
  read -r -s -p "Paste token: " GHOSTPSY_INGEST_TOKEN </dev/tty || die "Could not read token from terminal."
  echo "" >&2
  [[ -n "${GHOSTPSY_INGEST_TOKEN// }" ]] || die "Token is required."
fi

# Verbose: on by default when the script prompts for the token ([Y/n] defaults to yes);
# off by default when GHOSTPSY_INGEST_TOKEN was already set (set GHOSTPSY_VERBOSE=1 to enable).
scan_args=(scan)
if ((had_token_at_start)); then
  case "${GHOSTPSY_VERBOSE:-}" in
    1 | true | TRUE | yes | Yes | YES) scan_args+=(--verbose) ;;
  esac
else
  if [[ "${GHOSTPSY_VERBOSE+x}" != x ]]; then
    echo "" >&2
    read -r -p "Enable verbose logging (step-by-step actions)? [Y/n]: " vline </dev/tty || vline=""
    v="$(printf '%s' "$vline" | tr '[:upper:]' '[:lower:]')"
    if [[ -z "${v// }" || "$v" == y* ]]; then
      scan_args+=(--verbose)
    fi
  else
    case "${GHOSTPSY_VERBOSE}" in
      1 | true | TRUE | yes | Yes | YES | y | Y) scan_args+=(--verbose) ;;
      0 | false | FALSE | no | No | NO | n | N) ;;
      "")
        echo "" >&2
        read -r -p "Enable verbose logging (step-by-step actions)? [Y/n]: " vline </dev/tty || vline=""
        v="$(printf '%s' "$vline" | tr '[:upper:]' '[:lower:]')"
        if [[ -z "${v// }" || "$v" == y* ]]; then
          scan_args+=(--verbose)
        fi
        ;;
      *) die "Invalid GHOSTPSY_VERBOSE (use 1/true/yes or 0/false/no)." ;;
    esac
  fi
fi

export GHOSTPSY_INGEST_TOKEN
exec "$bin_path" "${scan_args[@]}"
