# Ghostpsy — Linux agent

[![Build Linux agent](https://github.com/ghostpsy/agent-linux/actions/workflows/build.yml/badge.svg)](https://github.com/ghostpsy/agent-linux/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Open-source** Go agent for **Ghostpsy**: it collects an **allowlisted** snapshot of a Linux host (OS, listeners, packages, SSH posture, time skew hints, and more), shows a **full JSON preview**, then posts to **Ghostpsy Cloud API** with a **one-time token**.

You can audit every collector under `internal/collect/` before you run the binary.

## Run the latest release (recommended)

This downloads the correct **static** binary for your CPU (**amd64**, **arm64**, or **i386**), checks it against **SHA256SUMS** from the same [GitHub Release](https://github.com/ghostpsy/agent-linux/releases/latest), then starts an interactive `scan`.

**1. Token** — Use an account on **[https://app.ghostpsy.com](https://app.ghostpsy.com)**, sign in, and create a **token** from the app (header). Each token works for **one** successful upload.

**2. Run** — Needs `bash`, `curl`, and `sha256sum` or `shasum`. Use **`bash`**, not plain `sh`.

The agent needs **root** for full collection. **Use `sudo` in the command below; drop `sudo` if you are already root.**

The script reads the **token** from your terminal (`/dev/tty`), so `curl … | sudo bash` still works when you are at a real keyboard and did not export a token.

**If you `export GHOSTPSY_INGEST_TOKEN=…` first**, use `sudo env "GHOSTPSY_INGEST_TOKEN=$GHOSTPSY_INGEST_TOKEN" bash` instead of plain `sudo bash`: the superuser shell does **not** inherit your normal-user environment by default, so the token would be missing and the script would prompt again.

**Verbose logging** is **on by default** when the script asks you for the token (you can answer **n** at the prompt to turn it off). If **`GHOSTPSY_INGEST_TOKEN`** is **already set** when the script starts (automation), verbose **defaults to off**; set **`GHOSTPSY_VERBOSE=1`** or **`true`** to enable step-by-step logs (`--verbose`). You can also set **`GHOSTPSY_VERBOSE=0`** or **`false`** before `curl` to skip the prompt and run quietly.

```bash
curl -fsSL https://raw.githubusercontent.com/ghostpsy/agent-linux/main/run-agent.sh | sudo bash
```

`run-agent.sh` sets the Cloud API base URL to **`https://api.ghostpsy.com`** (fixed). It prompts for a **token** when `GHOSTPSY_INGEST_TOKEN` is unset.

| Variable | Purpose |
|----------|---------|
| `GHOSTPSY_INGEST_TOKEN` | Token (environment, or paste when prompted) |
| `GHOSTPSY_VERBOSE` | Optional: `1` / `true` / `yes` → `--verbose`; `0` / `false` / `no` → quiet. If **unset**: verbose **on** when you paste the token (prompted); verbose **off** when `GHOSTPSY_INGEST_TOKEN` was **already** set. |

Example with token in the environment (preset token → quiet unless you set `GHOSTPSY_VERBOSE`):

```bash
export GHOSTPSY_INGEST_TOKEN="your-one-time-token"
curl -fsSL https://raw.githubusercontent.com/ghostpsy/agent-linux/main/run-agent.sh | sudo env "GHOSTPSY_INGEST_TOKEN=$GHOSTPSY_INGEST_TOKEN" bash
```

## Without the bash wrapper

To run a binary from [Releases](https://github.com/ghostpsy/agent-linux/releases/latest) yourself (no `run-agent.sh`), download **`ghostpsy_<version>_linux_<arch>`** and **`SHA256SUMS`**, verify with `sha256sum -c SHA256SUMS`, then:

```bash
export GHOSTPSY_API_URL="https://api.ghostpsy.com"
export GHOSTPSY_INGEST_TOKEN="your-token"
chmod +x ghostpsy_*_linux_amd64   # use your arch: amd64, arm64, or i386
./ghostpsy_*_linux_amd64 scan
```

## Prebuilt binaries and releases

Static builds for **linux/amd64**, **linux/arm64**, and **linux/i386** are published on [GitHub Releases](https://github.com/ghostpsy/agent-linux/releases), each with a **SHA256SUMS** file.

## Why open source

- **Trust:** Security and ops teams can read what runs on the server.
- **Reproducible builds:** Published release binaries are static (`CGO_ENABLED=0`) with checksums.
- **Clear scope:** Collectors follow the **ingest v1** contract used by Ghostpsy Cloud.

## What it does (and does not do)

| Does | Does not |
|------|----------|
| Reads local OS metadata, listeners, firewall hints, package update summaries, selected host facts | Run as a long-lived daemon (one-shot `scan` by default) |
| Shows a **full outbound JSON preview**; send only after you confirm | Send without confirmation in interactive `scan` |
| Uses **HTTPS** to Ghostpsy Cloud API | Store your token in this repository |

## Collector coverage by release

Optional ingest blocks (e.g. Apache `apache_httpd_posture`) depend on what is installed on the host. A **version matrix** is maintained in the Ghostpsy docs: **[agent-linux collector coverage](https://github.com/ghostpsy/ghostpsy/blob/main/internal-doc/agent-linux-collector-coverage.md)**.

## Requirements

- **OS:** Linux only (`GOOS=linux` in release builds).
- **Account:** **[https://app.ghostpsy.com](https://app.ghostpsy.com)** — sign in to create a **token**.
- **Privileges:** Full collection expects **root**; use **`sudo`** with the one-liner above unless you are already root.

## Build from source

```bash
git clone https://github.com/ghostpsy/agent-linux.git
cd agent-linux
make test
make build
./bin/ghostpsy help
./bin/ghostpsy scan -dry-run
```

## Module path

Go module: **`github.com/ghostpsy/agent-linux`**

## License

Apache License 2.0 — see [LICENSE](LICENSE).
