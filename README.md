# Ghostpsy — Linux agent

[![Build Linux agent](https://github.com/ghostpsy/agent-linux/actions/workflows/build.yml/badge.svg)](https://github.com/ghostpsy/agent-linux/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Open-source** Go agent for **Ghostpsy**: it collects an **allowlisted** snapshot of a Linux host (OS, listeners, packages, SSH posture, time skew hints, and more), shows a **full JSON preview**, then posts to your Ghostpsy API with a **one-time ingest token**.

You can audit every collector under `internal/collect/` before you run the binary.

## Run the latest release (recommended)

This downloads the correct **static** binary for your CPU (**amd64**, **arm64**, or **386**), checks it against **SHA256SUMS** from the same [GitHub Release](https://github.com/ghostpsy/agent-linux/releases/latest), then starts an interactive `scan`.

**1. Ingest token** — In the Ghostpsy web app, sign in and use **New ingest token** in the header. Copy the value when it appears; **each token works for one successful upload** only.

**2. Run** (needs `bash`, `curl`, and `sha256sum` or `shasum`; run with **`bash`**, not plain `sh`):

```bash
curl -fsSL https://raw.githubusercontent.com/ghostpsy/agent-linux/main/run-agent.sh | bash
```

Or clone the repo and run `./run-agent.sh`.

If `GHOSTPSY_API_URL` is unset, the script uses **`https://api.ghostpsy.com`**. It still asks for the **ingest token** when `GHOSTPSY_INGEST_TOKEN` is unset:

| Variable | Purpose |
|----------|---------|
| `GHOSTPSY_API_URL` | Base URL of the Ghostpsy API (default: `https://api.ghostpsy.com`) |
| `GHOSTPSY_INGEST_TOKEN` | Bearer token for `POST /v1/ingest` |

Example without prompts:

```bash
export GHOSTPSY_INGEST_TOKEN="your-one-time-token"
# Optional: export GHOSTPSY_API_URL="https://api.ghostpsy.com"  # same as default if omitted
curl -fsSL https://raw.githubusercontent.com/ghostpsy/agent-linux/main/run-agent.sh | bash
```

**If there is no Release yet** (or the API call fails), the script prints a link to the [Build workflow](https://github.com/ghostpsy/agent-linux/actions/workflows/build.yml): open the latest successful run → **Artifacts** → download `ghostpsy-linux-<arch>` and `SHA256SUMS`, verify with `sha256sum -c SHA256SUMS`, then run the binary with the same env vars and `ghostpsy scan`.

## Prebuilt binaries and Releases

- **Releases** — Versioned binaries and `SHA256SUMS` are attached to [GitHub Releases](https://github.com/ghostpsy/agent-linux/releases) when a maintainer pushes a version tag such as `v0.1.0` (see [release workflow](.github/workflows/release.yml)).
- **CI artifacts** — Every push to `main` and each pull request also produces per-arch artifacts in the [Build Linux agent](https://github.com/ghostpsy/agent-linux/actions/workflows/build.yml) workflow runs (`ghostpsy-linux-amd64`, `ghostpsy-linux-arm64`, `ghostpsy-linux-386`, plus **SHA256SUMS**).

Binaries are built with `CGO_ENABLED=0` (static; no glibc version lock-in to the build machine).

## Why open source

- **Trust:** Security and ops teams can read what runs on the server.
- **Reproducible builds:** CI builds **linux/amd64**, **linux/arm64**, and **linux/386** with published checksums.
- **Clear scope:** Collectors target the **ingest v1** contract (JSON shape aligned with the Ghostpsy product).

## What it does (and does not do)

| Does | Does not |
|------|----------|
| Reads local OS metadata, listeners, firewall hints, package update summaries, selected host facts | Run as a long-lived daemon (one-shot `scan` by default) |
| Shows a **full outbound JSON preview**; send only after you confirm | Send without confirmation in interactive `scan` |
| Uses **HTTPS** to your API | Store your ingest token in this repository |

## Requirements

- **OS:** Linux only (`GOOS=linux` in release builds).
- **API:** A Ghostpsy deployment with `POST /v1/ingest` and dashboard- or CLI-minted ingest tokens.
- **Permissions:** Some collectors need elevated access; **root** is typical for server audits.

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
