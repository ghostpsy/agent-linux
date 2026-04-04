# Ghostpsy — Linux agent

[![Build Linux agent](https://github.com/ghostpsy/agent-linux/actions/workflows/build.yml/badge.svg)](https://github.com/ghostpsy/agent-linux/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Open-source** Go agent for [Ghost Server Autopsy](https://github.com/edyan/ghostpsy): it collects an **allowlisted** snapshot of a Linux host (OS, listeners, packages, SSH posture, time skew hints, and more), lets the operator **preview the JSON payload**, then posts it to your Ghostpsy API with a **one-time ingest token**.

You can read every line of collector code here before you run the binary on production servers.

## Why open source

- **Trust:** Security and ops teams can audit what runs on the box.
- **Reproducible builds:** CI publishes static Linux binaries for **amd64**, **arm64**, and **386** with checksums.
- **No hidden behavior:** Collection scope is implemented in `internal/collect/` against a versioned ingest contract (`ingest.v1` in the main Ghostpsy repo).

## What it does (and does not do)

| Does | Does not |
|------|----------|
| Reads local OS metadata, listeners, firewall hints, package update summaries, selected host facts | Run continuously as a daemon (one-shot `scan` by default) |
| Shows a **full outbound JSON preview**; send only after explicit confirmation | Send data without confirmation when using interactive `scan` |
| Uses **HTTPS** to your configured API URL | Store your ingest token in this repository |

## Requirements

- **OS:** Linux (the codebase is Linux-only; `GOOS=linux` in CI and release builds).
- **API:** A Ghostpsy backend that exposes `POST /v1/ingest` and issues **ingest bearer tokens** from the dashboard or CLI (see main product docs).
- **Permissions:** Some collectors inspect networking and systemd; running as **root** matches typical server audit expectations.

## Quick start (from source)

```bash
git clone https://github.com/ghostpsy/agent-linux.git
cd agent-linux
make test
make build
./bin/ghostpsy help
./bin/ghostpsy scan -dry-run
```

Set `GHOSTPSY_API_URL` and `GHOSTPSY_INGEST_TOKEN` (or your deployment’s equivalents) when you run a real `scan`.

## Prebuilt binaries

1. **GitHub Actions** — On each push to `main` and on pull requests, the [Build Linux agent](https://github.com/ghostpsy/agent-linux/actions/workflows/build.yml) workflow uploads per-arch artifacts (`ghostpsy-linux-amd64`, `ghostpsy-linux-arm64`, `ghostpsy-linux-386`) plus **SHA256SUMS**.
2. **Releases** — Tag `v*` (example: `v0.1.0`) to trigger a [Release](https://github.com/ghostpsy/agent-linux/actions/workflows/release.yml) that attaches the same binaries and `SHA256SUMS` to the GitHub release.

Verify after download:

```bash
sha256sum -c SHA256SUMS
chmod +x ghostpsy_*_linux_amd64   # or arm64 / 386
./ghostpsy_*_linux_amd64 help
```

Binaries are built with `CGO_ENABLED=0` (static; suitable for older glibc userspace).

## Configuration (environment)

| Variable | Purpose |
|----------|---------|
| `GHOSTPSY_API_URL` | Base URL of the Ghostpsy API (e.g. `https://app.example.com`) |
| `GHOSTPSY_INGEST_TOKEN` | Bearer token for `POST /v1/ingest` |

Exact behavior of pairing and tokens is documented in the main Ghostpsy repository (`docs/`).

## Module path

Go module: **`github.com/ghostpsy/agent-linux`**

The [Ghostpsy monorepo](https://github.com/edyan/ghostpsy) vendors this tree as a **git submodule** at `agent-linux/` so Docker, CI, and local dev stay aligned.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
