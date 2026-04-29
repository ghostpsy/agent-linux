# Ghostpsy — Linux agent

[![Build Linux agent](https://github.com/ghostpsy/agent-linux/actions/workflows/build.yml/badge.svg)](https://github.com/ghostpsy/agent-linux/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**Open-source** Go agent for **Ghostpsy**: it collects an **allowlisted** snapshot of a Linux host (OS, listeners, packages, SSH posture, time skew hints, and more), shows a **full JSON preview**, then posts to **Ghostpsy Cloud API** with a long-lived agent credential stored at `/etc/ghostpsy/agent.conf`.

You can audit every collector under `internal/collect/` before you run the binary.

## Install (recommended)

The dashboard's **+ Add machine** modal walks through three commands. `run-agent.sh` is the install-only step that downloads the correct binary for your CPU (**amd64**, **arm64**, or **i386**), verifies its SHA256 against the GitHub Release, and writes it to `/usr/local/bin/ghostpsy`. It does **not** register the host. After it finishes, you call `ghostpsy register` directly.

The install script needs `bash`, `curl`, and `sha256sum` or `shasum`, and must run as **root** (or via `sudo`).

**1. Mint a bootstrap** in the dashboard at **[https://app.ghostpsy.com](https://app.ghostpsy.com)** → **+ Add machine**. The token is valid for **24 hours and one register call**.

**2. Run the three steps on the server:**

```bash
# Step 1: export the bootstrap token in your shell
export GHOSTPSY_BOOTSTRAP_TOKEN="<bootstrap>"

# Step 2: install /usr/local/bin/ghostpsy (download + SHA256 verify)
curl -fsSL https://raw.githubusercontent.com/ghostpsy/agent-linux/main/run-agent.sh | sudo bash

# Step 3: register this host with the API (runs the first scan, stores the
# long-lived agent token at /etc/ghostpsy/agent.conf, mode 0600)
sudo ghostpsy register --bootstrap="$GHOSTPSY_BOOTSTRAP_TOKEN"
```

`ghostpsy register` targets `https://api.ghostpsy.com` by default. Override with `GHOSTPSY_API_URL` for self-hosted or local-dev deployments.

| Variable | Purpose |
|----------|---------|
| `GHOSTPSY_BOOTSTRAP_TOKEN` | 24h single-use bootstrap consumed by `ghostpsy register` |
| `GHOSTPSY_API_URL` | Override the API base URL (default `https://api.ghostpsy.com`) |

## Recurring scans

The install does **not** schedule a scan. To enable one:

```bash
sudo ghostpsy cron install            # weekly (default)
sudo ghostpsy cron install --schedule=daily
sudo ghostpsy cron status
sudo ghostpsy cron remove
```

This installs a **systemd timer** when systemd is detected, falling back to `/etc/cron.d/ghostpsy`. Each scheduled run executes `ghostpsy scan --yes` with the agent token in `/etc/ghostpsy/agent.conf`.

## Manual scans

```bash
sudo ghostpsy scan --dry-run    # preview only, nothing sent
sudo ghostpsy scan --yes        # send to the API non-interactively
sudo ghostpsy scan              # send after interactive confirmation
```

## Without the bash wrapper

Download **`ghostpsy_<version>_linux_<arch>`** and **`SHA256SUMS`** from [Releases](https://github.com/ghostpsy/agent-linux/releases/latest), verify with `sha256sum -c SHA256SUMS`, then:

```bash
sudo install -m 0755 ghostpsy_*_linux_amd64 /usr/local/bin/ghostpsy
sudo ghostpsy register --bootstrap="<bootstrap>"
sudo ghostpsy cron install
```

## Prebuilt binaries and releases

Static builds for **linux/amd64**, **linux/arm64**, and **linux/i386** are published on [GitHub Releases](https://github.com/ghostpsy/agent-linux/releases), each with a **SHA256SUMS** file.

## Why open source

- **Trust:** security and ops teams can read what runs on the server.
- **Reproducible builds:** published release binaries are static (`CGO_ENABLED=0`) with checksums.
- **Clear scope:** collectors follow the **ingest v1** contract used by Ghostpsy Cloud.

## What it does (and does not do)

| Does | Does not |
|------|----------|
| Reads local OS metadata, listeners, firewall hints, package update summaries, selected host facts | Run as a long-lived daemon (cron / systemd timer fires `scan --yes`) |
| Shows a **full outbound JSON preview**; send only after you confirm in interactive mode | Send without confirmation when running interactively |
| Uses **HTTPS** to Ghostpsy Cloud API | Store your token in this repository |
| Stores the agent token at `/etc/ghostpsy/agent.conf` (mode `0600`) | Echo the token to logs, `ps`, or environment after install |

## Collector coverage by release

Optional ingest blocks (e.g. Apache `apache_httpd_posture`) depend on what is installed on the host. A **version matrix** is maintained in the Ghostpsy docs: **[agent-linux collector coverage](https://github.com/ghostpsy/ghostpsy/blob/main/internal-doc/agent-linux-collector-coverage.md)**.

## Requirements

- **OS:** Linux only (`GOOS=linux` in release builds).
- **Account:** **[https://app.ghostpsy.com](https://app.ghostpsy.com)** — sign in to mint a 24h bootstrap.
- **Privileges:** install and scan run as **root** (or via `sudo`) so `/etc/ghostpsy/agent.conf` (mode `0600`) is readable.

## Build from source

```bash
git clone https://github.com/ghostpsy/agent-linux.git
cd agent-linux
make test
make build
./bin/ghostpsy help
./bin/ghostpsy scan --dry-run
```

## Module path

Go module: **`github.com/ghostpsy/agent-linux`**

## License

Apache License 2.0 — see [LICENSE](LICENSE).
