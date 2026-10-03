# Daygle SSH Honeypot

[![CI](https://github.com/daygle/ssh_honeypot/actions/workflows/ci.yml/badge.svg)](https://github.com/daygle/ssh_honeypot/actions/workflows/ci.yml)
[![Docker Publish](https://github.com/daygle/ssh_honeypot/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/daygle/ssh_honeypot/actions/workflows/docker-publish.yml)

A self-hosted SSH honeypot that records every connection attempt to your server and
publishes the results as a live HTML dashboard.

This is a **total refactor** of the old journalctl/PHP/MariaDB stack. The old flow
scanned `journalctl` on a cron schedule and truncated a MySQL table every run; this
version *is* the attacker's destination: a decoy SSH service on port 22 captures the
source IP, client banner and credential guesses the moment they arrive, stores them
in SQLite, and the dashboard renders them live. No cron, no MySQL, no PHP, no data
loss between runs, and nothing to migrate.

---

## How it works

```
 internet scanners ──▶ port 22 ──▶ decoy SSH (asyncssh) ──▶ events ──▶ SQLite (volume)
                                                                  ▲
 browser ──▶ port 8080 ──▶ FastAPI dashboard / API ───────────────┘
```

Both services run in **one container** from **one `docker compose up`**:

- **Honeypot** - an `asyncssh` server that looks like OpenSSH, advertises a plausible
  banner, accepts every connection, records every credential guess, and then refuses
  authentication *always*. It never opens a shell and never grants access.
- **Dashboard** - a FastAPI + Jinja2 page with probe volume, unique IPs, top offenders,
  recent activity, and an SSH blocklist feed you can pipe into a firewall.

Every TCP connection is recorded at connect time, so even non-SSH garbage probes
(port scanners, vulnerability sweeps) show up with their source IP.

---

## ⚠️ Port 22 cutover - read before starting

The honeypot takes **host port 22**. If your real SSH daemon is still on 22 when you
start this, either the honeypot won't bind or - worse - you move your own access out
of the way without a replacement. Do it in this order, **keeping your current SSH
session open the whole time**:

1. Move the real SSH daemon to another port:

   ```bash
   sudo nano /etc/ssh/sshd_config      # set: Port 2222
   sudo systemctl restart ssh
   sudo ufw allow 2222/tcp             # if you use a firewall
   ```

2. **Verify** you can log in on the new port from a *second* terminal before
   closing anything:

   ```bash
   ssh -p 2222 youruser@your-server
   ```

3. Only then start the honeypot (below). It binds 22; your real SSH stays on 2222.

Prefer to leave sshd on 22? Change the mapping in `docker-compose.yml`
(`"2222:22"`) and point scanners at the decoy port instead.

---

## Quick start

```bash
git clone <this repo> && cd ssh_honeypot
docker compose up -d --build
```

Dashboard: `http://your-server:8080`

Prefer a prebuilt image? CI publishes one to GitHub Container Registry on every push
to `main` and every `v*` tag. Replace `build: .` in `docker-compose.yml` with:

    image: ghcr.io/daygle/ssh_honeypot:latest

State (SQLite DB + generated SSH host key) lives in the `daygle-data` Docker
volume, so rebuilds and upgrades never lose history.

Stop / remove:

```bash
docker compose down          # keeps the data volume
docker compose down -v       # also wipes recorded history
```

---

## Configuration

Environment variables (set under `environment:` in `docker-compose.yml`):

| Variable | Default | Purpose |
|---|---|---|
| `HONEYPOT_PORT` | `22` | Port the decoy SSH service listens on |
| `HONEYPOT_BANNER` | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` | Banner shown to scanners |
| `HONEYPOT_ENABLED` | `1` | Set `0` to run the dashboard alone |
| `WEB_PORT` | `8080` | Dashboard port |
| `DATA_DIR` | `/data` | Where SQLite + host key are stored |

---

## Dashboard & API

| URL | What it shows |
|---|---|
| `/` | Live HTML dashboard (auto-refreshes every 30s) |
| `/api/stats` | JSON summary: counters, top IPs, hourly volume, recent events |
| `/api/ips` | JSON per-IP aggregates (connections, auth attempts, first/last seen) |
| `/ssh-blocklist.txt` | Unique source IPs, one per line - same shape as the old page |
| `/export.csv` | Full event history as CSV |
| `/healthz` | Health probe |

### Feeding your firewall

```bash
# ufw: block every IP the honeypot has seen
for ip in $(curl -s http://localhost:8080/ssh-blocklist.txt); do sudo ufw deny from "$ip"; done
```

The text endpoint is deliberately plain, so it also drops straight into fail2ban
filters, cron pulls, or any automation that used the old page.

---

## Development (without Docker)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest                      # DB, honeypot and dashboard tests
HONEYPOT_PORT=2222 python -m app
```

The app runs without binding privileges in dev: set `HONEYPOT_PORT` to a high port
(or `HONEYPOT_ENABLED=0` for the dashboard only).

---

## Continuous Integration

GitHub Actions workflows (`.github/workflows/`):

- **CI** - runs on every push and pull request: the full test suite on Python 3.10,
  3.11 and 3.12, plus a Docker job that validates `docker-compose.yml`, builds the
  image and smoke-tests the dashboard, health endpoint and SSH blocklist feed inside the
  running container.
- **Docker Publish** - on pushes to `main` and `v*` tags, builds and publishes the
  image to GitHub Container Registry as `ghcr.io/daygle/ssh_honeypot`.

Dependabot (`.github/dependabot.yml`) opens weekly update PRs for the Python
dependencies, the Docker base image and the GitHub Actions used by the workflows.

---

## Security notes

- The honeypot **never authenticates** anyone: every password and public key is
  recorded and rejected, and no shell is ever spawned.
- The container runs as an unprivileged user with a read-only filesystem, dropped
  capabilities and `no-new-privileges`.
- The dashboard is intentionally unauthenticated because it contains only honeypot
  data - but if you expose it publicly, put it behind a reverse proxy with TLS
  and access control (e.g. Caddy/nginx + basic auth).
- Recorded passwords are attacker guesses stored as evidence. Treat the export as
  sensitive-ish data and don't reuse it anywhere.

---

## What replaced what

| Old | New |
|---|---|
| `journalctl` cron parser | Decoy SSH service capturing probes directly |
| MySQL (`failed_ips`) + `TRUNCATE` cron | SQLite written in real time |
| `public/index.php` IP list | Live dashboard + `/ssh-blocklist.txt` + JSON API + CSV export |
| Bare-metal LAMP install | One hardened Docker container |
