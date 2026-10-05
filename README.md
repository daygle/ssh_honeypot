## Quick start (Debian 13)

Install Docker first. Docker's official apt repository:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER && newgrp docker
```

Or Docker's convenience script (same result, fewer steps):

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker
```

Then clone and run:

```bash
git clone <this repo> ssh_honeypot && cd ssh_honeypot
```

The honeypot takes host port **22**. Before starting it, move your real SSH daemon off 22 (keep your current SSH session open the whole time):

```bash
sudo nano /etc/ssh/sshd_config      # set: Port 2222
sudo systemctl restart ssh
sudo ufw allow 2222/tcp             # if you use a firewall
ssh -p 2222 youruser@your-server    # verify from a second terminal
```

Only then start the honeypot:

```bash
docker compose up -d --build   # from the ssh_honeypot checkout
docker compose logs -f
```

Run it as a normal user, not root: with Docker group membership on the Debian 13 host, the container binds port 22 itself, and running as root offers no advantage and exposes you to a real lockout if you turn on port 22 without moving sshd.

Dashboard: `http://your-server:8080`.

Stop / remove:

```bash
docker compose down          # keeps the data volume
docker compose down -v       # also wipes recorded history
```

## Updating

Pull the new code and rebuild the image:

```bash
cd ssh_honeypot
git pull
docker compose build         # required: a restart alone keeps the old image
docker compose up -d
```

The rebuild is the part people skip. `docker compose restart` reuses the image
that is already built, so it keeps running the old code - and after a
`requirements.txt` bump it keeps running the old dependencies too. Only
`docker compose build` picks up a new Dockerfile, changed app code or new pins.

Recorded events live in the `daygle-data` volume and survive the recreate.
Nothing in the project runs schema migrations; `init_db` only issues
`CREATE TABLE IF NOT EXISTS`, so an update never needs a migration step.

Confirm the new version actually came up:

```bash
curl -s localhost:8080/healthz
docker compose logs | grep "honeypot listening on"
```

`/healthz` is not enough on its own - it reports ok whenever the web process
answers, and a honeypot that failed to bind its port still answers. The
`honeypot listening on` line is what proves the decoy is listening.

To roll back, check out the previous commit and rebuild:

```bash
git log --oneline -3         # find the sha you want
git checkout <sha>
docker compose build && docker compose up -d
```

## What to run before starting

1. Move real sshd to 2222 and verify a login on the new port from a second terminal.
2. On the Debian 13 host, run `docker compose up -d --build` as your normal user.
3. Open `http://your-server:8080` for the dashboard, or `http://your-server:8080/ssh-blocklist.txt` for the IP list.

## Development

Without Docker, the app runs as a normal user with a high port for the decoy listener:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest                      # DB, honeypot and dashboard tests
HONEYPOT_PORT=2222 python -m app
```

## Configuration

Environment variables (set under `environment:` in `docker-compose.yml`):

| Variable | Default | Purpose |
|---|---|---|
| `HONEYPOT_HOST` | `0.0.0.0` | Address the decoy SSH service binds to |
| `HONEYPOT_PORT` | `22` | Port the decoy SSH service listens on |
| `HONEYPOT_BANNER` | `OpenSSH_8.9p1 Ubuntu-3ubuntu0.6` | Banner shown to scanners, without the `SSH-2.0-` prefix (asyncssh adds that) |
| `HONEYPOT_ENABLED` | `1` | Set `0` to run the dashboard alone |
| `WEB_HOST` | `0.0.0.0` | Address the dashboard binds to |
| `WEB_PORT` | `8080` | Dashboard port |
| `DATA_DIR` | `/data` in Docker, `./data` otherwise | Where SQLite + host key are stored |
| `DB_PATH` | `$DATA_DIR/honeypot.db` | SQLite database file |
| `HOST_KEY_PATH` | `$DATA_DIR/host_key` | Decoy SSH host key (generated on first start) |

Captured usernames and banners are capped at 512 characters, and CSV exports prefix cells that would be evaluated as spreadsheet formulas with `'`.
