# Deploying the VEN server

These steps put `ven server` on the existing VPS (`traceiq@162.35.112.175`) next to TraceIQ,
behind the Caddy that already serves 80/443. VEN listens only on `127.0.0.1:4100`, with its
files in `/home/traceiq/ven`. TraceIQ's setup is not changed.

Files in this folder:

| File | Goes to |
| --- | --- |
| `ven.service` | `/etc/systemd/system/ven.service` |
| `env.example` | `/home/traceiq/ven/env` (edit it; `chmod 600`) |
| `Caddyfile.snippet` | add its block to the existing Caddyfile |
| `backup.sh` | `/home/traceiq/ven/backup.sh` (nightly cron) |

## 1. Point the domain

The server lives at `ven.traceiq.run`. Where `traceiq.run`'s DNS is managed (Vercel → Domains →
`traceiq.run`), add an **A record**: name `ven`, value `162.35.112.175`. This does not affect
`traceiq.run` itself. Check with `nslookup ven.traceiq.run`.

## 2. Register a GitHub OAuth app (free, about 2 minutes)

GitHub → Settings → Developer settings → **OAuth Apps** → **New OAuth App**:

| Field | Value |
| --- | --- |
| Application name | `VEN` |
| Homepage URL | `https://ven.traceiq.run` |
| Authorization callback URL | `https://ven.traceiq.run/auth/callback` (unused by the CLI, but required) |
| **Enable Device Flow** | **ticked** (required: `ven login` uses it) |

Click **Register application** and copy the **Client ID**. VEN needs **no client secret**
and asks GitHub for **no scopes**: it only reads your public profile to learn who you are.

## 3. Get the Linux binary

Once a release exists (see "Releasing" in the main README), download it straight on the VPS:

```bash
ssh traceiq@162.35.112.175
cd ~/ven
V=v0.2.0   # the release tag
curl -fsSLO https://github.com/enigma-137/ven/releases/download/$V/ven_${V#v}_linux_amd64.tar.gz
curl -fsSLO https://github.com/enigma-137/ven/releases/download/$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS && tar -xzf ven_${V#v}_linux_amd64.tar.gz
mv ven_${V#v}_linux_amd64/ven ./ven && rm -rf ven_${V#v}_linux_amd64* SHA256SUMS
exit
scp deploy/ven.service deploy/env.example deploy/backup.sh traceiq@162.35.112.175:/home/traceiq/ven/
```

Or build it yourself on your Windows machine, in the repository (PowerShell):

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -trimpath -ldflags "-s -w" -o ven-linux ./cmd/ven
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED
scp ven-linux traceiq@162.35.112.175:/home/traceiq/ven/ven
scp deploy/ven.service deploy/env.example deploy/backup.sh traceiq@162.35.112.175:/home/traceiq/ven/
```

(Check the VPS architecture first with `ssh traceiq@162.35.112.175 uname -m`: `x86_64` means
`amd64` as above, `aarch64` means `GOARCH=arm64`.)

## 4. Configure and start on the VPS

```bash
ssh traceiq@162.35.112.175
cd ~/ven
chmod 700 ven backup.sh
mv env.example env && chmod 600 env
nano env                      # paste the GitHub Client ID into VEN_GITHUB_CLIENT_ID

sudo cp ven.service /etc/systemd/system/ven.service
sudo systemctl daemon-reload
sudo systemctl enable --now ven
systemctl status ven          # should say active (running)
curl -s http://127.0.0.1:4100/v1/health    # {"status":"ok"}
```

`ven.service` caps VEN at 256 MB of memory and half a CPU so it can never slow TraceIQ down.

## 5. Add the Caddy site

Find the Caddyfile (usually `/etc/caddy/Caddyfile`; `systemctl cat caddy` shows the path),
append the block from `Caddyfile.snippet` with your domain, then:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
curl -s https://ven.traceiq.run/v1/health   # {"status":"ok"} with a valid certificate
```

Caddy gets the TLS certificate automatically once DNS points at the VPS.

## 6. Backups

```bash
sudo apt install -y sqlite3   # if missing
crontab -e                    # add:  17 3 * * * /home/traceiq/ven/backup.sh
```

Backups contain only ciphertext and metadata. Copy `~/ven/backups` off the VPS from time to
time (e.g. `scp` to your machine).

## 7. Try it

On your machine:

```bash
ven login --server https://ven.traceiq.run
ven remote create "My App"
ven link my-app -e development
ven push --from .env
ven share --to some-github-user --env development
```

## Updating

Build and `scp` a new `ven-linux` to `~/ven/ven.new`, then on the VPS:
`mv ~/ven/ven.new ~/ven/ven && sudo systemctl restart ven`. Database migrations run
automatically on start.

## Logs

`journalctl -u ven -f`. The unit runs with `--quiet`; remove it in `ven.service` to log one line
per request (IP, method, path, status). Logs never contain values or tokens.
