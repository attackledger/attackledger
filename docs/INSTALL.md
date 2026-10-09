# Installing and running AttackLedger

This guide is for the person who installs and runs AttackLedger on their organisation's
own server. It assumes you know how to use a Linux shell over SSH; it does not assume you
have seen AttackLedger before. Every step is a command you can copy.

AttackLedger is self-hosted: test data never leaves your server (D-042). It runs as a set
of Docker containers:

| Container | What it does |
|---|---|
| `caddy` | HTTPS in front of everything. The only container that listens on the network. |
| `web` | The web app. Forwards `/api/` to the API. |
| `api` | The API and the ledger. Runs database migrations when it starts. |
| `worker` | Runs recon jobs and Claude agent runs. Has no database access: it reaches the API through the gateway ([section 6](#6-traffic-gateway)). |
| `db` | PostgreSQL 16. |
| *gateway* | All traffic to test targets. See [section 6](#6-traffic-gateway). |

Two files in `deploy/` turn the development setup into a production one:
`deploy/compose.prod.yml` (no default passwords, nothing exposed but HTTPS, restart
policies, healthchecks, limits, rotated logs) and `deploy/Caddyfile` (HTTPS).

**Conventions.** Commands are run as root (`sudo -i` first). The install folder is
`/opt/attackledger`, and every `docker compose` command is run inside it, because that is
where it finds its settings (`.env`). Replace `attackledger.example.com` and
`you@example.com` with your own values.

## Contents

1. [What you need](#1-what-you-need)
2. [Install Docker](#2-install-docker)
3. [Get AttackLedger](#3-get-attackledger)
4. [Settings and secrets](#4-settings-and-secrets)
5. [HTTPS](#5-https)
6. [Traffic gateway](#6-traffic-gateway)
7. [Encryption at rest](#7-encryption-at-rest)
8. [Build and start](#8-build-and-start)
9. [Create the first owner](#9-create-the-first-owner)
10. [Add people and give them roles](#10-add-people-and-give-them-roles)
11. [Reviewers' signing keys](#11-reviewers-signing-keys)
12. [Timestamp authority](#12-timestamp-authority)
13. [Where the secrets live](#13-where-the-secrets-live)
14. [Backup and restore](#14-backup-and-restore)
15. [Upgrade and rollback](#15-upgrade-and-rollback)
16. [Monitoring and logs](#16-monitoring-and-logs)
17. [Uninstall and delete the data](#17-uninstall-and-delete-the-data)
18. [Troubleshooting](#18-troubleshooting)
19. [Practise against the lab](#19-practise-against-the-lab)
20. [Trying it on a Mac](#20-trying-it-on-a-mac)

## 1. What you need

**A server.** Ubuntu Server 24.04 LTS (22.04 also works), x86-64 or ARM64, used only for
AttackLedger. To try it on a Mac first, with fictional data, see section 20.

| | Minimum | Comfortable |
|---|---|---|
| CPU | 4 cores | 8 cores |
| Memory | 8 GB | 16 GB |
| Disk | 60 GB | 200 GB |

The images and their build cache take about 15 GB. The rest is the database and the
evidence store, which grow with use; recon output and captured HTTP exchanges are most of
it. Keep backups on another machine (section 14).

**Software.** Docker Engine 24 or later with the Docker Compose plugin **2.24 or later**
(the production file uses `!reset` and `!override`, which older versions reject). Section 2
installs both. Also `git`, `curl` and `openssl`.

**A DNS name** for the server, such as `attackledger.example.com`, that the people who use
it can resolve.

**Network.**

| Direction | To or from | Port | When | Why |
|---|---|---|---|---|
| In | users' browsers | 443 (and 80, which redirects) | always | the web app |
| In | your administrators | 22 | always | SSH |
| Out | Docker Hub, GitHub, the Go module proxy, PyPI, npm, Debian and Alpine mirrors | 443 | install and upgrade only | building the images |
| Out | `timestamp.digicert.com` | 80 | each time a lane is closed | RFC 3161 timestamps; only a SHA-256 hash is sent (section 12) |
| Out | Let's Encrypt (`acme-v02.api.letsencrypt.org`), and port 80 reachable from the internet | 443 | only with Let's Encrypt | certificates (section 5) |
| Out | test targets | as needed | during testing | **only from the gateway container** (section 6) |
| Out | passive recon sources (certificate transparency, web archives and similar; the list is in section 6) | 443, and 80 for the web archive | when the subdomain and archive steps run | recon that sends nothing to the target, **only from the gateway container**, GET only |
| Out | `api.anthropic.com` | 443 | only if Claude agents are turned on | the agent's model, **only from the gateway container** |
| Out | your DNS resolver | 53 | during testing | the gateway resolves target names for the worker, in-scope names only |

Nothing else needs to leave the server. AttackLedger sends no telemetry.

Docker writes its own firewall rules: a published port is reachable even if `ufw` says
it is closed. The production file publishes only Caddy's 80 and 443, so that is all the
network sees. If you use `ufw` for SSH, allow it before you enable it:

```sh
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

## 2. Install Docker

From Docker's own package repository (Ubuntu's `docker.io` package is often too old for
the Compose version this needs).

1. Add Docker's repository:

   ```sh
   apt-get update
   apt-get install -y ca-certificates curl git openssl
   install -m 0755 -d /etc/apt/keyrings
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
   chmod a+r /etc/apt/keyrings/docker.asc
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
   apt-get update
   ```

2. Install Docker and the Compose plugin:

   ```sh
   apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
   ```

3. Check the versions. The Engine must be 24 or later and Compose 2.24 or later:

   ```sh
   docker version --format '{{.Server.Version}}'
   docker compose version
   ```

## 3. Get AttackLedger

1. Clone the repository you were given access to, and check out the release you were
   told to install (here `v0.7.0`):

   ```sh
   REPO_URL=https://github.com/attackledger/attackledger.git
   git clone "$REPO_URL" /opt/attackledger
   cd /opt/attackledger
   git checkout v0.7.0
   ```

2. From now on, work in that folder:

   ```sh
   cd /opt/attackledger
   ```

## 4. Settings and secrets

All settings live in one file, `/opt/attackledger/.env`. It holds secrets, so only root
may read it, and it is never committed (the repository ignores it).

1. Create it from the example and lock it down:

   ```sh
   cp deploy/.env.example .env
   chmod 600 .env
   ```

2. Generate the database password. It is hex on purpose: it is also part of a database URL,
   where other characters would need escaping.

   ```sh
   sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 32)/" .env
   ```

3. Set the server's name:

   ```sh
   sed -i "s/^ATTACKLEDGER_HOSTNAME=.*/ATTACKLEDGER_HOSTNAME=attackledger.example.com/" .env
   ```

4. Choose where the HTTPS certificate comes from in [section 5](#5-https), which sets
   `ATTACKLEDGER_TLS`.

5. Optional: an operator token, only if you will script against the API. It acts as an
   owner (it cannot sign receipts), so leave it empty if you do not need it:

   ```sh
   sed -i "s/^ATTACKLEDGER_API_TOKEN=.*/ATTACKLEDGER_API_TOKEN=$(openssl rand -hex 32)/" .env
   ```

6. Optional: Claude agents. Put an Anthropic API key in `ANTHROPIC_API_KEY` (edit `.env`
   with `nano .env`). The key is passed to the gateway only, which adds it to the agent's
   calls to the Claude API; the worker, where the recon tools run, never has it. Without it,
   everything except agent runs works.

7. Check that Compose can read the settings. It prints nothing when they are complete,
   and names the missing one otherwise:

   ```sh
   docker compose config --quiet
   ```

`.env` also sets `COMPOSE_FILE` and `COMPOSE_PROJECT_NAME`, so that every
`docker compose` command in this folder uses the production file and the same project
name. Do not remove those two lines.

## 5. HTTPS

Caddy terminates HTTPS and renews certificates by itself. HTTPS is not optional: the
session cookie is sent only over HTTPS, and browsers create reviewers' signing keys only
on secure pages. Choose one of the options and run its commands.

| Option | Suitable for |
|---|---|
| A. Let's Encrypt | a server with a public DNS name. Real work. |
| B. Your organisation's certificate | internal names, or when policy requires your own CA. Real work. |
| C. Caddy's internal CA | a test install that several people reach over the network, when A and B are not possible yet. Everyone must trust Caddy's root first. |
| D. Plain HTTP on `attackledger.localhost`, over an SSH tunnel | a trial by one or a few people with fictional data. Nothing is reachable from the network. |

For client work use A or B.

**Option A: Let's Encrypt.** The DNS name must resolve to this server from the internet,
and port 80 must be reachable from the internet. The email address receives expiry
warnings.

```sh
sed -i "s|^ATTACKLEDGER_TLS=.*|ATTACKLEDGER_TLS=you@example.com|" .env
```

**Option B: your organisation's own certificate.** For internal names, or when your
policy requires your own CA. You need the certificate with its chain (server certificate
first, then intermediates) and its private key, both PEM:

```sh
cp /path/to/fullchain.pem deploy/certs/fullchain.pem
cp /path/to/privkey.pem deploy/certs/key.pem
chmod 600 deploy/certs/key.pem
sed -i "s|^ATTACKLEDGER_TLS=.*|ATTACKLEDGER_TLS=/certs/fullchain.pem /certs/key.pem|" .env
```

When you renew it, replace the two files and run `docker compose restart caddy`.

**Option C: Caddy's internal CA, for a test install.** Caddy creates its own certificate
authority and issues the server's certificate from it. Until a machine trusts that
authority's root, its browsers block the page with a certificate error (for example
`NET::ERR_CERT_AUTHORITY_INVALID` or `SEC_ERROR_UNKNOWN_ISSUER`), and there is no safe way
to click through it.

```sh
sed -i "s|^ATTACKLEDGER_TLS=.*|ATTACKLEDGER_TLS=internal|" .env
```

After section 8, trust the root on each machine that opens AttackLedger:

1. On the server, copy the root certificate out and print its fingerprint:

   ```sh
   cd /opt/attackledger
   docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./caddy-root.crt
   openssl x509 -in caddy-root.crt -noout -subject -fingerprint -sha256
   ```

   The subject is `CN=Caddy Local Authority - <year> ECC Root`. The root is valid for ten
   years.

2. Copy `caddy-root.crt` to the user's machine (for example
   `scp admin@attackledger.example.com:/opt/attackledger/caddy-root.crt .`). On that
   machine, check that the fingerprint matches the one the server printed before you trust
   it (`openssl x509 -in caddy-root.crt -noout -fingerprint -sha256`, or the certificate's
   details window).

3. Trust it, for the machine's operating system:

   - **macOS** (Safari, Chrome, Edge). In Terminal:

     ```sh
     sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain caddy-root.crt
     ```

     Or in Keychain Access: drag the file into **System**, open it, expand **Trust** and
     set **When using this certificate** to **Always Trust**.
   - **Windows** (Edge, Chrome). In a Command Prompt run as administrator:

     ```bat
     certutil -addstore -f Root caddy-root.crt
     ```

     Or double-click the file, **Install Certificate**, **Local Machine**, **Place all
     certificates in the following store**, **Trusted Root Certification Authorities**.
   - **Ubuntu** (the system store, used by `curl`, Python and most tools):

     ```sh
     sudo cp caddy-root.crt /usr/local/share/ca-certificates/attackledger-caddy-root.crt
     sudo update-ca-certificates
     ```

     Chrome and Chromium on Linux read their own store as well. Add the root there too
     (`sudo apt-get install -y libnss3-tools` first):

     ```sh
     certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "AttackLedger Caddy root" -i caddy-root.crt
     ```

   - **Firefox**, on any system, keeps its own list: **Settings**, **Privacy & Security**,
     **Certificates**, **View Certificates**, **Authorities** tab, **Import**, choose
     `caddy-root.crt`, tick **Trust this CA to identify websites**, **OK**.

4. Restart the browser and open `https://attackledger.example.com`.

A trusted root can vouch for any website on that machine, and its private key is on the
AttackLedger server (in the `caddy_data` volume). Trust it only on machines that need it,
and remove it when the test ends: on macOS delete it in Keychain Access, on Windows run
`certutil -delstore Root "Caddy Local Authority - <year> ECC Root"`, on Ubuntu delete the
file and run `sudo update-ca-certificates --fresh`, and in Firefox delete it in
**Authorities**. The root changes if the `caddy_data` volume is lost; section 14 says how
to keep it.

**Option D: plain HTTP on `attackledger.localhost`, for a trial.** Nothing to trust and no
DNS name to set up. Caddy serves plain HTTP on the server's loopback address only, and each
user reaches it through an SSH tunnel. Browsers treat `http://*.localhost` as a secure page,
so the HTTPS-only session cookie and reviewers' signing keys work. Use it only for a trial
with fictional data: everyone who uses it needs SSH access to the server.

1. Set the name with `http://` in front, and publish the ports on the loopback address only
   (replace the step 3 value of `ATTACKLEDGER_HOSTNAME` from section 4):

   ```sh
   sed -i "s|^ATTACKLEDGER_HOSTNAME=.*|ATTACKLEDGER_HOSTNAME=http://attackledger.localhost|" .env
   sed -i "s|^ATTACKLEDGER_TLS=.*|ATTACKLEDGER_TLS=internal|" .env
   sed -i "s|^ATTACKLEDGER_HTTP_PORT=.*|ATTACKLEDGER_HTTP_PORT=127.0.0.1:80|" .env
   sed -i "s|^ATTACKLEDGER_HTTPS_PORT=.*|ATTACKLEDGER_HTTPS_PORT=127.0.0.1:443|" .env
   ```

   (`ATTACKLEDGER_TLS=internal` is only there because the setting may not be empty; with an
   `http://` name Caddy issues no certificate.)

2. After section 8, each user opens a tunnel from their own machine and leaves it open:

   ```sh
   ssh -N -L 8080:127.0.0.1:80 admin@attackledger.example.com
   ```

3. They open `http://attackledger.localhost:8080` in Chrome or Edge.

Signing in, staying signed in and creating a signing key were tested this way in Chromium,
the engine of Chrome and Edge. Firefox and Safari also treat `*.localhost` as a secure page,
but were not tested; if signing in there sends you back to the sign-in page, use Chrome or
Edge. A reviewer's signing key belongs to the exact address, port included,
so keep the same local port (`8080`) each time. To move on to real work, choose A or B, set
`ATTACKLEDGER_HOSTNAME` to the real name, reset the two ports to `80` and `443`, and run
`docker compose up -d --wait`. Reviewers then get new keys on the new address (section 11).

**Other ports.** If ports 80 and 443 are taken on the server, set `ATTACKLEDGER_HTTP_PORT`
and `ATTACKLEDGER_HTTPS_PORT` in `.env` (Let's Encrypt needs port 80 itself). With another
HTTPS port, give people the address with the port, such as
`https://attackledger.example.com:8443`. Caddy's redirect from HTTP does not know the port
Docker publishes, so `http://attackledger.example.com:8080` sends the browser to
`https://attackledger.example.com/` without the port, where nothing answers.

## 6. Traffic gateway

Every request that recon tools and Claude agents send leaves through one gateway container
(D-039, `docs/GATEWAY.md`). The worker has no route to the internet and no database access
(D-042, `docs/WORKER_API.md`): it sits on the internal-only Docker network `internal` with the
gateway and nothing else. The gateway is its only way out, for traffic to targets and for its
own calls to the API, which the gateway relays (port 8081, `/worker/*` routes only). The
gateway enforces, in one place, each engagement's scope (exclusions win), read-only methods
(GET, HEAD, OPTIONS; every write is refused), rate ceiling, research header and user agent,
never follows redirects, and logs every request.

| Network | Containers | Why |
|---|---|---|
| `internal` | worker, gateway | the worker's only network: the gateway's proxy, resolver and relay |
| `control` | gateway, api | rules and the request log for the gateway; the worker's relayed calls |
| `database` | db, api | only the API reaches the database |
| `lab` | gateway, lab, lab-proxy | the practice target (section 19) |
| `default` | api, web, gateway, caddy (and lab-proxy, when the lab runs) | the way out: the timestamp authority, targets, Caddy; the published ports |

All but `default` are `internal: true` in Docker: nothing on them has a route out.

- **Outbound firewall.** Only the gateway needs to reach targets, passive recon sources and
  the Claude API; it is the only container on both `internal` and the outside network
  (`default`, with the API, the web app and Caddy). If your network filters outbound traffic,
  allow from this server: the targets of your engagements; the passive sources the
  subdomain and archive steps use (`gateway.PASSIVE_HOSTS` in `server/app/gateway.py`:
  certificate transparency, web archives and similar; HTTPS, and HTTP for the web archive);
  `api.anthropic.com` on 443 if you run agents; and DNS. Passive sources and the Claude API
  are allowlisted inside the gateway, GET only for passive sources, and are not counted
  against an engagement's rate.
- **The gateway's CA.** To check the method and headers of HTTPS requests, the gateway
  terminates TLS with a certificate authority it creates on first start. The private key is
  in the volume `gateway-private` (mounted by the gateway only); the certificate is copied
  to `gateway-public`, which only the worker mounts, read-only. It needs no backup: a lost CA
  is replaced by a new one on the next start. To replace it, stop the stack, remove both
  volumes (`docker volume rm attackledger_gateway_private attackledger_gateway_public`, with your `COMPOSE_PROJECT_NAME` if you changed it) and start
  again.
- **The gateway token.** The gateway gets each job's rules from the API and writes its
  request log there, with a token it creates in the volume `gateway-control` (shared with the
  API only). To set your own instead, put `ATTACKLEDGER_GATEWAY_TOKEN` in `.env` and pass it
  to both the `api` and `gateway` services.
- **The worker token.** The worker claims jobs with a token it creates on first start in the
  volume `worker-control` (shared with the API only; the gateway relays the calls but never
  stores the token). Each job it claims gets its own token from the API, which opens only that
  job's routes while it runs, and a separate gateway credential for its tools. To set your own
  worker token, put `ATTACKLEDGER_WORKER_TOKEN` in `.env` and pass it to both the `api` and
  `worker` services. Neither volume needs a backup: new tokens are made if they are lost.
- **The Claude API key** (`ANTHROPIC_API_KEY` in `.env`) is passed to the gateway only.
- **Settings** (all optional, in `.env`): `ATTACKLEDGER_GATEWAY_PASSIVE_HOSTS`, extra passive
  source hosts, comma-separated, for subfinder sources you configured with your own keys.
- **Check.** The worker cannot reach the internet or the database directly, and a request
  through the gateway is logged:

  ```sh
  docker compose exec worker python -c "import socket; socket.create_connection(('1.1.1.1', 443), 5)"
  # OSError: [Errno 101] Network is unreachable
  docker compose exec worker python -c "import socket; socket.create_connection(('db', 5432), 5)"
  # socket.gaierror: ... (no network of the worker has the database on it)
  docker compose logs gateway | head -1
  # gateway ready: proxy 0.0.0.0:8080, dns 53, control 8081, api http://api:8000, claude key not set
  ```

  After a recon run, its requests are listed per engagement at
  `GET /api/engagements/<id>/gateway-log` (totals by verdict, kind and method, and the latest
  rows, each allowed or refused with the reason).

## 7. Encryption at rest

Raw evidence (HTTP exchanges, notes, attached files) and evidence summaries are encrypted
with AES-256-GCM, with a key per engagement (D-043, `docs/ENCRYPTION.md`). Each engagement
key is stored wrapped (encrypted) by one **master key** for the deployment, in the blob
store at `<blobs>/e/<engagement id>/key.json`, next to the blobs it protects. When an
engagement's content is deleted, its key and blobs are destroyed: the content becomes
unreadable for good, while the evidence chain, receipts and reports still verify (the
verifier says the content is unavailable and why).

The API refuses to start without a master key. The production file reads it from a file on
the host, `/etc/attackledger/master.key` (or the path in `ATTACKLEDGER_MASTER_KEY_PATH`),
mounted read-only into the API container only, as `ATTACKLEDGER_MASTER_KEY_FILE`. The worker
has no key: everything it produces is encrypted by the API (D-042). If that file cannot be
read, startup fails; there is no fallback to another key.

1. **Create the master key** (256 random bits, base64), readable only by the user the
   API runs as (uid 10001):

   ```sh
   install -m 700 -d /etc/attackledger
   (umask 077; openssl rand -base64 32 > /etc/attackledger/master.key)
   chown 10001 /etc/attackledger/master.key
   chmod 400 /etc/attackledger/master.key
   ```

   This is the same format as `python -m app.vault generate` prints (a file with 64 hex
   digits works too). To keep the key somewhere else, set `ATTACKLEDGER_MASTER_KEY_PATH`
   in `.env` to that path, and use that path wherever this guide says
   `/etc/attackledger/master.key`.

2. **Keep a copy of the master key somewhere else**, such as your organisation's password
   vault or an offline safe, and not next to the backups (section 14 says why). Without
   it, no evidence content can be read again, from the server or from any backup.

3. After section 8, **check** that the API uses it: `/api/health` answers
   `"encryption":{"master_key":"configured"}`. `development` would mean the public
   development key (`ATTACKLEDGER_DEV_KEY=1`, for trials with fictional data only; the
   production file turns it off), `missing` that there is no key.

4. **See what is encrypted**, per engagement:

   ```sh
   docker compose exec api python -m app.vault status
   ```

**Retention.** An owner decides, per engagement, on the engagement's **Team** tab, under
**Data and retention**:
- **Keep the content until (UTC)** a date. The API deletes the content the day after it
  (it checks once a minute).
  No date means the content is kept until someone deletes it.
- **Delete this engagement's data** now, confirmed by typing the engagement's name.

Either way the deletion is an entry in the audit log, and afterwards the engagement takes
no new evidence, jobs or receipts. On the server,
`docker compose exec api python -m app.vault delete-content --engagement <id>` does the
same, recorded as "the operator on the server".

**What deletion removes, and what stays.** Deleted: the engagement's key and its raw
evidence (HTTP exchanges, notes, attached files), the evidence summaries, the recon results
(hosts found, URLs, leads), the recon and agent logs, and the imported entries' URLs and
labels. What stays, in plain text, because the reports and their verification depend on it:
- the evidence chain, with each entry's host, lane, kind, hash and **URL: host, path and
  query string** (secrets in it redacted when it was stored), or an attached file's name;
- the lanes, items and their not-applicable reasons;
- the receipts, their signatures and timestamps;
- the logs: the audit log, the key log and the gateway's request log (method, URL and
  verdict of every request recon and agents sent).

So a URL that names something confidential stays readable after the deletion. Evidence
summaries written before 0.7 (chain record v1) also stay, because the chain covers their
text. The details are in `docs/ENCRYPTION.md`, "What is encrypted".

**Rotating the master key.** Do it when someone who had the key leaves, if you think it
leaked, and after deleting content that must not survive in old backups (see below).

Run the steps in one shell: step 1 sets `KEY` to the key file's path, the one in
`ATTACKLEDGER_MASTER_KEY_PATH` or else the default, and the later steps use it.

1. Find the key file, make the new key next to it, and stop the API and the worker:

   ```sh
   cd /opt/attackledger
   KEY=$(sed -n 's/^ATTACKLEDGER_MASTER_KEY_PATH=//p' .env); KEY=${KEY:-/etc/attackledger/master.key}
   echo "$KEY"
   (umask 077; openssl rand -base64 32 > "$KEY.new")
   docker compose stop api worker
   ```

2. Swap them, so the new key is the configured one and the old one is kept for the
   re-wrap:

   ```sh
   mv "$KEY" "$KEY.old"
   mv "$KEY.new" "$KEY"
   chown 10001 "$KEY" "$KEY.old"
   chmod 400 "$KEY" "$KEY.old"
   ```

3. Re-wrap every engagement key under the new master key (the evidence itself is not
   re-encrypted; only the engagement keys depend on the master key). It ends with
   `re-wrapped <n>, already under <new key id>: <m>`, and can be run again safely:

   ```sh
   docker compose run --rm --no-deps -v "$KEY.old":/run/secrets/old-master-key:ro api python -m app.vault rotate-master --old-key-file /run/secrets/old-master-key
   ```

4. Start again, take a backup under the new key, and keep a copy of the new key
   somewhere else, as for the first one:

   ```sh
   docker compose up -d --wait
   tools/backup.sh /var/backups/attackledger
   ```

5. Destroy the old key (`shred -u "$KEY.old"`, and its stored copy) once you no longer
   need the backups made with it: those backups open only with it.

**Backups and deletion.** A backup holds the wrapped engagement keys that existed when it
was made. Content deleted since can therefore still be recovered from an older backup
together with the master key of that time. To make a deletion final in the backups too,
either keep backups no longer than your retention policy allows, or rotate the master key
after the deletion and destroy the old one.

**Upgrading an install from before encryption (0.6 or earlier).** The API now runs as uid
10001, like the worker. Before the first start of the new version, give the blob store to
that user once, then encrypt the evidence stored before (new evidence is always
encrypted; old evidence stays as it was until you do this):

```sh
docker compose run --rm --user 0 --no-deps api chown -R 10001 /data/blobs
docker compose up -d --wait
docker compose exec api python -m app.vault encrypt-existing
```

## 8. Build and start

1. Build the images. The first build downloads and compiles the recon tools and takes
   10 to 30 minutes:

   ```sh
   docker compose build
   ```

2. Start everything and wait until every container reports healthy. On the first start
   the API creates the database tables:

   ```sh
   docker compose up -d --wait
   ```

3. Check the state. Every container should be `running` and `healthy`:

   ```sh
   docker compose ps
   ```

4. Check HTTPS and the API. With option C, add `--cacert caddy-root.crt`. With option D,
   run `curl -fsS -H 'Host: attackledger.localhost' http://127.0.0.1/api/health` instead.

   ```sh
   curl -fsS https://attackledger.example.com/api/health
   ```

   The answer has `"mode":"setup"`: the API is up and refuses everyone until there is an
   owner. Opening the address in a browser says the same. It also has
   `"encryption":{"master_key":"configured"}` (section 7).

## 9. Create the first owner

A fresh production install lets nobody in (`ATTACKLEDGER_REQUIRE_SIGN_IN=1` in
`deploy/compose.prod.yml`). The first owner is created on the server, by someone with
shell access, so that whoever reaches the web page first cannot make themselves the owner.

1. Create the owner. It asks for a password (at least 12 characters, not shown as you
   type):

   ```sh
   docker compose exec api python -m app.people create --owner --email you@example.com --name "Your Name"
   ```

   For a script, pass the password in an environment variable instead (never as an
   argument, so it stays out of shell history and process lists). Piping it in does not
   work: the prompt discards anything typed before it appears.

   ```sh
   read -rs ATTACKLEDGER_NEW_PASSWORD && export ATTACKLEDGER_NEW_PASSWORD
   docker compose exec -e ATTACKLEDGER_NEW_PASSWORD api python -m app.people create --owner --email you@example.com --name "Your Name"
   unset ATTACKLEDGER_NEW_PASSWORD
   ```

2. Open `https://attackledger.example.com` and sign in with that email and password.

3. Choose your own password: **Your account** (bottom left), **Change your password**. Until
   you do, the key log records your keys as registered "in a session with a password
   someone else set", because a password typed on the server is also known to whoever
   typed it.

The creation is the first entry in the audit log, made by "the operator on the server".

An install is one organization, made by the migrations; there is nothing to set up for it,
and the app never shows it. (Several organizations in one deployment are for a hosted service
later: `docs/ORGANIZATIONS.md`.)

## 10. Add people and give them roles

Owners manage people. Everyone else sees only the engagements they have a role on.

| Role | Can |
|---|---|
| Owner | everything: people, engagements, scope and rules, roles |
| Tester | run recon, work lanes, attach and import evidence |
| Reviewer | sign receipts (close lanes) |
| Viewer (client, auditor) | read coverage, evidence and reports, and verify them |

1. **Add a person:** **People** (bottom left), **Add a person**. You set their first
   password; give it to them through a channel you trust. Tick **Owner** only for people
   who administer AttackLedger.
2. **They choose their own password** at their first sign-in (**Your account**, **Change
   your password**). Nobody can set another person's password through the app (D-036).
3. **Give roles per engagement:** open the engagement, **Team** tab, tick roles, **Save
   team**. On the same tab:
   - **Separation of duties**: whoever attached a lane's evidence cannot sign its receipt.
     Auditors look for this; turn it on for client work.
   - **Require signed receipts**: every receipt needs the reviewer's own key (section 11).
4. **Someone leaves:** **People**, **Disable**. Their sessions end at once. People are
   never deleted, because receipts and the audit log name them.

**The first engagement.** An owner creates it (**New engagement**), sets its scope and
rules, and gives the team their roles. Testers who work in Burp, Caido or a browser bring
their traffic in as an export file (HAR, Burp XML or Caido JSON, up to 50 MB each): it
waits in the engagement's inbox, redacted and checked against the scope, until a person
maps each entry to checklist items.

**Give testers [`docs/TESTER_GUIDE.md`](TESTER_GUIDE.md).** It walks through an engagement
in the app: signing in, the rules, lanes and checklist items, evidence, importing from
Burp, Caido or a browser, and getting lanes signed. `docs/IMPORT.md` is the technical
description of the import formats. To let people practise before a real engagement, start
the bundled practice target (section 19).

On the server, for the cases the app deliberately does not cover:

```sh
# A forgotten password (signs the person out everywhere; they choose a new one after signing in)
docker compose exec api python -m app.people set-password --email someone@example.com
# Every administrative change, and a check that the log's hash chain is intact
docker compose exec api python -m app.people audit-log
```

## 11. Reviewers' signing keys

A reviewer closes a lane by signing its receipt with a key that exists only in their
browser (D-033). Nobody who runs the server, you included, can sign with it.

- **The key is made automatically** the first time the reviewer signs a receipt. The
  browser creates it with WebCrypto as non-extractable (Ed25519, or ECDSA P-256 where
  Ed25519 is missing) and keeps it in that browser profile's storage for this site. The
  server stores only the public key.
- **A new browser, a new computer or cleared site data means a new key.** The old private
  key cannot be copied out. The next signature registers a new key; signatures made with
  the old key stay valid, because every report carries the public key that made each
  signature. The reviewer can revoke the old key under **Your account**, **Your signing
  keys**.
- **Every key registration and revocation is logged** in a hash-chained key log, with
  how it happened. At sign-in, people see keys registered or revoked for them since their
  previous sign-in, and can revoke one they did not make.
- **For high assurance**, the reader of a report compares each signer's key fingerprint
  (shown in the report and under **Your account**) with the one the signer gives them in
  person or by another channel they trust.

On the server:

```sh
# Revoke a key (for example, a lost laptop); 8 or more characters of the fingerprint
docker compose exec api python -m app.people revoke-key --email someone@example.com --fingerprint 6d50ab12
# Every key registration and revocation, and a check of the chain
docker compose exec api python -m app.people key-log
```

Signing needs HTTPS. Over plain HTTP the browser refuses ("Signing needs a secure page").

## 12. Timestamp authority

When a lane closes, the API asks an RFC 3161 timestamp authority (TSA) to timestamp the
receipt. The token proves the receipt existed at that time and has not changed since; the
report carries it and `tools/verify_report.py` checks it offline (D-034).

- **What leaves the server:** one SHA-256 hash per closed lane, over HTTP. No evidence, no
  names.
- **Default:** DigiCert's public service, `ATTACKLEDGER_TSA_URL=http://timestamp.digicert.com`.
  The verifier trusts DigiCert's root out of the box (`tools/tsa-roots/`).
- **Your own TSA** (for example, one your organisation runs): set its URL in `.env`, then
  `docker compose up -d`. Readers of your reports then need its root certificate:
  `python3 tools/verify_report.py report.json --tsa-root your-tsa-root.pem`.
- **No timestamps:** `ATTACKLEDGER_TSA_URL=off`. Nothing is sent; receipts are still signed
  but carry no independent time.
- **If the TSA cannot be reached**, the lane still closes; the lane panel shows "Not
  timestamped" with the reason and a **Timestamp now** button. A later timestamp shows the
  later time.

After changing `.env`, apply it with:

```sh
docker compose up -d --wait
```

**How your clients verify a report.** The independent copies are on attackledger.com: the
page https://attackledger.com/verify checks a report in the browser without uploading it,
and https://attackledger.com/verify_report.py is the offline script. Signed-in people can
also download the script and the TSA roots from this server (Report tab, or
`/api/verifier/attackledger-verifier.zip`). Ask clients to compare its SHA-256 with the
public copy, because a copy from the tester's own server is the weaker source.

The API documentation (`/api/docs`, `/api/openapi.json`) needs sign-in whenever the API
does.

## 13. Where the secrets live

| Secret | Where | Needed for | In the backup |
|---|---|---|---|
| Postgres password | `.env` (`POSTGRES_PASSWORD`) | the API to reach the database | no; a new install makes a new one |
| Operator token (optional) | `.env` (`ATTACKLEDGER_API_TOKEN`) | scripts using the API | no |
| Anthropic API key (optional) | `.env` (`ANTHROPIC_API_KEY`), passed to the gateway only | agent runs | no |
| Encryption master key | `/etc/attackledger/master.key`, or `ATTACKLEDGER_MASTER_KEY_PATH` (section 7), mounted read-only into the API only; never in `.env` | reading any evidence content | **no, kept separately** (its id, a hash, is in `info.txt`) |
| Gateway and worker tokens | the volumes `gateway-control` and `worker-control` (section 6), shared with the API only | the gateway's and the worker's calls to the API | no; new ones are made on the next start |
| Engagement data keys | the blob store, `e/<id>/key.json`, wrapped by the master key | reading one engagement's content | yes (wrapped) |
| People's passwords | the database, as scrypt hashes | signing in | yes (hashes only) |
| Session cookies | the database, as SHA-256 hashes | staying signed in (12 hours) | yes (hashes only) |
| Reviewers' private signing keys | each reviewer's browser only | signing receipts | no, and they never reach the server |
| TLS private key | `deploy/certs/key.pem` (option B) or the `caddy_data` volume (options A and C) | HTTPS | no; re-issue or copy it yourself |
| Caddy's internal CA key (option C) | the `caddy_data` volume | the certificate that users' machines trust | no; copy it yourself (section 14) |

`.env`, `/etc/attackledger/` and `deploy/certs/` are readable by root only (the key file
also by uid 10001, the containers' user). Docker shows environment variables
to anyone who can run `docker inspect`, so membership of the `docker` group is the same as
root on this server: give it to administrators only.

## 14. Backup and restore

A backup has two parts that must be taken together: the **Postgres database** (people,
engagements, the evidence chain, receipts, encrypted summaries, the key and audit logs) and
the **evidence blob store** (the encrypted raw evidence, and each engagement's wrapped data
key). The **master key** (section 7) is kept separately.

Why separately: the backup holds encrypted content plus the engagement keys, wrapped; the
master key is what unwraps them. Stored together, anyone who gets the backup can read every
engagement. Stored apart, a stolen backup alone reveals no evidence content. Lose the master
key, and the backups' evidence content is lost too, even though the chain and receipts
still verify. `.env` is not needed for a restore; a new install generates its own.
The gateway's volumes (its CA and its token, section 6) are not backed up either: the gateway
makes new ones on a fresh install, and its request log is in the database.

Caddy's volume (`caddy_data`) is not backed up. With Let's Encrypt (option A) that costs
nothing: Caddy gets a new certificate. With Caddy's internal CA (option C), a new server or
a lost volume means a **new root**, and every machine that trusted the old one shows the
certificate error again until it trusts the new root (section 5). To avoid that, keep a
copy of the CA, readable by root only, next to your other backups:

```sh
cd /opt/attackledger
install -m 700 -d /var/backups/attackledger/caddy-local-ca
docker compose cp caddy:/data/caddy/pki/authorities/local/. /var/backups/attackledger/caddy-local-ca/
chmod 600 /var/backups/attackledger/caddy-local-ca/*
```

The folder holds the root and intermediate certificates and their private keys. Whoever has
the root key can make certificates that the machines trusting it accept for any site, so
guard it like the master key. It does not change once made, so one copy is enough.

To put it back on a new server, after the restore below (Caddy is running):

```sh
cd /opt/attackledger
docker compose cp /var/backups/attackledger/caddy-local-ca/. caddy:/data/caddy/pki/authorities/local/
docker compose exec caddy rm -rf /data/caddy/certificates/local
docker compose restart caddy
```

The second command removes the server certificate Caddy issued from its new CA, so that it
issues one from the restored CA. Check with
`curl -fsS --cacert caddy-root.crt https://attackledger.example.com/api/health`, using the
`caddy-root.crt` you gave users.

Why the two parts together: the database's encrypted summaries open only with the data keys
in the blob store, and the API refuses to start when an engagement's key file is missing.

### Make a backup

`tools/backup.sh` dumps the database (a consistent snapshot, while everything keeps
running), then archives the blob store, and writes a manifest with the SHA-256 of each
part. The folder appears under its final name only when it is complete.

1. Create a folder for backups, readable by root only:

   ```sh
   install -m 700 -d /var/backups/attackledger
   ```

2. Run a backup:

   ```sh
   /opt/attackledger/tools/backup.sh /var/backups/attackledger
   ```

   It ends with `backup: done: /var/backups/attackledger/attackledger-<UTC time>` and what
   it saved, for example `engagements 1, evidence entries 10, receipts 1, people 3, blob
   files 10, migration <n>`. The migration is the database's own at that moment; it grows
   with each release that changes the database. To see it for your install, and the
   newest one your release knows:

   ```sh
   docker compose exec -T api python -c "from app import migrate; print(migrate.current(), migrate.head())"
   ```

   A backup's own value is in its `info.txt`, on the line `migration:`.

3. Run it every night at 02:15, and delete backups older than 30 days (set the number of
   days from your retention policy, section 7):

   ```sh
   cat > /etc/cron.d/attackledger-backup <<'EOF'
   15 2 * * * root /opt/attackledger/tools/backup.sh /var/backups/attackledger >> /var/log/attackledger-backup.log 2>&1
   45 3 * * * root find /var/backups/attackledger -maxdepth 1 -name 'attackledger-*' -mtime +30 -exec rm -rf {} +
   EOF
   ```

4. **Copy the backups off the server** (your backup system, `rsync` to a backup host, or
   object storage). A backup on the same disk does not survive the disk.

Each backup folder holds `postgres.dump`, `blobs.tar.gz`, `info.txt` (time, migration,
counts) and `MANIFEST.sha256`.

### Restore

`tools/restore.sh` first checks the manifest (and stops if any part is missing or
changed), checks that this version of AttackLedger knows the backup's database migration,
and refuses to overwrite an install that holds any data unless you add `--force`. Then it
stops the API and the worker, replaces the database and the blob store, and starts
everything again.

**On a new server** (after losing the old one):

1. Install as in sections 2 to 8, with the same release as the backup or a newer one.
   Do not create an owner: the people come back with the backup.
2. Put the original master key in place (section 7, step 1, with the saved key instead of
   a new one). The restore checks it against the key id the backup names, before it
   changes anything.
3. Copy the backup folder to the server, for example to `/var/backups/attackledger/`, and
   restore it:

   ```sh
   /opt/attackledger/tools/restore.sh /var/backups/attackledger/attackledger-20261009T021500Z
   ```

   It ends with `restore: done`. Old sessions from the backup still work until they
   expire (12 hours); people who were signed in stay signed in.

4. Sign in as before. Check that the engagements are there, and that a report still
   verifies: on the engagement's **Report** tab, **Download JSON**, then run
   `python3 tools/verify_report.py <the downloaded file>` on any machine with Python 3.

**On the same server** (to go back to an earlier state), the install is not empty, so
the script refuses. Take a backup of the current state first, then force it:

```sh
/opt/attackledger/tools/backup.sh /var/backups/attackledger
/opt/attackledger/tools/restore.sh --force /var/backups/attackledger/attackledger-20261009T021500Z
```

**Test a restore** on a spare machine at least once a quarter. A backup you have never
restored is a hope, not a backup.

## 15. Upgrade and rollback

The API applies database migrations itself when it starts (Alembic, forward to the newest
the code knows). The worker, which has no database access, waits until the API answers
before it takes jobs. Migrations can change the data, so always back up first.

1. Read the release notes (`CHANGELOG.md`) of every version between yours and the new one.
2. Back up:

   ```sh
   cd /opt/attackledger
   tools/backup.sh /var/backups/attackledger
   ```

3. Get the new release and compare the settings with yours. Add any new setting the
   example has to your `.env`:

   ```sh
   git fetch --tags
   git checkout v0.7.1
   keys() { grep -oE '^[# ]*[A-Z][A-Z0-9_]*=' "$1" | tr -d '# =' | sort -u; }
   diff <(keys deploy/.env.example) <(keys .env)
   ```

   It compares setting names only, never values, and counts a commented-out line such as
   `# ATTACKLEDGER_LAB_PROXY_PORT=3128` as a setting too: the example lists its optional
   settings that way. Lines starting with `<` are settings your `.env` does not mention yet.
   Read each one in `deploy/.env.example`: copy a line without `#` to `.env` and set it as
   its comment says; copy a commented line as it is, so the next comparison finds it, and
   remove the `#` only if you want to change its default. No output means nothing is new.

4. Build and restart. The API migrates the database while it starts. Coming from 0.6 or
   earlier, first create the master key and run the one-time steps in section 7
   ("Upgrading an install from before encryption"):

   ```sh
   docker compose build
   docker compose up -d --wait
   ```

5. Check that the database is at the new release's migration (the two values are the
   same) and that everything is healthy:

   ```sh
   docker compose exec -T api python -c "from app import migrate; print(migrate.current(), migrate.head())"
   docker compose ps
   ```

**Upgrading to migration 0022 (organizations, after 0.7.1).** Nothing to do beyond the steps
above. The migration makes the default organization and puts every existing row in it; the
key log and the audit log keep their entries and hashes, so reports issued before still
verify, and new entries continue the same chains. Engagement names and emails are now unique
per organization, which for one organization is what they were. The worker and gateway token
files keep working: they belong to the default organization. The migration fills a new
column on every table once: on Postgres, about 5 seconds per million rows of gateway log
and recon results (measured, see `docs/ORGANIZATIONS.md`).

**Rollback.** Migrations are not reversed in place (some would drop data). To go back,
return to the previous release and restore the backup from step 2:

```sh
cd /opt/attackledger
git checkout v0.7.0
docker compose build
tools/restore.sh --force /var/backups/attackledger/attackledger-<the backup from step 2>
```

Anything recorded between the upgrade and the rollback is lost, so roll back early or
export what you need first.

## 16. Monitoring and logs

**Health.** Each container has a healthcheck, and Docker restarts any that stops:

```sh
docker compose ps
curl -fsS https://attackledger.example.com/api/health
```

Alert when a container is not `healthy`, or when the health URL fails.

**Logs.** Every container logs to Docker, rotated at 10 MB, five files each (at most about
50 MB per container). Caddy writes one JSON line per request, with cookies and
authorization headers redacted.

```sh
docker compose logs --since 1h api worker
docker compose logs -f caddy
```

The API logs one line per request (method, path, status), never request bodies, so
passwords and keys do not reach the logs. Recon and agent output is in the ledger, not the
logs.

**Integrity.** The audit log and the key log are hash chains. Each command below ends
with `chain: intact`, or exits with status 1 and says where it is broken:

```sh
docker compose exec -T api python -m app.people audit-log | tail -n 1
docker compose exec -T api python -m app.people key-log | tail -n 1
```

**Disk.** Watch free space; the database and the blob store grow with use:

```sh
df -h /var/lib/docker
docker system df
```

**Backups.** Check `/var/log/attackledger-backup.log` for `backup: done`, and that a
backup newer than a day exists:

```sh
find /var/backups/attackledger -maxdepth 1 -name 'attackledger-*' -mtime -1
```

**Timestamps.** A receipt the TSA could not timestamp says so in its lane panel ("Not
timestamped") and in the report. Several in a row usually mean outbound HTTP to the TSA
is blocked (section 18).

## 17. Uninstall and delete the data

This deletes every engagement, evidence entry, receipt and person on this server. Make and
keep a final backup first if your contract or policy requires one.

1. Stop and remove the containers, the volumes (database, blob store, Caddy's
   certificates) and the images built here. `--profile lab` also removes the practice
   target if it was started (section 19):

   ```sh
   cd /opt/attackledger
   docker compose --profile lab down --volumes --rmi local
   docker builder prune --all --force
   ```

2. Remove the install folder (it holds `.env` and any TLS key you put in `deploy/certs/`)
   and the cron job:

   ```sh
   rm -rf /opt/attackledger
   rm -f /etc/cron.d/attackledger-backup
   ```

3. Delete the backups, on this server and wherever you copied them:

   ```sh
   rm -rf /var/backups/attackledger /var/log/attackledger-backup.log
   ```

4. Destroy the master key and every copy of it. Once the key is gone, the evidence content
   in any copy of the data you missed is unreadable. If you set
   `ATTACKLEDGER_MASTER_KEY_PATH`, use that file's folder instead:

   ```sh
   shred -u /etc/attackledger/master.key*
   rmdir /etc/attackledger
   ```

Deleting files does not reliably erase them from SSDs. If the data must be unrecoverable
from the disk itself, follow your organisation's disk sanitisation procedure (or destroy
the disk) after these steps.

## 18. Troubleshooting

**`docker compose` says `required variable POSTGRES_PASSWORD is missing a value`** (or
`ATTACKLEDGER_HOSTNAME`, `ATTACKLEDGER_TLS`). The setting is empty in `.env`; see
section 4. Run `docker compose config --quiet` until it prints nothing.

**`docker compose` rejects `!reset` or `!override`.** Compose is older than 2.24. Install
it from Docker's repository (section 2) and check `docker compose version`.

**`docker compose ps` lists no containers, or a dev setup with ports 8000 and 8080.** You
are not in `/opt/attackledger`, or `.env` lacks the `COMPOSE_FILE` and
`COMPOSE_PROJECT_NAME` lines. `cd /opt/attackledger` and compare `.env` with
`deploy/.env.example`.

**The browser cannot connect, or shows a certificate error.**
- `docker compose logs caddy | tail -n 50` says why.
- Let's Encrypt: the DNS name must resolve to this server from the internet, and port 80
  must be open to the internet.
- Own certificate: both files must exist in `deploy/certs/`, the chain must start with the
  server certificate, and the key must match it.
- Internal CA: the warning is expected until you trust `caddy-root.crt` (section 5).
- Something else uses port 80 or 443: `ss -ltnp | grep -E ':(80|443) '`.

**"Nobody can sign in yet"** on the sign-in page. There is no owner; see section 9.

**Signed in, but sent back to the sign-in page at once.** The session cookie is HTTPS-only.
Open the `https://` address with the configured name, not the IP address or `http://`
(with option D in section 5, `http://attackledger.localhost:8080` through the tunnel).

**"Too many failed sign-ins; try again in 15 minutes".** Five failures from one address
for one email lock it for 15 minutes. Wait, or clear all lockouts with
`docker compose restart api`. A forgotten password is reset on the server (section 10).

**Every owner is locked out** (forgotten passwords, or the only owner left). Reset an owner's
password on the server: `docker compose exec api python -m app.people set-password --email owner@example.com`.

**"Signing needs a secure page"** when a reviewer signs. The page is not on HTTPS; see
section 5.

**A reviewer's key is "not registered" or they see a new key notice.** They are on a new
browser or cleared site data: the next signature registers a new key (section 11). If they
did not do it, revoke it under **Your account** and tell an owner.

**Receipts say "Not timestamped".** The API could not reach the TSA. Test from the server:
`docker compose exec api python -c "import httpx; print(httpx.get('http://timestamp.digicert.com', timeout=10).status_code)"`.
Any status code means it is reachable; an error means outbound port 80 to the TSA is
blocked. Allow it (or set your own TSA, section 12), then use **Timestamp now** on each
receipt.

**The API stops at once with "no master key", "cannot be read" or "not a
256-bit key".** The key file is missing, not readable by uid 10001, or not a key. Check
section 7, step 1: `ls -l /etc/attackledger/master.key` (or the file in
`ATTACKLEDGER_MASTER_KEY_PATH`) should show owner `10001` and `-r--------`. A missing file
makes `docker compose up` itself fail with a "bind source path does not exist" error.

**The API stops at once with "the configured master key ... did not wrap the keys of
engagement ..." or "the blob store ... has no key for engagement ...".** The master key is
not the one the data was encrypted with (put the right one in place), or the blob store
volume does not belong to this database (only one of the two parts was restored). The
message names the engagement.

**The API stops with "this process (uid 10001) cannot write to ... in the blob
store".** The volume comes from a version before encryption, when the API wrote as root.
Run the one-time `chown` in section 7 ("Upgrading an install from before encryption").

**`restore.sh` says the backup's keys "are wrapped by master key ...".** Put the master key
that was in use when the backup was made in place, restore, and then rotate if you need to
(section 7).

**The API stays `unhealthy` or restarts after an upgrade.** Read
`docker compose logs api | tail -n 100`. A migration error names the migration. Roll back
(section 15) and send the log to whoever supports your install.

**The worker is `unhealthy`, or its log says "waiting for the API".** It cannot reach the API
through the gateway's relay. Check that `gateway` and `api` are healthy
(`docker compose ps`) and read `docker compose logs gateway | tail`. "the worker token is
required" in the worker's log means the API and the worker do not share the `worker-control`
volume or the same `ATTACKLEDGER_WORKER_TOKEN`.

**`restore.sh` says "this install is not empty".** It protects existing data. Back up the
current state, then add `--force` (section 14).

**`restore.sh` says a part "does not match the manifest".** The backup was damaged or
changed after it was made. Use another backup, or a copy of this one from your off-server
store.

**`restore.sh` says "this version does not know migration ...".** The backup comes from a
newer AttackLedger. Check out that version (section 15), build, and restore again.

**The disk is full.** `docker system df` shows what uses it. `docker builder prune` frees the
build cache after an upgrade. Old backups on the server are removed by the cron job in
section 14.

## 19. Practise against the lab

AttackLedger comes with a small practice target: a fictional shop that answers as
`shop.lab.test`. It is useful for a first engagement before a real one: recon runs against
it, testers browse it and import what they captured, and reviewers sign its lanes. The
production file does not start it (`profiles: ["lab"]` in `deploy/compose.prod.yml`); you
start it when you want it.

The lab is on its own internal network (`lab`), with no route out. Two containers can reach
it: the **gateway**, which is how the worker's recon tools and agents reach it, with the
engagement's scope, rate and read-only rules, and the **lab proxy**, an HTTP proxy for a
person's browser, published on the server's loopback address only (port 3128). The lab proxy
forwards to `shop.lab.test` and refuses every other host, so it is no way out of the server.
Unlike the gateway, it lets a browser send forms (POST) to the lab, because a person is
driving it.

### Start and stop it

1. Start the lab and its proxy:

   ```sh
   cd /opt/attackledger
   docker compose --profile lab up -d lab lab-proxy
   ```

2. Check that both are running:

   ```sh
   docker compose --profile lab ps lab lab-proxy
   ```

3. When you no longer need them, stop and remove them. The rest keeps running:

   ```sh
   docker compose --profile lab rm --stop --force lab lab-proxy
   ```

Plain `docker compose` commands leave the lab alone, because they do not name the
profile. In particular, `docker compose down` without `--profile lab` leaves it running and
cannot remove the networks it uses; add `--profile lab`. To use another port for the lab
proxy, set `ATTACKLEDGER_LAB_PROXY_PORT` in `.env` before step 1.

### A practice engagement

An owner sets it up once:

1. **New engagement** (left), name it `Lab practice`, leave **Type** on **Pentest** and
   **Methodology** on **Web application pentest (OWASP WSTG)**, **Create**.
2. On the **Recon** tab, under **Rules of engagement**:
   - **In scope**: `shop.lab.test`
   - **Research header**: `X-Pentest: lab-practice`
   - **Requests per second**: `5`
   - Under **Authorization**: **Statement of work or rules of engagement URL**
     `https://example.com/policy` (it must start with `https://`; for the lab any page will
     do), **Your name or handle**, and tick **I am authorized by the client to test these
     hosts under the statement of work and will follow its rules of engagement.**
   - **Save rules**. `shop.lab.test` becomes a row in the ledger.
3. On the **Team** tab, give the people who practise their roles (section 10).

(A bug bounty engagement shows **Program policy URL** and **I am authorized to test this
program and will follow its policy.** instead.)

Recon: on the **Recon** tab, **Find live web servers**, **Run**, or **Run all steps**. Their
requests go through the gateway and are listed per engagement at
`GET /api/engagements/<id>/gateway-log`.

**Run all steps** does not queue every step. It says, for example, "Queued 6 steps; 7 steps
cannot apply and were not queued", and lists each step left out with its reason:
- **Find subdomains**, **Collect archived URLs** and **Dork checklist**: "needs a wildcard in
  scope, such as *.example.com". These steps work on the domain under a wildcard rule; the
  lab's scope is one exact host, so they never run. Their own **Run** buttons say "Needs a
  wildcard rule such as *.example.com".
- **Scan ports**, **Discover content**, **Discover hidden parameters** and **Scan for known
  issues**: off, until an owner ticks them under **Modules the rules of engagement allow**.

The six steps that do run (resolve, find live web servers, well-known files, crawl,
JavaScript analysis and parameter routing) finished in under a minute on a test install,
and the gateway log listed 27 entries for them (requests and DNS questions).

### Capture a HAR of the lab from a browser

The lab is not reachable from people's machines directly. Each person opens an SSH tunnel to
the lab proxy and points a separate browser profile at it, so their normal browsing is not
affected.

1. On your own machine, open the tunnel and leave it open (it needs SSH access to the
   server; with option D in section 5, add `-L 8080:127.0.0.1:80` to the same command):

   ```sh
   ssh -N -L 3128:127.0.0.1:3128 admin@attackledger.example.com
   ```

2. Start a browser with its own profile that uses the tunnel as its proxy:

   - Chrome on macOS:

     ```sh
     open -na "Google Chrome" --args --user-data-dir="$HOME/.attackledger-lab-chrome" --proxy-server=http://127.0.0.1:3128
     ```

   - Chrome on Windows (Command Prompt):

     ```bat
     "C:\Program Files\Google\Chrome\Application\chrome.exe" --user-data-dir="%TEMP%\attackledger-lab-chrome" --proxy-server=http://127.0.0.1:3128
     ```

   - Chrome on Linux:

     ```sh
     google-chrome --user-data-dir="$HOME/.attackledger-lab-chrome" --proxy-server=http://127.0.0.1:3128
     ```

   - Firefox: create a profile on `about:profiles`, start it, then **Settings**, **Network
     Settings**, **Manual proxy configuration**, **HTTP Proxy** `127.0.0.1`, **Port** `3128`.

3. Open the developer tools (F12), select the **Network** tab and tick **Preserve log**
   (Firefox: **Persist Logs**, in the gear menu).

4. Go to `http://shop.lab.test/` (type `http://`; the lab has no HTTPS) and click through
   the shop: products, about, search, admin.

5. Save the capture as a HAR file. Chrome: the **Export HAR** button (a downward arrow) in
   the Network tab's toolbar, or right-click any request, **Save all as HAR**. Firefox:
   right-click any request, **Save All As HAR**.

6. In AttackLedger, open the practice engagement, **Import** tab, choose the file,
   **Import**. The result line says how many entries reached the inbox, how many were
   duplicates, and how many were refused: any request the browser made to another host is
   refused as out of scope and listed by row and host only.

7. Map the entries to checklist items, as in `docs/TESTER_GUIDE.md`.

**What counts as a duplicate.** Only an exact copy: the same method, URL and status, and the
same request and response bytes, after redaction. Loading the same page twice is a
duplicate only if the shop answered with exactly the same bytes both times. Any difference
makes a new entry, and the `Date` header alone is enough: it changes every second. A test
file with one request three times, the second answer identical to the first and the third
one second later (only its `Date` differed), gave two entries and one duplicate.

Measured on a test install: headless Chrome 155 through the lab proxy, driven by a script
that clicked through the shop, captured 25 requests. The import added 9 entries to the
inbox, counted 16 duplicates, and refused as out of scope a row added for another host.

To practise the Burp or Caido import instead, point the tool's upstream proxy at the
tunnel for `shop.lab.test` only, browse the lab through the tool, and export as in the
tester guide:
- Burp: **Settings**, **Network**, **Connections**, **Upstream proxy servers**, **Add**:
  **Destination host** `shop.lab.test`, **Proxy host** `127.0.0.1`, **Proxy port** `3128`.
- Caido: **Settings** (account menu, top right), **Network**, **HTTP Proxies**,
  **+ Add Proxy**: address `127.0.0.1`, port `3128`, **Included Hosts** `shop.lab.test`,
  **+ Create**.

When you finish, close the browser and delete its profile folder
(`$HOME/.attackledger-lab-chrome`, or the Firefox profile on `about:profiles`).

## 20. Trying it on a Mac

For a trial with fictional data, before a server exists, the same production setup runs on
a Mac with [Colima](https://github.com/abiosoft/colima) (a Linux VM for Docker). It was
tested with Colima on Apple silicon (4 CPUs, 6 GB of memory for the VM) and Docker Compose
2.24 or later. Real work belongs on a server: sections 1 to 19 stay the main path. Follow
them with these differences:

- **No `sudo`, and everything under your home folder.** Colima shares only your home
  folder with the VM, so the install folder and the master key must be in it. Clone into
  `~/attackledger` instead of `/opt/attackledger`, and run every command there as yourself.
- **`sed -i ''` instead of `sed -i`** in sections 4 and 5: macOS `sed` needs the empty
  argument, and without it says `invalid command code`.
- **The master key under `~`, and no `chown`** (section 7, step 1):

  ```sh
  install -m 700 -d ~/.attackledger
  (umask 077; openssl rand -base64 32 > ~/.attackledger/master.key)
  chmod 400 ~/.attackledger/master.key
  sed -i '' "s|^ATTACKLEDGER_MASTER_KEY_PATH=.*|ATTACKLEDGER_MASTER_KEY_PATH=$HOME/.attackledger/master.key|" .env
  ```

  Colima shows the file to the API container as owned by the API's own user, so it reads
  it without a `chown`. Leave `chown` out of the rotation steps too.
- **Option D without a tunnel** (section 5). Publish Caddy on the Mac's loopback address,
  on ports that are free, and open the page directly:

  ```sh
  sed -i '' "s|^ATTACKLEDGER_HOSTNAME=.*|ATTACKLEDGER_HOSTNAME=http://attackledger.localhost|" .env
  sed -i '' "s|^ATTACKLEDGER_TLS=.*|ATTACKLEDGER_TLS=internal|" .env
  sed -i '' "s|^ATTACKLEDGER_HTTP_PORT=.*|ATTACKLEDGER_HTTP_PORT=127.0.0.1:8080|" .env
  sed -i '' "s|^ATTACKLEDGER_HTTPS_PORT=.*|ATTACKLEDGER_HTTPS_PORT=127.0.0.1:8443|" .env
  ```

  After section 8, check with `curl -fsS http://attackledger.localhost:8080/api/health`
  and open `http://attackledger.localhost:8080` in Chrome.
- **The lab proxy needs no tunnel either** (section 19): it listens on the Mac's
  `127.0.0.1:3128`, so start the browser with `--proxy-server=http://127.0.0.1:3128` as
  shown there and skip the `ssh` step.
- **Backups and cleanup.** `tools/backup.sh` works with a folder under `~`, such as
  `~/attackledger-backups`. macOS has no `shred`; delete key files with `rm`. Skip the cron
  job.

To end the trial: `docker compose --profile lab down --volumes --rmi local` in the install
folder, then delete the folder, the backups and `~/.attackledger`.
