# Deployment

## Production Deployment (Docker)

### Prerequisites

- Docker and Docker Compose
- A domain with DNS control
- An SMTP provider (e.g. [Resend](https://resend.com/), SendGrid, AWS SES, Postmark)

### DNS Setup

Point the following records at your server:

| Record                 | Target                                 |
| ---------------------- | -------------------------------------- |
| `pds.example.com`      | your server IP                         |
| `auth.pds.example.com` | your server IP                         |
| `*.pds.example.com`    | your server IP (for handle resolution) |

### Configuration

Run the setup script to generate `.env` and `packages/demo/.env` with all
secrets auto-generated:

```bash
./scripts/setup.sh
```

See [configuration.md](configuration.md) for how env vars work across
deployment contexts and a full variable reference.

### Build and Start

```bash
# Build images
docker compose build

# Start services
docker compose up -d

# View logs
docker compose logs -f
```

Caddy handles TLS automatically via ACME/Let's Encrypt. The Docker Compose
service caps Caddy at 512 MiB of memory and sets `GOMEMLIMIT=384MiB` so TLS
storage maintenance or traffic spikes cannot exhaust the full VM.

### Caddy and TLS-check incident diagnostics

pds-core emits aggregate `/tls-check` observability logs every 10 seconds while there is activity on Caddy's on-demand TLS permission endpoint. Look for `tls-check summary` to see started/completed/aborted/in-flight request counts, status-code buckets, hostname-shape buckets (`apex`, `auth`, `oneLabel`, `nested`, `unsupported`, `missing`), request-duration percentiles, account-lookup duration percentiles, event-loop lag, process memory, and suppressed individual-log counts. Individual `tls-check slow`, `tls-check aborted`, and `tls-check failed` logs are emitted when a permission check exceeds 1000 ms, the client disconnects before completion, or the handler throws; each category is capped at 50 individual warning logs per summary window to avoid turning an attack spike into a log flood.

When investigating Caddy memory growth, run the read-only snapshot watcher from the Docker Compose host:

```bash
THRESHOLD_MIB=384 ./scripts/caddy-oom-snapshot.sh
```

The watcher polls the Caddy container memory cgroup and writes snapshots under `/tmp/epds-caddy-snapshots` by default when memory crosses the threshold. Set `SNAPSHOT_DIR=/var/log/epds/caddy-snapshots` if you want persistent host logs. Each snapshot captures Caddy `/debug/vars`, `/metrics`, heap and goroutine profiles, `docker stats`, selected container state without environment variables, connection state, recent Caddy/core compose logs, and recent kernel logs. It does not restart, reload, or reconfigure any containers. Treat snapshots as sensitive operational artifacts because recent logs can contain request metadata.

For a one-off local smoke test of the watcher without waiting in a loop:

```bash
./scripts/caddy-oom-snapshot.sh --once
```

### Updating

```bash
docker compose build
docker compose up -d
```

Note: `docker compose restart` does **not** pick up `.env` changes.
Always use `docker compose up -d` to recreate containers after changing environment variables.

If you want the built image version to include a commit suffix outside Railway, pass `EPDS_GIT_SHA` at build time:

```bash
EPDS_GIT_SHA=$(git rev-parse HEAD) docker compose build
```

If you have Node and pnpm installed on the host, `pnpm docker:build` remains available as a convenience wrapper that pre-stamps `.epds-version` before calling `docker compose build`.

## Railway Deployment

Railway is the primary cloud deployment target. Each package has a
`railway.toml` that configures its build.

### Prerequisites

- A [Railway](https://railway.app/) account (Pro plan recommended for volume size)
- The [Railway CLI](https://docs.railway.com/guides/cli) installed and logged in
- DNS control for your domain

### Project Setup

1. Create a new Railway project and link it to your GitHub repo:

   ```bash
   railway init
   railway link
   ```

2. Create three services in the Railway dashboard (or via CLI), one per package:
   - `@certified-app/pds-core`
   - `@certified-app/auth-service`
   - `@certified-app/demo`

3. Link each package directory to its service:

   ```bash
   cd packages/pds-core && railway link
   cd packages/auth-service && railway link
   cd packages/demo && railway link
   ```

### Volumes

Both pds-core and auth-service need persistent volumes for their SQLite
databases. Create them from each package directory:

```bash
cd packages/pds-core
railway volume add --mount-path /data

cd packages/auth-service
railway volume add --mount-path /data
```

The demo app is stateless and does not need a volume.

**Important**: The mount path must match the env vars:

- pds-core: `PDS_DATA_DIRECTORY=/data` (also stores blobs at `/data/blobs`)
- auth-service: `DB_LOCATION=/data/epds.sqlite`

### Environment Variables

Run the setup script to generate `.env` files, then paste the values into
each service's raw environment editor in the Railway dashboard:

```bash
./scripts/setup.sh

# Strip comments and blank lines for pasting into Railway:
grep -v '^\s*#' packages/pds-core/.env | grep -v '^\s*$'
grep -v '^\s*#' packages/auth-service/.env | grep -v '^\s*$'
grep -v '^\s*#' packages/demo/.env | grep -v '^\s*$'
```

**Important**: The setup script sets `PDS_INTERNAL_URL=http://core:3000` (the
Docker Compose service name). For Railway, you **must** update this in the
auth-service to the pds-core service's Railway internal URL. Find it via:

```bash
railway link -s '@certified-app/pds-core'
railway variables --json | python3 -c "import sys,json; print(json.load(sys.stdin)['RAILWAY_PRIVATE_DOMAIN'])"
```

Then update it on the auth-service:

```bash
railway link -s '@certified-app/auth-service'
railway variables set PDS_INTERNAL_URL=http://<private-domain>:3000
```

Without a correct `PDS_INTERNAL_URL`, the auth service will **crash at startup**
if the value is missing, or log warnings and fail on auth→PDS calls at runtime
if it points to the wrong host.

### DNS Setup

Point the following records at Railway's DNS target (shown in the dashboard
under each service's custom domain settings):

| Record                 | Service      |
| ---------------------- | ------------ |
| `pds.example.com`      | pds-core     |
| `auth.pds.example.com` | auth-service |
| `*.pds.example.com`    | pds-core     |
| `demo.example.com`     | demo         |

Railway handles TLS automatically.

### Deploying

Railway deploys automatically on push to the linked branch. Each service's
`railway.toml` defines `watchPatterns` so only relevant changes trigger a
rebuild.

To manually redeploy:

```bash
cd packages/pds-core && railway redeploy --yes
cd packages/auth-service && railway redeploy --yes
cd packages/demo && railway redeploy --yes
```

### Viewing Logs

```bash
cd packages/pds-core && railway logs --deployment
cd packages/auth-service && railway logs --deployment
cd packages/demo && railway logs --deployment
```

### Railway-Specific Notes

- Each service reads only its own per-package `.env` — the top-level `.env`
  is not used on Railway.
- The demo app runs Next.js with `output: "standalone"` in production. If you
  see a warning about this, ensure the start command uses
  `node .next/standalone/server.js` instead of `next start`.
- Volumes cannot be configured via `railway.toml` — they must be created
  through the dashboard or CLI.
- Services with volumes have brief downtime during redeployment (Railway
  cannot mount the same volume to two containers simultaneously).

## Service Ports

| Service      | Internal port | Public          |
| ------------ | ------------- | --------------- |
| PDS Core     | 3000          | via Caddy (443) |
| Auth Service | 3001          | via Caddy (443) |
| Caddy        | 80, 443       | yes             |

## Generating Secrets

```bash
# PLC rotation key (secp256k1)
openssl ecparam -name secp256k1 -genkey -noout | \
  openssl ec -text -noout 2>/dev/null | \
  grep priv -A 3 | tail -n +2 | tr -d '[:space:]:'

# Generic secrets (JWT, DPOP, HMAC keys, etc.)
openssl rand -hex 32
```

## Invite Codes

The AT Protocol PDS requires invite codes for account creation by default
(`PDS_INVITE_REQUIRED=true`). You have two options:

### Option 1: Create an invite code (recommended for production)

Once the PDS is running, generate a high-`useCount` invite code via the admin
API and set it as `EPDS_INVITE_CODE` on the pds-core service:

```bash
curl -X POST https://$PDS_HOSTNAME/xrpc/com.atproto.server.createInviteCode \
  -H "Content-Type: application/json" \
  -u "admin:$PDS_ADMIN_PASSWORD" \
  -d '{"useCount": 9999999}'
```

The response contains the invite code:

```json
{ "code": "your-pds-hostname-xxxxx-xxxxx" }
```

Set it as `EPDS_INVITE_CODE` on pds-core (Railway example):

```bash
railway variable set EPDS_INVITE_CODE=<code> -s '@certified-app/pds-core'
```

### Option 2: Disable invite codes (simpler, less secure)

For test or development environments, you can disable the invite code
requirement entirely by setting `PDS_INVITE_REQUIRED=false` on the pds-core
service. This allows anyone who can reach the PDS to create accounts, so it
is **not recommended for production**.
