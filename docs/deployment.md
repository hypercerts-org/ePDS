# Deployment

## Production Deployment (Docker)

### Prerequisites

- Docker and Docker Compose
- A domain with DNS control
- An SMTP provider (e.g. [Resend](https://resend.com/), SendGrid, AWS SES, Postmark)

### DNS Setup

Point the following records at your server:

| Record | Target |
|--------|--------|
| `pds.example.com` | your server IP |
| `auth.pds.example.com` | your server IP |
| `*.pds.example.com` | your server IP (for handle resolution) |

### Configuration

Copy `.env.example` to `.env` and fill in your values.
See [configuration.md](configuration.md) for a full reference.

### Build and Start

```bash
# Build images (use --no-cache for pds-core if changes aren't picked up)
docker compose build
docker compose build --no-cache pds   # if cache busting is needed

# Start services
docker compose up -d

# View logs
docker compose logs -f
```

Caddy handles TLS automatically via ACME/Let's Encrypt.

### Updating

```bash
docker compose build
docker compose up -d
```

Note: `docker compose restart` does **not** pick up `.env` changes.
Always use `docker compose up -d` to recreate containers after changing environment variables.

## Service Ports

| Service | Internal port | Public |
|---------|--------------|--------|
| PDS Core | 3000 | via Caddy (443) |
| Auth Service | 3001 | via Caddy (443) |
| Caddy | 80, 443 | yes |

## Generating Secrets

```bash
# PLC rotation key (secp256k1)
openssl ecparam -name secp256k1 -genkey -noout | \
  openssl ec -text -noout 2>/dev/null | \
  grep priv -A 3 | tail -n +2 | tr -d '[:space:]:'

# Generic secrets (JWT, DPOP, HMAC keys, etc.)
openssl rand -hex 32
```

## Generating an Invite Code

If `PDS_INVITE_REQUIRED` is true (the default), generate a high-`useCount` invite code
and set it as `MAGIC_INVITE_CODE`:

```bash
curl -X POST https://<pds-hostname>/xrpc/com.atproto.server.createInviteCode \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n 'admin:<PDS_ADMIN_PASSWORD>' | base64)" \
  -d '{"useCount": 1000}'
```
