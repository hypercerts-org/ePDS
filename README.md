# ePDS

An [AT Protocol](https://atproto.com/) Personal Data Server (PDS) with a pluggable authentication layer powered by [Better Auth](https://www.better-auth.com/). Supports email OTP, social login (Google, GitHub), and any other mechanism Better Auth provides — configured per deployment.

## Architecture

```
                  +-----------------+
                  |   OAuth Client  |
                  | (Bluesky, custom|
                  |   apps, etc.)   |
                  +-------+---------+
                          |
                   1. PAR  |  8. Token exchange
                          v
           +-----------------------------+
           |          PDS Core           |
           |  (stock @atproto/pds +      |
           |   magic-callback endpoint)  |
           +-----------------------------+
                   |             ^
   2. AS metadata  |             | 7. Auth code issued
   redirects to    |             |    via /oauth/magic-callback
   auth subdomain  v             |
           +-----------------------------+
           |        Auth Service         |
           |  /oauth/authorize           |
           |  /auth/complete             |
           |  /account/* (settings)      |
           |  (better-auth OTP backend)  |
           +-----------------------------+
                          |
              3-6. Email  |  OTP code flow
                          v
                     User's inbox
```

### OAuth Flow

1. **Client sends PAR** to PDS (stock AT Protocol behaviour)
2. **PDS AS metadata** points `authorization_endpoint` to the auth subdomain
3. **Auth service** renders login page (email input, or OTP step directly if `login_hint` provided)
4. **OTP email sent** to user (8-digit code, via better-auth)
5. **User enters code** — verified by better-auth
6. **better-auth** redirects to `/auth/complete`
7. **Auth service** creates PDS account (if new) and issues authorization code via magic-callback
8. **Client exchanges code** for tokens (standard OAuth)

There are two supported login flows for client apps:

- **Flow 1** — App has its own email form: collect email, pass as `login_hint` to PAR, auth server pre-fills the email and auto-sends the OTP (known issue: brief flash of email form while OTP is sending)
- **Flow 2** — App has a simple "Login" button: no email collected, auth server shows the email input form itself

Users get a random handle (e.g., `a3x9kf.epds-poc1.test.certified.app`) — no email-derived handles for privacy.

## Packages

| Package | Description |
|---------|-------------|
| `@magic-pds/shared` | Database (SQLite), crypto utilities, types, logger |
| `@magic-pds/auth-service` | Auth UI, OTP code flow via better-auth, account settings |
| `@magic-pds/pds-core` | Wraps `@atproto/pds` with magic link integration |

## Quick Start

### Prerequisites

- Node.js >= 18.7.0
- pnpm 9+
- OpenSSL (for key generation)

### Setup

```bash
# Clone and install
git clone <repo-url> epds
cd epds
pnpm install

# Generate a PLC rotation key
openssl ecparam -name secp256k1 -genkey -noout | \
  openssl ec -text -noout 2>/dev/null | \
  grep priv -A 3 | tail -n +2 | tr -d '[:space:]:'

# Add the key to .env
# PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX=<paste hex here>

# Configure your domain, email provider, etc. in .env
```

### Local Development

```bash
./scripts/dev.sh
```

This starts both services with `NODE_ENV=development` (disables secure cookies).

- PDS: http://localhost:3000
- Auth: http://localhost:3001

### Production Deployment (Docker)

```bash
# Build and start
docker compose up -d

# Caddy handles TLS automatically
# Ensure DNS points:
#   pds.example      -> your server
#   auth.pds.example -> your server
#   *.pds.example    -> your server (for handle resolution)
```

## Configuration

See [`.env.example`](.env.example) for all configuration options. Key settings:

| Variable | Description |
|----------|-------------|
| `PDS_HOSTNAME` | Your PDS domain (e.g., `epds-poc1.test.certified.app`) |
| `AUTH_HOSTNAME` | Auth subdomain (e.g., `auth.epds-poc1.test.certified.app`) |
| `SMTP_HOST` | SMTP server hostname (e.g., `smtp.resend.com`) |
| `SMTP_PORT` | SMTP port (e.g., `465`) |
| `SMTP_USER` | SMTP username |
| `SMTP_PASS` | SMTP password / API key |
| `SMTP_FROM` | From address (must be on a verified domain) |
| `MAGIC_INVITE_CODE` | Pre-generated invite code for account creation (required if `PDS_INVITE_REQUIRED=true`) |
| `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX` | secp256k1 private key |

### Generating an Invite Code

If `PDS_INVITE_REQUIRED` is true (the default), generate a high-useCount invite code via the PDS admin API and set it as `MAGIC_INVITE_CODE`:

```bash
curl -X POST https://<pds-hostname>/xrpc/com.atproto.server.createInviteCode \
  -H "Content-Type: application/json" \
  -H "Authorization: Basic $(echo -n 'admin:<PDS_ADMIN_PASSWORD>' | base64)" \
  -d '{"useCount": 1000}'
```

## Security

- OTP codes: 8-digit, managed by better-auth, single-use, short expiry
- CSRF protection on all forms
- Accounts created with a random unguessable password (login only possible via OTP flow)
- HttpOnly, SameSite cookies
- Security headers: HSTS, X-Frame-Options, X-Content-Type-Options

## License

MIT
